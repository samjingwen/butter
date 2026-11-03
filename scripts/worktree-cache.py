#!/usr/bin/env python3
"""Conservatively seed a new worktree with Cargo's disposable native caches."""

import argparse
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tomllib


CACHE_DIRS = ("target/debug/deps", "target/debug/.fingerprint", "target/debug/build")
LOCKS = (".cargo-lock", ".cargo-build-lock", ".cargo-artifact-lock")


class SkipCopy(Exception):
    """An optional optimization is unavailable; ordinary Cargo still works."""


def run(root, *args):
    return subprocess.check_output(args, cwd=root, text=True, stderr=subprocess.PIPE).strip()


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise SkipCopy("cache/configuration path is missing or not a regular file (symlinks excluded)")
    return path


def inputs(root):
    # Only tracked, public build inputs; never inspect environment/auth files.
    paths = run(root, "git", "ls-files", "-z", "Cargo.lock", "*Cargo.toml",
                "rust-toolchain.toml", ".cargo/config", ".cargo/config.toml",
                ".worktreeinclude", ".config/wt.toml", ".gitignore").split("\0")
    result = {p: regular(root / p).read_bytes() for p in paths if p}
    for required in ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml", ".worktreeinclude"):
        if required not in result:
            raise SkipCopy("required tracked build inputs are missing")
    return result


def tool(root, name):
    # Unlike invoking a rustup shim, `which` never installs a missing toolchain.
    return run(root, "rustup", "which", name)


def compatible(source, destination):
    if source == destination:
        raise SkipCopy("source and destination are the same worktree")
    common = lambda p: (p / run(p, "git", "rev-parse", "--git-common-dir")).resolve()
    if common(source) != common(destination):
        raise SkipCopy("source is not in this Git worktree family")
    if inputs(source) != inputs(destination):
        raise SkipCopy("lockfile, toolchain, manifests or copy/build configuration differ")
    for root in (source, destination):
        for name in (".cargo/config", ".cargo/config.toml"):
            path = root / name
            if path.exists():
                config = tomllib.loads(regular(path).read_text())
                if config.get("build", {}).get("target"):
                    raise SkipCopy("configured cross-target builds use the cold path")
    overrides = ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "CARGO_BUILD_BUILD_DIR",
                 "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
                 "CARGO_ENCODED_RUSTFLAGS")
    if any(os.environ.get(name) for name in overrides):
        raise SkipCopy("custom target/compiler settings use the cold path")
    compiler = run(source, tool(source, "rustc"), "-vV")
    if compiler != run(destination, tool(destination, "rustc"), "-vV"):
        raise SkipCopy("resolved compilers/host ABIs differ")
    cfg = run(source, tool(source, "rustc"), "--print", "cfg")
    info = json.loads(regular(source / "target/.rustc_info.json").read_text())
    outputs = [o.get("stdout", "").strip() for o in info["outputs"].values()
               if o.get("success")]
    def target_cfg(output):
        return {line for line in output.splitlines()
                if line.startswith("target_") or line in ("unix", "windows")}

    if compiler not in outputs or not any(target_cfg(o) == target_cfg(cfg) for o in outputs):
        raise SkipCopy("cached compiler/platform/target does not match the native toolchain")
    for root in (source, destination):
        metadata = json.loads(run(root, tool(root, "cargo"), "metadata", "--no-deps",
                                  "--locked", "--offline", "--format-version=1"))
        if any(Path(metadata[key]) != root / "target"
               for key in ("target_directory", "build_directory")):
            raise SkipCopy("non-default Cargo target/build directory uses the cold path")


def safe_cache(root, recursive=True):
    # Worktrunk can preserve symlinks and special files. Never import them.
    for relative in ("target", "target/debug", *CACHE_DIRS):
        if (root / relative).is_symlink():
            raise SkipCopy("cache contains a symlink")
    if not recursive:
        return
    for relative in CACHE_DIRS:
        for directory, dirs, files in os.walk(root / relative, followlinks=False):
            if any((Path(directory) / name).is_symlink() for name in dirs + files):
                raise SkipCopy("cache contains a symlink")
            for name in files:
                regular(Path(directory) / name)


def copy(source, destination, dry_run=False):
    if (destination / "target").exists() or (destination / "target").is_symlink():
        raise SkipCopy("destination already has a target directory; leave it untouched")
    safe_cache(source, recursive=False)
    # Cargo uses flock on Linux/macOS. Hold its existing source lock throughout
    # discovery/copy so an active build cannot change the snapshot underneath us.
    with ExitStack() as stack:
        regular(source / "target/debug/.cargo-lock")
        for name in LOCKS:
            path = source / "target/debug" / name
            if path.exists():
                lock = stack.enter_context(regular(path).open("rb"))
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise SkipCopy("source cache is in use by Cargo") from error
        safe_cache(source)
        compatible(source, destination)
        command = ["wt", "step", "copy-ignored", "--require-include", "--from", str(source)]
        plan = json.loads(run(destination, *command, "--dry-run", "--format=json"))
        if any(entry["kind"] != "file" for entry in plan["entries"]):
            raise SkipCopy("copy plan contains a recursive directory rather than individual files")
        for entry in plan["entries"]:
            regular(source / entry["path"])
        if dry_run:
            print(json.dumps(plan, indent=2))
            return
        (destination / "target").mkdir()
        (destination / "target/debug").mkdir()
        for name in LOCKS:
            lock = stack.enter_context((destination / "target/debug" / name).open("xb"))
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        subprocess.run(command, cwd=destination, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        copy(args.source.resolve(), Path.cwd().resolve(), args.dry_run)
    except (SkipCopy, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        # Missing caches/tools or changed settings must not break a cold checkout.
        # Do not print subprocess stderr: external Cargo config may be private.
        reason = str(error) if isinstance(error, SkipCopy) else type(error).__name__
        print(f"Rust cache copy skipped ({reason}); use ordinary locked Cargo builds.")


if __name__ == "__main__":
    main()
