#!/usr/bin/env python3
"""Exercise real Worktrunk copying with disposable public, synthetic fixtures."""

import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


PROJECT = Path(__file__).resolve().parent.parent


class CacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="butter-cache-", dir=os.environ.get("TMPDIR"))
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.source = cls.root / "source with spaces"
        cls.source.mkdir()
        cls.env = dict(os.environ, XDG_CONFIG_HOME=str(cls.root / "config"),
                       CARGO_HOME=str(cls.root / "cargo-home"), CARGO_NET_OFFLINE="true")
        cls.run_at(cls.source, "git", "init", "-b", "master")
        cls.run_at(cls.source, "git", "config", "core.excludesFile", "/dev/null")
        for name in (".config/wt.toml", ".worktreeinclude", "scripts/worktree-cache.py",
                     "rust-toolchain.toml"):
            path = cls.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(PROJECT / name, path)
        (cls.source / "src").mkdir()
        (cls.source / "src/lib.rs").write_text("pub fn fixture() {}\n")
        (cls.source / "build.rs").write_text('''fn main() {
    println!("cargo:rerun-if-env-changed=CACHE_TEST_HOLD");
    if let Some(path) = std::env::var_os("CACHE_TEST_HOLD") {
        let path = std::path::PathBuf::from(path);
        std::fs::write(path.with_extension("started"), "started").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while path.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}
''')
        (cls.source / "Cargo.toml").write_text(
            '[package]\nname = "cache-fixture"\nversion = "0.1.0"\nedition = "2024"\n'
            '[dependencies]\ncache-dependency = { path = "../dependency" }\n')
        dependency = cls.root / "dependency"
        (dependency / "src").mkdir(parents=True)
        (dependency / "Cargo.toml").write_text(
            '[package]\nname = "cache-dependency"\nversion = "0.1.0"\nedition = "2024"\n')
        (dependency / "src/lib.rs").write_text("pub fn dependency() {}\n")
        (cls.source / ".gitignore").write_text("/target/**\n!/target/**/\n.env*\n/private/\n/runtime/\n/evidence/\n/transcripts/\n/user-data/\n/.cargo/credentials.toml\n")
        cls.run_at(cls.source, "cargo", "generate-lockfile", "--offline")
        cls.run_at(cls.source, "git", "add", ".")
        cls.run_at(cls.source, "git", "-c", "user.name=Cache Test", "-c",
                   "user.email=cache-test@example.invalid", "-c", "commit.gpgsign=false",
                   "commit", "-m", "Synthetic cache fixture")
        cls.run_at(cls.source, "cargo", "build", "--locked", "--offline")
        cls.negative = (".env", ".env.local", ".cargo/credentials.toml", "private/key",
                        "runtime/control.sqlite", "runtime/service-ownership.json",
                        "evidence/check.txt", "transcripts/session.json", "user-data/item",
                        "target/validation/evidence.json", "target/debug/incremental/state",
                        "target/doc/index.html", "target/debug/examples/example",
                        "target/debug/deps/unrelated.txt",
                        "target/debug/build/synthetic/out/.env",
                        "target/debug/build/synthetic/out/credentials.json",
                        "target/debug/build/synthetic/out/control.sqlite",
                        "target/debug/build/synthetic/out/transcripts/session.json",
                        "target/debug/build/synthetic/out/cache.lock",
                        "target/debug/build/synthetic/out/service.pid")
        for name in cls.negative:
            path = cls.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("disposable synthetic negative fixture\n")

    @classmethod
    def run_at(cls, root, *command, env=None):
        result = subprocess.run(command, cwd=root, env=env or cls.env,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode:
            raise AssertionError(f"{command!r} failed:\n{result.stdout}")
        return result.stdout

    def destination(self, hooks=False):
        name = self.id().split(".")[-1]
        destination = self.root / name
        args = ["wt", "switch", "--create", name, "--base", "master", "--path",
                str(destination), "--yes", "--no-cd"]
        if hooks:
            # This must see the copy before --execute runs, not a background race.
            args += ["--execute", "python3", "--", "-c",
                     "from pathlib import Path; assert list(Path('target/debug/deps').glob('*.rlib'))"]
        else:
            args += ["--no-hooks"]
        self.run_at(self.source, *args)
        return destination

    def copy(self, destination, *args, env=None):
        return self.run_at(destination, "python3", "scripts/worktree-cache.py",
                           str(self.source), *args, env=env)

    def test_blocking_hook_and_independent_copy(self):
        destination = self.destination(hooks=True)
        for name in self.negative:
            self.assertFalse((destination / name).exists(), name)
        original = next((self.source / "target/debug/deps").glob("*.rlib"))
        copied = destination / original.relative_to(self.source)
        self.assertEqual(original.stat().st_mtime_ns, copied.stat().st_mtime_ns)
        self.assertNotEqual(original.stat().st_ino, copied.stat().st_ino)
        output = self.run_at(destination, "cargo", "build", "--locked", "--offline", "-v")
        self.assertIn("Fresh cache-dependency", output)
        copied.write_bytes(b"independent copy")
        self.assertNotEqual(original.read_bytes(), copied.read_bytes())
        # A locally-created lock is empty, not the source's lock contents/inode.
        source_lock = self.source / "target/debug/.cargo-lock"
        dest_lock = destination / "target/debug/.cargo-lock"
        self.assertNotEqual(source_lock.stat().st_ino, dest_lock.stat().st_ino)

    def test_dry_run_then_real_copy(self):
        destination = self.destination()
        self.copy(destination, "--dry-run")
        self.assertFalse((destination / "target").exists())
        self.copy(destination)
        self.assertTrue(list((destination / "target/debug/deps").glob("*.rlib")))
        self.assertIn("destination already", self.copy(destination))

    def test_changed_lockfile(self):
        destination = self.destination()
        with (destination / "Cargo.lock").open("a") as lock:
            lock.write("\n# synthetic mismatch\n")
        self.assertIn("differ", self.copy(destination))
        self.assertFalse((destination / "target").exists())

    def test_changed_toolchain(self):
        destination = self.destination()
        (destination / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "missing-fixture"\n')
        self.assertIn("differ", self.copy(destination))
        self.assertFalse((destination / "target").exists())

    def test_changed_policy(self):
        destination = self.destination()
        (destination / ".worktreeinclude").unlink()
        self.assertIn("skipped", self.copy(destination))
        output = self.run_at(destination, "wt", "step", "copy-ignored", "--require-include",
                             "--from", str(destination), "--to", str(self.source), "--dry-run")
        self.assertIn(".worktreeinclude", output)

    def test_custom_target(self):
        destination = self.destination()
        self.assertIn("custom target", self.copy(destination, env=dict(self.env, CARGO_BUILD_TARGET="synthetic")))
        self.assertFalse((destination / "target").exists())

    def test_effective_build_directory(self):
        destination = self.destination()
        # Exercise metadata, not just the environment/config comparison guards.
        cargo_config = self.source / ".cargo/config.toml"
        dest_config = destination / ".cargo/config.toml"
        cargo_config.parent.mkdir(exist_ok=True)
        dest_config.parent.mkdir(exist_ok=True)
        try:
            for path in (cargo_config, dest_config):
                path.write_text('[build]\nbuild-dir = "separate-build"\n')
            self.assertIn("target/build directory", self.copy(destination))
            self.assertFalse((destination / "target").exists())
        finally:
            cargo_config.unlink()
            dest_config.unlink()

    def test_cross_target_config(self):
        destination = self.destination()
        cargo_config = self.source / ".cargo/config.toml"
        dest_config = destination / ".cargo/config.toml"
        cargo_config.parent.mkdir(exist_ok=True)
        dest_config.parent.mkdir(exist_ok=True)
        try:
            for path in (cargo_config, dest_config):
                path.write_text('[build]\ntarget = "foreign-synthetic"\n')
            self.assertIn("cross-target", self.copy(destination))
            self.assertFalse((destination / "target").exists())
        finally:
            cargo_config.unlink()
            dest_config.unlink()

    def test_busy_source(self):
        destination = self.destination()
        with (self.source / "target/debug/.cargo-lock").open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIn("in use", self.copy(destination))
        self.assertFalse((destination / "target").exists())

    def test_real_cargo_build_lock(self):
        destination = self.destination()
        hold = self.root / "hold-build"
        hold.touch()
        process = subprocess.Popen(["cargo", "build", "--locked", "--offline"], cwd=self.source,
                                   env=dict(self.env, CACHE_TEST_HOLD=str(hold)),
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + 10
            while not hold.with_suffix(".started").exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    self.fail("synthetic Cargo build did not reach its bounded hold")
                time.sleep(0.02)
            self.assertIn("in use", self.copy(destination))
            self.assertFalse((destination / "target").exists())
        finally:
            hold.unlink()
            output, _ = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, output)

    def test_recursive_directory_plan(self):
        destination = self.destination()
        # Git's worktree-shared info/exclude can collapse an otherwise safe file
        # plan into a recursive directory. Never trust that plan with secrets.
        exclude = self.source / ".git/info/exclude"
        original = exclude.read_bytes()
        try:
            with exclude.open("a") as file:
                file.write("\n/target/debug/build/synthetic/out/generated.rs/\n")
            private = self.source / "target/debug/build/synthetic/out/generated.rs/private"
            private.parent.mkdir(parents=True)
            private.write_text("synthetic private material")
            self.assertIn("recursive directory", self.copy(destination))
            self.assertFalse((destination / "target").exists())
        finally:
            exclude.write_bytes(original)
            shutil.rmtree(private.parent)

    def test_symlink(self):
        destination = self.destination()
        link = self.source / "target/debug/deps/synthetic.rlib"
        link.symlink_to(self.source / ".env")
        try:
            self.assertIn("symlink", self.copy(destination))
            self.assertFalse((destination / "target").exists())
        finally:
            link.unlink()

    def test_fifo(self):
        destination = self.destination()
        fifo = self.source / "target/debug/build/synthetic/out/generated.rs"
        os.mkfifo(fifo)
        process = subprocess.Popen(["python3", "scripts/worktree-cache.py", str(self.source)],
                                   cwd=destination, env=self.env, start_new_session=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            try:
                output, _ = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                self.fail("cache copying blocked on a FIFO")
            self.assertEqual(process.returncode, 0, output)
            self.assertIn("not a regular file", output)
            self.assertFalse((destination / "target").exists())
        finally:
            fifo.unlink()

    def test_cached_platform_mismatch(self):
        destination = self.destination()
        info = self.source / "target/.rustc_info.json"
        original = info.read_bytes()
        try:
            info.write_text(json.dumps({"outputs": {"test": {"success": True, "stdout": "foreign ABI"}}}))
            self.assertIn("does not match", self.copy(destination))
            self.assertFalse((destination / "target").exists())
        finally:
            info.write_bytes(original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
