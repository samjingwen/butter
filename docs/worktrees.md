# Worktree dependency caches

Butter's `.config/wt.toml` uses a blocking `pre-start` hook with Worktrunk v0.81 or newer and Python 3.11 or newer.
The copy finishes before background hooks or `wt switch --execute` can build.
It does not install dependencies, run checks, start services or provision databases.

The source is the selected base's existing worktree, falling back to primary when the base has no worktree.
If it has no compatible cache, creation simply takes the ordinary cold-build path.
Build normally in the source worktree first, for example with `cargo build --locked`.

## What is reused

Cargo already reuses its registry downloads and pinned Git checkouts through the existing `CARGO_HOME` (normally `~/.cargo`).
Do not copy Cargo homes, registry authentication, credentials, Rustup state or private environment files between worktrees.
No symlink or alternate shared writable target directory is installed.

The explicit `.worktreeinclude` selects individual library/dependency-info files, fingerprints, build scripts and generated Rust/native objects under native `target/debug/deps`, `.fingerprint` and `build` caches.
Worktrunk's `wt step copy-ignored --require-include` reflinks them where supported, otherwise makes independent full copies.
It preserves file timestamps, which Cargo needs to reuse dependency fingerprints.
Cargo remains responsible for validating features, flags, changed local source and build-script dependencies; workspace crates can legitimately rebuild after relocation.

The guard compares tracked lockfiles, all Cargo manifests, pinned toolchains, public Cargo configuration and copy policies.
It checks resolved Rust compiler/host ABI and native target configuration against Cargo's cached compiler information, and checks effective target directories using offline locked metadata.
Custom target directories, cross targets, compiler wrappers/flags, mismatches, missing tools, symlinks, busy source caches and existing destination targets skip the optimization without changing normal Cargo behavior.
It holds Cargo's source build/artifact locks during copying and creates separate destination locks; source lock/control files themselves are never transferred.
Keep source builds idle during worktree creation, including builds using custom Cargo build directories outside this supported native layout.

Worktrunk v0.81 discovers ignored directories as recursive copy units, so exclusions inside such a selected directory would not protect its contents.
Butter's `.gitignore` keeps target directories traversable while ignoring their files; the allowlist selects only individual files.
The guard inspects Worktrunk's JSON dry-run plan and refuses recursive directories, symlinks and non-regular files such as FIFOs before copying.

Incremental state, docs, example binaries, whole Cargo homes, runtime databases, service records, user data, transcripts and validation evidence are not selected.
Additional exclusions reject lock/control files and environment/auth/database/log files even within the selected cache directories.
These directories must remain disposable Cargo build output, not a storage location for private or runtime material.
Do not broaden the allowlist to `target/`, `.cache/`, `.cargo/` or private files.

## Inspect and verify

From an empty destination worktree with the same committed copy policy:

```sh
python3 scripts/worktree-cache.py /path/to/source-worktree --dry-run
python3 scripts/worktree-cache.py /path/to/source-worktree
cargo check -p butter --no-default-features --locked --offline -v
```

The verbose Cargo output should report compatible upstream dependencies as `Fresh` rather than compiling them again.
An offline build proves no dependency download is needed only when that Cargo home already contains the locked dependencies.
No cache is required for correctness: a fresh clone, `wt switch --no-hooks`, or a skipped copy still supports ordinary online `cargo build --locked` and the documented check commands.
For copy-policy regressions, run `python3 scripts/test-worktree-cache.py`; it uses only disposable synthetic repositories and never starts application services or databases.
