#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo check -p butter --no-default-features --locked
bash scripts/check-graph.sh
cargo test --workspace --exclude butter-workflow --all-features --locked
cargo test -p butter-boot --no-default-features --locked
cargo test -p butter-workflow --all-features --doc --locked
RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -D warnings" cargo doc -p butter --no-default-features --no-deps --locked
RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo build -p butter --example hello --features web,actuator --locked
bash scripts/smoke-http.sh
