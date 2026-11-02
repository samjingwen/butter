#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# The retained native harness owns its disposable PostgreSQL 18 container and
# per-test databases. Missing Docker is a failure, never a skipped acceptance.
cargo test -p butter-workflow --all-features --locked "$@"
