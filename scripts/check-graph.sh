#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
minimal=$(cargo tree -p butter --no-default-features --locked --edges normal --prefix none --format '{p}')
if grep -Eq '^(butter-(boot|web|data|workflow)|axum|sqlx|runledger-core) v' <<<"$minimal"; then
  printf 'Minimal Butter unexpectedly selects an integration.\n' >&2
  exit 1
fi
web=$(cargo tree -p butter --locked --edges normal --prefix none --format '{p}')
if grep -Eq '^(butter-(data|workflow)|sqlx|runledger-core) v' <<<"$web"; then
  printf 'HTTP-only Butter unexpectedly selects persistence.\n' >&2
  exit 1
fi
workflow=$(cargo tree -p butter --no-default-features --features workflow --locked --edges normal --prefix none --format '{p}')
grep -Eq '^butter-workflow v' <<<"$workflow"
if grep -Eq '^runledger-(postgres|runtime) v' <<<"$workflow"; then
  printf 'Workflow selects an extra native persistence/runtime implementation.\n' >&2
  exit 1
fi
# An ambiguous SQLx selection makes this command fail; all components must share
# the same native type identity, not independently resolved major versions.
cargo tree --workspace --all-features --locked --invert sqlx --depth 1
printf 'PASS: minimal, HTTP and workflow feature/source isolation\n'
