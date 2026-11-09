#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

assert_absent() {
  if grep -Eq "^($2) v" <<<"$1"; then
    printf 'Feature/source isolation failed: forbidden integration selected.\n' >&2
    exit 1
  fi
}
assert_present() { grep -Eq "^$2 v" <<<"$1"; }
for features in '' security web data workflow actuator web,security web,actuator web,data,actuator; do
  args=(--no-default-features)
  [[ -z "$features" ]] || args+=(--features "$features")
  graph=$(cargo tree -p butter "${args[@]}" --locked --edges normal --prefix none --format '{p}')
  assert_present "$graph" butter-core
  case "$features" in
    '') assert_absent "$graph" 'butter-(security|boot|web|actuator|data|workflow)|axum|sqlx|runledger-core' ;;
    security) assert_present "$graph" butter-security
              assert_absent "$graph" 'butter-(boot|web|actuator|data|workflow)|axum|sqlx|runledger-core' ;;
    web) assert_present "$graph" butter-boot
         assert_present "$graph" butter-web
         assert_absent "$graph" 'butter-(security|actuator|data|workflow)|sqlx|runledger-core' ;;
    data) assert_present "$graph" butter-data
          assert_absent "$graph" 'butter-(security|boot|web|actuator|workflow)|axum|runledger-core' ;;
    workflow) assert_present "$graph" butter-workflow
              assert_present "$graph" butter-data
              assert_absent "$graph" 'butter-(security|boot|web|actuator)|axum|runledger-(postgres|runtime)' ;;
    actuator) assert_present "$graph" butter-actuator
              assert_absent "$graph" 'butter-(security|boot|web|data|workflow)|axum|sqlx|runledger-core' ;;
    web,security) assert_present "$graph" butter-boot
                  assert_present "$graph" butter-web
                  assert_present "$graph" butter-security
                  assert_absent "$graph" 'butter-(actuator|data|workflow)|sqlx|runledger-core' ;;
    web,actuator) assert_present "$graph" butter-boot
                   assert_present "$graph" butter-actuator
                   assert_absent "$graph" 'butter-(security|data|workflow)|sqlx|runledger-core' ;;
    web,data,actuator) assert_present "$graph" butter-boot
                       assert_present "$graph" butter-actuator
                       assert_present "$graph" butter-data
                       assert_absent "$graph" 'butter-(security|workflow)|runledger-core' ;;
  esac
  cargo check -p butter "${args[@]}" --locked
done
# Check real defaults, not only --no-default-features.
defaults=$(cargo tree -p butter --locked --edges normal --prefix none --format '{p}')
assert_absent "$defaults" 'butter-(security|boot|web|actuator|data|workflow)|axum|sqlx|runledger-core'
for component in butter-core butter-security butter-actuator butter-web; do
  graph=$(cargo tree -p "$component" --locked --edges normal --prefix none --format '{p}')
  case "$component" in
    butter-core) assert_absent "$graph" 'butter-(security|web|boot|actuator|data|workflow)|axum|sqlx' ;;
    butter-security) assert_absent "$graph" 'butter-(core|web|boot|actuator|data|workflow)|axum|sqlx|runledger-core' ;;
    butter-actuator) assert_absent "$graph" 'butter-(security|web|boot|data|workflow)|axum|sqlx' ;;
    butter-web) assert_absent "$graph" 'butter-(security|actuator|boot|data|workflow)|sqlx' ;;
  esac
done
# Ambiguous native SQLx identities make this command fail.
cargo tree --workspace --all-features --locked --invert sqlx --depth 1
printf 'PASS: empty defaults, nine facade combinations and component/source isolation\n'
