#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
binary="${CARGO_TARGET_DIR:-target}/debug/examples/hello"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/butter-http-smoke.XXXXXX")
pid=
cleanup() {
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid"
    for _ in {1..100}; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.05
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid"
    fi
    wait "$pid" || true
  fi
  # Remove only this invocation's two files and its now-empty owned directory.
  rm -f "$temporary/stdout" "$temporary/stderr"
  rmdir "$temporary"
}
trap cleanup EXIT
for signal in TERM INT; do
  BUTTER_HTTP_ADDR=127.0.0.1:0 "$binary" >"$temporary/stdout" 2>"$temporary/stderr" &
  pid=$!
  address=
  for _ in {1..100}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$temporary/stderr" >&2
      wait "$pid"
      exit 1
    fi
    address=$(sed -n 's/^Listening on http:\/\///p' "$temporary/stdout")
    [[ -n "$address" ]] && break
    sleep 0.05
  done
  [[ -n "$address" ]] || { printf 'No startup address was published.\n' >&2; exit 1; }
  [[ "$address" =~ ^127\.0\.0\.1:[0-9]+$ ]] || { printf 'Unexpected listener address.\n' >&2; exit 1; }
  [[ "$(curl --silent --show-error --fail --max-time 5 "http://$address/")" == 'Smooth like butter.' ]]
  for view in health health/liveness health/readiness; do
    [[ "$(curl --silent --show-error --fail --max-time 5 "http://$address/actuator/$view")" == '{"status":"UP"}' ]]
    curl --silent --show-error --fail --head --max-time 5 "http://$address/actuator/$view" >/dev/null
  done
  for removed in live ready; do
    [[ "$(curl --silent --show-error --max-time 5 --output /dev/null --write-out '%{http_code}' "http://$address/$removed")" == 404 ]]
  done
  kill -"$signal" "$pid"
  for _ in {1..100}; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.05
  done
  if kill -0 "$pid" 2>/dev/null; then
    printf 'Signal shutdown exceeded the smoke deadline.\n' >&2
    kill -KILL "$pid"
    wait "$pid" || true
    pid=
    exit 1
  fi
  wait "$pid"
  pid=
  printf 'PASS: hello, Actuator GET/HEAD, removed legacy probes and SIG%s shutdown\n' "$signal"
done
