#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

docker info >/dev/null
docker buildx version >/dev/null
docker buildx build \
  --file Dockerfile.quality \
  --no-cache-filter quality \
  --output type=cacheonly \
  --platform linux/amd64 \
  --progress plain \
  .
