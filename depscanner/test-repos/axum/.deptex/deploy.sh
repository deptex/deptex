#!/usr/bin/env bash
# Boot the axum dogfood fixture for DAST. Port 4008.

set -euo pipefail

cd "$(dirname "$0")/.."

docker build -t deptex-dogfood-axum:local .
docker rm -f deptex-dogfood-axum >/dev/null 2>&1 || true
docker run -d \
  --name deptex-dogfood-axum \
  -p 4008:4008 \
  deptex-dogfood-axum:local

echo "axum dogfood fixture is up at http://localhost:4008"
echo "endpoints to scan:"
echo "  GET  /file?name=<traversal-payload>"
echo "  GET  /"
echo "tear down with: docker rm -f deptex-dogfood-axum"
