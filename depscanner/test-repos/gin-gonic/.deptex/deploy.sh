#!/usr/bin/env bash
# Boot the gin-gonic dogfood fixture for DAST. Port 4007.

set -euo pipefail

cd "$(dirname "$0")/.."

docker build -t deptex-dogfood-gin-gonic:local .
docker rm -f deptex-dogfood-gin-gonic >/dev/null 2>&1 || true
docker run -d \
  --name deptex-dogfood-gin-gonic \
  -p 4007:4007 \
  deptex-dogfood-gin-gonic:local

echo "gin-gonic dogfood fixture is up at http://localhost:4007"
echo "endpoints to scan:"
echo "  GET  /run?name=<cmdi-payload>"
echo "  GET  /files"
echo "tear down with: docker rm -f deptex-dogfood-gin-gonic"
