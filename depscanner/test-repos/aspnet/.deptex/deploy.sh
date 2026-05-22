#!/usr/bin/env bash
# Boot the aspnet dogfood fixture for DAST. Port 4011.

set -euo pipefail

cd "$(dirname "$0")/.."

docker build -t deptex-dogfood-aspnet:local .
docker rm -f deptex-dogfood-aspnet >/dev/null 2>&1 || true
docker run -d \
  --name deptex-dogfood-aspnet \
  -p 4011:4011 \
  deptex-dogfood-aspnet:local

echo "aspnet dogfood fixture is up at http://localhost:4011"
echo "endpoints to scan:"
echo "  GET  /users/by-name?name=<sqli-payload>"
echo "  GET  /users/<id>"
echo "tear down with: docker rm -f deptex-dogfood-aspnet"
