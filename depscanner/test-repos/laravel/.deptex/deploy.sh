#!/usr/bin/env bash
# Boot the laravel dogfood fixture for DAST. Port 4010.

set -euo pipefail

cd "$(dirname "$0")/.."

docker build -t deptex-dogfood-laravel:local .
docker rm -f deptex-dogfood-laravel >/dev/null 2>&1 || true
docker run -d \
  --name deptex-dogfood-laravel \
  -p 4010:4010 \
  deptex-dogfood-laravel:local

echo "laravel dogfood fixture is up at http://localhost:4010"
echo "endpoints to scan:"
echo "  GET  /users/search?name=<sqli-payload>"
echo "  GET  /users/<id>"
echo "tear down with: docker rm -f deptex-dogfood-laravel"
