#!/usr/bin/env bash
# Boot the fastapi dogfood fixture for DAST.
# Port assignment: express=4001, nextjs=4002, django=4003, fastapi=4004.

set -euo pipefail

cd "$(dirname "$0")/.."

docker build -t deptex-dogfood-fastapi:local .
docker rm -f deptex-dogfood-fastapi >/dev/null 2>&1 || true
docker run -d \
  --name deptex-dogfood-fastapi \
  -p 4004:4004 \
  deptex-dogfood-fastapi:local

echo "fastapi dogfood fixture is up at http://localhost:4004"
echo "endpoints to scan:"
echo "  GET  /users"
echo "  GET  /users/lookup?name=<sqli-payload>"
echo "tear down with: docker rm -f deptex-dogfood-fastapi"
