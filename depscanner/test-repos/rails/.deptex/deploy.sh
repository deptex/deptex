#!/usr/bin/env bash
# Boot the rails dogfood fixture for DAST. Port 4009.

set -euo pipefail

cd "$(dirname "$0")/.."

docker build -t deptex-dogfood-rails:local .
docker rm -f deptex-dogfood-rails >/dev/null 2>&1 || true
docker run -d \
  --name deptex-dogfood-rails \
  -p 4009:4009 \
  deptex-dogfood-rails:local

echo "rails dogfood fixture is up at http://localhost:4009"
echo "endpoints to scan:"
echo "  GET  /users/search?name=<sqli-payload>"
echo "  GET  /users/<id>"
echo "tear down with: docker rm -f deptex-dogfood-rails"
