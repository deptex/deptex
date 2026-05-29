#!/usr/bin/env bash
# Boot the spring-boot dogfood fixture for DAST.
# Port assignment: express=4001, nextjs=4002, django=4003, fastapi=4004,
# flask=4005, spring-boot=4006.

set -euo pipefail

cd "$(dirname "$0")/.."

docker build -t deptex-dogfood-spring-boot:local .
docker rm -f deptex-dogfood-spring-boot >/dev/null 2>&1 || true
docker run -d \
  --name deptex-dogfood-spring-boot \
  -p 4006:4006 \
  deptex-dogfood-spring-boot:local

echo "spring-boot dogfood fixture is up at http://localhost:4006"
echo "endpoints to scan:"
echo "  GET  /owners/find?name=<sqli-payload>"
echo "  GET  /owners/<id>"
echo "tear down with: docker rm -f deptex-dogfood-spring-boot"
