#!/usr/bin/env bash
# Boot the express dogfood fixture for DAST.
# Port assignment per runbook: 4000 + alphabetical index. express=4001.

set -euo pipefail

cd "$(dirname "$0")/.."

# Plain docker (no compose) — single container, no volume bind, no auto-restart.
docker build -t deptex-dogfood-express:local .
docker rm -f deptex-dogfood-express >/dev/null 2>&1 || true
docker run -d \
  --name deptex-dogfood-express \
  -p 4001:4001 \
  deptex-dogfood-express:local

echo "express dogfood fixture is up at http://localhost:4001"
echo "endpoints to scan:"
echo "  GET  /api/health"
echo "  GET  /api/render?tpl=<lodash-template>"
echo "  GET  /api/users?id=<sql-payload>"
echo "tear down with: docker rm -f deptex-dogfood-express"
