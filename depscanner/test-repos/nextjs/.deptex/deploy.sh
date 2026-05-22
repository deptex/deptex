#!/usr/bin/env bash
# Boot the nextjs dogfood fixture for DAST.
# Port assignment: sequential across server-side fixtures.
# express=4001, nextjs=4002.

set -euo pipefail

cd "$(dirname "$0")/.."

# Plain docker (no compose) — single container, no volume bind, no auto-restart.
docker build -t deptex-dogfood-nextjs:local .
docker rm -f deptex-dogfood-nextjs >/dev/null 2>&1 || true
docker run -d \
  --name deptex-dogfood-nextjs \
  -p 4002:4002 \
  deptex-dogfood-nextjs:local

echo "nextjs dogfood fixture is up at http://localhost:4002"
echo "endpoints to scan:"
echo "  GET  /?msg=<reflected-xss-payload>"
echo "tear down with: docker rm -f deptex-dogfood-nextjs"
