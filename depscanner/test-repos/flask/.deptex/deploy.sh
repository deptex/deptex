#!/usr/bin/env bash
# Boot the flask dogfood fixture for DAST.
# Port assignment: express=4001, nextjs=4002, django=4003, fastapi=4004,
# flask=4005.

set -euo pipefail

cd "$(dirname "$0")/.."

docker build -t deptex-dogfood-flask:local .
docker rm -f deptex-dogfood-flask >/dev/null 2>&1 || true
docker run -d \
  --name deptex-dogfood-flask \
  -e FLASK_APP=app.py \
  -p 4005:4005 \
  deptex-dogfood-flask:local

echo "flask dogfood fixture is up at http://localhost:4005"
echo "endpoints to scan:"
echo "  GET  /read?p=<traversal-payload>"
echo "  GET  /dump"
echo "tear down with: docker rm -f deptex-dogfood-flask"
