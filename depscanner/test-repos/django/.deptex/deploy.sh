#!/usr/bin/env bash
# Boot the django dogfood fixture for DAST.
# Port assignment: sequential across server-side fixtures.
# express=4001, nextjs=4002, django=4003.

set -euo pipefail

cd "$(dirname "$0")/.."

docker build -t deptex-dogfood-django:local .
docker rm -f deptex-dogfood-django >/dev/null 2>&1 || true
docker run -d \
  --name deptex-dogfood-django \
  -p 4003:4003 \
  deptex-dogfood-django:local

echo "django dogfood fixture is up at http://localhost:4003"
echo "endpoints to scan:"
echo "  GET  /msg?msg=<reflected-xss-payload>"
echo "  GET  /static"
echo "tear down with: docker rm -f deptex-dogfood-django"
