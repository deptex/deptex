#!/usr/bin/env bash
# Bring up a local Supabase stack and load the Deptex schema.
#
# Prereqs:
#   - Docker Desktop running
#   - Supabase CLI installed: https://supabase.com/docs/guides/local-development/cli/getting-started
#
# Idempotent: safe to re-run. If the stack is already up it just reloads schema.sql.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCHEMA="$ROOT/backend/database/schema.sql"
HELPER="$ROOT/backend/database/phase19_4_schema_dump_helper.sql"

if ! command -v supabase >/dev/null 2>&1; then
  echo "ERROR: supabase CLI not found. Install from https://supabase.com/docs/guides/local-development/cli/getting-started" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running. Start Docker Desktop and retry." >&2
  exit 1
fi

cd "$ROOT"

echo "==> supabase start"
supabase start

# Local Postgres connection — ports come from supabase/config.toml.
DB_URL="postgresql://postgres:postgres@127.0.0.1:54322/postgres"

echo "==> Applying schema.sql ($(wc -l < "$SCHEMA") lines)"
psql "$DB_URL" -v ON_ERROR_STOP=1 -f "$SCHEMA"

echo "==> Installing pg_catalog_dump_v1() helper"
psql "$DB_URL" -v ON_ERROR_STOP=1 -f "$HELPER"

echo ""
echo "Done. Connection info:"
supabase status

cat <<'EOF'

Next:
  1. Copy .env.example to .env and fill in SUPABASE_URL / KEYS from `supabase status` above.
  2. cd backend && npm install && npm run dev
  3. cd frontend && npm install && npm run dev
EOF
