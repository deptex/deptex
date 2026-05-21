#!/usr/bin/env bash
# Phase 35 (v1.1) — fail CI when frontend SPEC_ERROR_CODES drift away
# from the backend canonical declaration.
#
# Both files maintain an `export const SPEC_ERROR_CODES = [ ... ] as const`
# block. We grep the inside of the array (trimmed lines starting with a
# single-quoted string), normalize whitespace, and `diff` them.
#
# Re-run locally before opening a PR if you change either file:
#   bash scripts/check-dast-error-codes-match.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND="${ROOT}/backend/src/types/dast.ts"
FRONTEND="${ROOT}/frontend/src/lib/dast-error-codes.ts"

if [ ! -f "${BACKEND}" ]; then
  echo "SPEC_ERROR_CODES backend source missing: ${BACKEND}" >&2
  exit 1
fi
if [ ! -f "${FRONTEND}" ]; then
  echo "SPEC_ERROR_CODES frontend mirror missing: ${FRONTEND}" >&2
  exit 1
fi

# Extract everything between `SPEC_ERROR_CODES = [` and the closing `]`,
# keep only quoted strings, normalize ordering so a re-ordering doesn't
# fail the check (the *set* of codes is what matters).
extract() {
  awk '
    /SPEC_ERROR_CODES *= *\[/ { capturing=1; next }
    capturing && /^[[:space:]]*\] *as const/ { capturing=0 }
    capturing {
      if (match($0, /'\''[A-Za-z0-9_]+'\''/)) {
        s = substr($0, RSTART+1, RLENGTH-2)
        print s
      }
    }
  ' "$1" | LC_ALL=C sort
}

BACKEND_CODES="$(extract "${BACKEND}")"
FRONTEND_CODES="$(extract "${FRONTEND}")"

if [ "${BACKEND_CODES}" != "${FRONTEND_CODES}" ]; then
  echo "SPEC_ERROR_CODES drift detected:" >&2
  echo "  backend  (${BACKEND}):" >&2
  echo "${BACKEND_CODES}" | sed 's/^/    /' >&2
  echo "  frontend (${FRONTEND}):" >&2
  echo "${FRONTEND_CODES}" | sed 's/^/    /' >&2
  echo "" >&2
  echo "Edit BOTH files in the same commit so the set matches." >&2
  exit 1
fi

echo "SPEC_ERROR_CODES parity OK ($(echo "${BACKEND_CODES}" | wc -l | tr -d ' ') codes)"
