// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DO NOT EDIT — synced from backend/src/lib/dast-openapi-constants.ts via
//   scripts/sync-dast-openapi.ts
// Edit the backend source and re-run the sync script. CI fails if this file
// drifts.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Phase 35 (v1.1) — shared constants used by BOTH the backend's PATCH-time
// spec validation AND the depscanner worker's scan-time spec resolution.
//
// This is the source-of-truth copy. The depscanner ships a synced mirror at
// `depscanner/src/dast/openapi-constants.ts`, kept byte-identical via
// `scripts/sync-dast-openapi.ts` + a CI grep diff.

/** Max wall-clock time for an outbound URL-mode spec fetch (PATCH or scan). */
export const FETCH_TIMEOUT_MS = 5000;

/** Hard cap on the bytes we'll accept from a remote spec URL (25 MB). */
export const MAX_SPEC_BYTES = 25 * 1024 * 1024;

/**
 * OpenAPI versions we accept on URL/upload paths. Synthesizer emits 3.1.0;
 * customers can supply 3.0.x or Swagger 2.0 (ZAP imports all three per the
 * 2026-05-21 smoke spike against the pinned ZAP image).
 */
export const ACCEPTED_OPENAPI_VERSIONS = ['2.0', '3.0', '3.1'] as const;
export type AcceptedOpenApiVersion = typeof ACCEPTED_OPENAPI_VERSIONS[number];
