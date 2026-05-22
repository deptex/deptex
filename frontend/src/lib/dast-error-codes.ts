// Phase 35 (v1.1) — duplicated from backend/src/types/dast.ts.
//
// Frontend is ESM, backend is CommonJS — Vite's bundler can't reach across
// the workspace boundary, so this enum is maintained as a duplicate.
// `scripts/check-dast-error-codes-match.sh` is a CI step that greps the
// SPEC_ERROR_CODES block from both files and fails the PR on divergence.
//
// To add or rename a code: edit BOTH files (here + backend/src/types/dast.ts)
// in the same commit. The CI check catches one-sided edits.

export const SPEC_ERROR_CODES = [
  'invalid_spec_source',
  'spec_url_required',
  'spec_url_invalid',
  'spec_url_unreachable',
  'spec_parse_failed',
  'spec_too_large',
  'spec_unavailable',
  'target_not_found',
  'unsupported_openapi_on_nuclei',
] as const;
export type SpecErrorCode = typeof SPEC_ERROR_CODES[number];

/**
 * Map a backend SpecErrorCode to user-friendly copy for toast / inline
 * error rendering. Unknown codes fall through to a generic message so a
 * rename without a frontend update still produces something readable.
 */
export function friendlySpecErrorMessage(
  code: string | undefined,
  detail?: string | undefined,
): string {
  switch (code) {
    case 'invalid_spec_source':
      return 'Spec source must be Synthesized, URL, or None.';
    case 'spec_url_required':
      return 'Enter a spec URL.';
    case 'spec_url_invalid':
      return `Spec URL is not reachable from Deptex: ${detail ?? 'blocked by SSRF guard'}.`;
    case 'spec_url_unreachable':
      return `Couldn’t fetch the spec at that URL${detail ? ` (${detail})` : ''}.`;
    case 'spec_parse_failed':
      return `Spec didn’t parse as OpenAPI 3.0 / 3.1 or Swagger 2.0${
        detail ? `: ${detail}` : '.'
      }`;
    case 'spec_too_large':
      return 'Spec exceeds the 25 MB cap.';
    case 'spec_unavailable':
      return 'No spec available yet. Run a scan first.';
    case 'target_not_found':
      return 'Target not found.';
    case 'unsupported_openapi_on_nuclei':
      return 'OpenAPI mode is currently ZAP-only. Switch engine to ZAP or set spec source to None.';
    default:
      return 'Something went wrong updating the spec config.';
  }
}

// ---------------------------------------------------------------------------
// Phase 36 (v1.1) — HAR replay-import error codes. Mirror of
// backend/src/lib/dast-har-constants.ts HAR_ERROR_CODES.
// `scripts/check-dast-error-codes-match.sh` extends to compare both blocks.
// ---------------------------------------------------------------------------

export const HAR_ERROR_CODES = [
  'invalid_har_shape',
  'har_too_large',
  'har_too_small',
  'har_entry_too_large',
  'har_non_https_entry',
  'har_private_ip_entry',
  'har_origin_count_exceeded',
  'har_no_replayable_requests',
  'har_totp_secret_invalid',
  'replay_payload_too_large',
  'dast_encryption_not_configured',
] as const;
export type HarErrorCode = typeof HAR_ERROR_CODES[number];

/**
 * Map a backend HarErrorCode to user-friendly copy for the Replay tab's
 * upload-error banner.
 */
export function friendlyHarErrorMessage(
  code: string | undefined,
  detail?: string | undefined,
): string {
  switch (code) {
    case 'invalid_har_shape':
      return 'That file isn’t a valid HAR (HTTP Archive 1.2). Export it from Chrome DevTools → Network → ⋮ → Save all as HAR with content.';
    case 'har_too_large':
      return 'HAR exceeds the 1.5 MB cap. Trim the captured session to just the login flow before re-exporting.';
    case 'har_too_small':
      return 'The HAR contained no captured requests. Re-record the login and ensure DevTools is recording before you click Sign in.';
    case 'har_entry_too_large':
      return `A single captured request is too large for replay (${detail ?? 'header / body cap exceeded'}). Trim the HAR or drop telemetry-heavy requests.`;
    case 'har_non_https_entry':
      return 'All captured requests must use HTTPS. Re-record against the production hostname (not a local proxy).';
    case 'har_private_ip_entry':
      return 'A captured request points at a private / loopback IP. Replay only supports public IdP targets.';
    case 'har_origin_count_exceeded':
      return 'HAR touches more than 10 hostnames. Trim cross-origin telemetry / analytics before re-exporting.';
    case 'har_no_replayable_requests':
      return 'No replayable requests after filtering. The HAR may have been captured before the login traffic started.';
    case 'har_totp_secret_invalid':
      return 'TOTP secret must be canonical base32 (A-Z and 2-7 only, up to 256 chars). Copy it verbatim from your IdP setup screen.';
    case 'replay_payload_too_large':
      return 'Replay payload is too large to encrypt and store. Trim some captured requests.';
    case 'dast_encryption_not_configured':
      return 'Replay credentials need the DAST encryption key set on the server. Ask an admin to configure DAST_CREDENTIAL_KEY.';
    default:
      return 'Couldn’t process that HAR.';
  }
}
