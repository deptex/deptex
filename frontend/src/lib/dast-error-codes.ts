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
