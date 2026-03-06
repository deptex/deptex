/**
 * Single source of truth for "project is currently extracting" across Overview, Dependencies, Compliance, Watchtower.
 * Backend project_repositories.status uses: initializing | extracting | analyzing | finalizing | ready | not_connected | error | cancelled | pending
 * Only the first four mean "extraction in progress"; everything else (ready, not_connected, error, loading, etc.) must NOT show the extracting spinner.
 */

export const EXTRACTING_STATUSES = ['initializing', 'extracting', 'analyzing', 'finalizing'] as const;

export type ExtractingStatus = (typeof EXTRACTING_STATUSES)[number];

/** True only when status is one of the in-progress extraction states. Returns false for loading, ready, not_connected, error, etc. */
export function isExtractionOngoing(status: string): boolean {
  if (!status || status === 'loading') return false;
  return EXTRACTING_STATUSES.includes(status as ExtractingStatus);
}
