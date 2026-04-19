/**
 * Single source of truth for "project is currently extracting" across Overview, Dependencies, Compliance, Watchtower.
 * Backend project_repositories.status uses: initializing | extracting | analyzing | finalizing | ready | not_connected | error | cancelled | pending
 * Only the first four mean "extraction in progress"; everything else (ready, not_connected, error, loading, etc.) must NOT show the extracting spinner.
 *
 * Special case: after the Fly extraction pipeline, the worker sets status `analyzing` and extraction_step `completed`
 * while QStash populate runs; extraction_jobs is already `completed`. That is background enrichment, not clone/scan —
 * treat as NOT ongoing so Recent Activity and Overview stay aligned.
 */

export const EXTRACTING_STATUSES = ['initializing', 'extracting', 'analyzing', 'finalizing'] as const;

export type ExtractingStatus = (typeof EXTRACTING_STATUSES)[number];

/** True only when the clone/scan pipeline is actively in progress. Pass extraction_step from project_repositories when available. */
export function isExtractionOngoing(status: string, extractionStep: string | null | undefined = undefined): boolean {
  if (!status || status === 'loading') return false;
  if (status === 'analyzing' && extractionStep === 'completed') return false;
  return EXTRACTING_STATUSES.includes(status as ExtractingStatus);
}

/**
 * True when extraction is ongoing AND the project has never completed one before.
 * Use this to gate blocking UI (ExtractionProgressCard, grey nodes). Re-syncs of
 * projects that already have data should NOT block the UI.
 */
export function isInitialExtraction(
  status: string,
  extractionStep: string | null | undefined,
  lastExtractedAt: string | null | undefined,
): boolean {
  return isExtractionOngoing(status, extractionStep) && !lastExtractedAt;
}
