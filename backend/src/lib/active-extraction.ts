import { SupabaseClient } from '@supabase/supabase-js';

/**
 * Sentinel used as the WHERE-clause value when a project has no active run yet.
 * `'__no_active_run__'` will not match any real `extraction_run_id`, so passing
 * it to `.eq('extraction_run_id', ...)` cleanly returns zero rows instead of
 * leaking unfiltered data — much safer than `null`, which would compare with
 * `= NULL` and silently match nothing OR everything depending on driver.
 */
export const NO_ACTIVE_RUN = '__no_active_run__';

/**
 * Fetches the current active extraction_run_id for a project.
 *
 * After Phase 19 (soft-switch commit), findings reads must filter by
 * `extraction_run_id = projects.active_extraction_run_id` to see the current
 * generation. Call this once at the top of any route that reads findings.
 *
 * Returns `null` for projects that have never completed an extraction.
 */
export async function getActiveExtractionId(
  supabase: SupabaseClient,
  projectId: string
): Promise<string | null> {
  const { data, error } = await supabase
    .from('projects')
    .select('active_extraction_run_id')
    .eq('id', projectId)
    .single();

  if (error || !data) return null;
  return (data.active_extraction_run_id as string | null) ?? null;
}

/**
 * Batch variant. Returns the non-null `active_extraction_run_id`s for a list
 * of projects. Use with `.in('extraction_run_id', activeRunIds)` for org-wide
 * rollups across many projects.
 *
 * If `activeRunIds.length === 0`, callers should short-circuit: it means
 * either no projects were passed, or none have ever completed an extraction.
 * Either way there's nothing to filter against, so the rollup result is empty.
 */
export async function getActiveExtractionIds(
  supabase: SupabaseClient,
  projectIds: string[]
): Promise<string[]> {
  if (projectIds.length === 0) return [];
  const { data, error } = await supabase
    .from('projects')
    .select('active_extraction_run_id')
    .in('id', projectIds);
  if (error || !data) return [];
  return data
    .map((p: { active_extraction_run_id: string | null }) => p.active_extraction_run_id)
    .filter((id): id is string => typeof id === 'string' && id.length > 0);
}
