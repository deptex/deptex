import { SupabaseClient } from '@supabase/supabase-js';

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
