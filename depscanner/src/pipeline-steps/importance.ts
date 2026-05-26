/**
 * Helper: read `projects.importance` once before depscore-touching steps run
 * (vuln_scan, semgrep, trufflehog, reachability). The scalar is multiplied
 * directly into the depscore as `tierWeight`.
 *
 * Not a runStage step because it does not log, has no timeout, has no failure
 * mode worth persisting (a missing row degrades to importance=1.0 silently).
 * Mutates ctx.importance.
 */

import type { PipelineContext } from '../pipeline-types';

export async function loadImportance(ctx: PipelineContext): Promise<void> {
  const { supabase, projectId } = ctx;
  let importance = 1.0;

  const { data: projRow, error: projErr } = await supabase
    .from('projects')
    .select('importance')
    .eq('id', projectId)
    .maybeSingle();
  if (projErr) {
    console.warn(`[importance] Failed to load project importance for ${projectId}; defaulting to 1.0:`, projErr.message);
  }
  const raw = (projRow as { importance?: number | string } | null)?.importance;
  if (raw != null) {
    const parsed = typeof raw === 'string' ? Number(raw) : raw;
    if (Number.isFinite(parsed) && parsed >= 0.5 && parsed <= 2.0) {
      importance = parsed;
    }
  }

  ctx.importance = importance;
}
