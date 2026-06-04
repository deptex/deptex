import type { Storage } from '../storage';
import type { ExtractedFile } from '../tree-sitter-extractor/languages/types';

/**
 * Persist extractor-side entry points to `project_entry_points`.
 *
 * Writes only under the pending `extraction_run_id`; atomic-commit semantics
 * come from the Phase 19 active-run pointer on `projects`, so no explicit
 * carry-forward / soft-delete is needed here.
 */
export async function storeEntryPoints(
  supabase: Storage,
  projectId: string,
  runId: string,
  files: readonly ExtractedFile[]
): Promise<{ success: boolean; error?: string; count: number; framework?: string; frameworkWriteError?: string }> {
  try {
    const rows: Array<Record<string, unknown>> = [];
    for (const file of files) {
      for (const ep of file.entryPoints ?? []) {
        rows.push({
          project_id: projectId,
          extraction_run_id: runId,
          file_path: ep.filePath,
          line_number: ep.lineNumber,
          framework: ep.framework,
          handler_name: ep.handlerName,
          http_method: ep.httpMethod,
          route_pattern: ep.routePattern,
          entry_point_type: ep.entryPointType,
          classification: ep.classification,
          authenticated: ep.authenticated,
          auth_mechanism: ep.authMechanism,
          middleware_chain: ep.middlewareChain,
          metadata: ep.metadata,
        });
      }
    }

    if (rows.length === 0) return { success: true, count: 0 };

    // Same class of bug as depscanner/src/tree-sitter-extractor/storage.ts:
    // multiple framework detectors can emit the same entry-point tuple
    // (e.g. an express app.get('/x') is reported by both the file-level
    // detector and the AST-level detector, with different metadata blobs but
    // identical conflict keys). PGLite rejects the batch with "ON CONFLICT DO
    // UPDATE command cannot affect row a second time"; dedupe last-write-wins
    // to match Postgres ON CONFLICT DO UPDATE semantics.
    const onConflict = 'project_id,extraction_run_id,file_path,line_number,framework,handler_name';
    const keyFields = onConflict.split(',').map((s) => s.trim());
    const deduped = new Map<string, Record<string, unknown>>();
    for (const row of rows) {
      const key = keyFields.map((f) => String(row[f] ?? '')).join('\x00');
      deduped.set(key, row);
    }
    const finalRows = Array.from(deduped.values());

    const BATCH = 200;
    for (let i = 0; i < finalRows.length; i += BATCH) {
      const slice = finalRows.slice(i, i + BATCH);
      const { error } = await supabase
        .from('project_entry_points')
        .upsert(slice, { onConflict });
      if (error) {
        return { success: false, error: error.message, count: 0 };
      }
    }

    // Write the dominant detected framework back to projects.framework so the
    // project icon (org canvas + project header) reflects what extraction
    // actually parsed. Creation-time detection only peeks the repo's root
    // manifest, which misses the real framework whenever the app lives at a
    // subpath / in a monorepo (e.g. a fixture at depscanner/test-repos/express
    // → "unknown"). The entry-point detector parsed the code, so it's the
    // authoritative signal. Best-effort: a failure here must never fail the
    // scan — the entry points are already persisted.
    const frameworkCounts = new Map<string, number>();
    for (const row of finalRows) {
      const fw = typeof row.framework === 'string' ? row.framework : '';
      if (fw && fw !== 'unknown') frameworkCounts.set(fw, (frameworkCounts.get(fw) ?? 0) + 1);
    }
    let dominantFramework: string | null = null;
    let bestCount = 0;
    for (const [fw, n] of frameworkCounts) {
      if (n > bestCount) {
        bestCount = n;
        dominantFramework = fw;
      }
    }
    if (dominantFramework) {
      const { error: fwError } = await supabase
        .from('projects')
        .update({ framework: dominantFramework })
        .eq('id', projectId);
      if (fwError) {
        // Non-fatal: the entry-point rows landed; only the icon hint is stale.
        return { success: true, count: finalRows.length, framework: dominantFramework, frameworkWriteError: fwError.message };
      }
    }

    return { success: true, count: finalRows.length, framework: dominantFramework ?? undefined };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { success: false, error: message, count: 0 };
  }
}
