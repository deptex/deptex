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
): Promise<{ success: boolean; error?: string; count: number }> {
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

    const BATCH = 200;
    for (let i = 0; i < rows.length; i += BATCH) {
      const slice = rows.slice(i, i + BATCH);
      const { error } = await supabase
        .from('project_entry_points')
        .upsert(slice, {
          onConflict: 'project_id,extraction_run_id,file_path,line_number,framework,handler_name',
        });
      if (error) {
        return { success: false, error: error.message, count: 0 };
      }
    }
    return { success: true, count: rows.length };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { success: false, error: message, count: 0 };
  }
}
