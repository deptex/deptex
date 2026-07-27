import * as fs from 'fs';
import * as path from 'path';
import type { Storage } from '../storage';
import type { ExtractedFile } from '../tree-sitter-extractor/languages/types';
import { canonicalizeParams } from '../param-harvest/types';

/**
 * Read a small window of source around `line`, formatted to match the
 * reachability-flow code snippets (`→ NN │ code` markers — the UI strips them
 * and re-numbers from the affected line). Captured here, at extraction time,
 * because the DAST worker has no repo on disk: the DAST cross-link copies this
 * onto the finding so it can render the receiving handler code. Best-effort —
 * returns null on any miss so a read failure never fails extraction. `cache`
 * memoizes each file's line array so co-located handlers read it once.
 */
function readHandlerSnippet(
  workspaceRoot: string | undefined,
  filePath: string,
  line: number,
  cache: Map<string, string[] | null>,
  // Asymmetric window: a couple of lines of lead-in for context, then a
  // generous tail so the whole handler body is visible (DAST shows this as the
  // "Endpoint code"). The UI scrolls anything longer; the `→ NNNN │` markers
  // carry the real line numbers, so the gutter stays correct at any window size.
  beforeLines = 2,
  afterLines = 16,
): string | null {
  if (!filePath || !line || !Number.isFinite(line) || line <= 0) return null;
  let lines = cache.get(filePath);
  if (lines === undefined) {
    lines = null;
    // Entry-point file_path may be absolute (the clone's tmp path) or relative
    // to the workspace root — handle both.
    const candidates = path.isAbsolute(filePath)
      ? [filePath]
      : workspaceRoot
        ? [path.join(workspaceRoot, filePath)]
        : [];
    for (const c of candidates) {
      try {
        if (fs.existsSync(c) && fs.statSync(c).isFile()) {
          lines = fs.readFileSync(c, 'utf8').split(/\r?\n/);
          break;
        }
      } catch {
        /* try the next candidate */
      }
    }
    cache.set(filePath, lines);
  }
  if (!lines) return null;
  const start = Math.max(0, line - beforeLines - 1);
  const end = Math.min(lines.length, line + afterLines);
  if (start >= end) return null;
  return lines
    .slice(start, end)
    .map((l, i) => {
      const num = start + i + 1;
      const marker = num === line ? '→' : ' ';
      return `${marker} ${num.toString().padStart(4)} │ ${l}`;
    })
    .join('\n');
}

/**
 * Store entry-point file paths relative to the project base (e.g.
 * `routes/api.js`), NOT the clone's tmp path — so a DAST finding's handler
 * location reads the same as the SCA reachability flows (which already store
 * project-relative paths). Without this the entry point keeps the absolute
 * `/tmp/deptex-extract-XXXX/<subpath>/routes/api.js`, which also breaks the
 * cross-link's `flow.entry_point_file === ep.file_path` match.
 */
export function toProjectRelative(workspaceRoot: string | undefined, filePath: string): string {
  if (!filePath) return filePath;
  if (workspaceRoot && path.isAbsolute(filePath)) {
    const rel = path.relative(workspaceRoot, filePath);
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
      return rel.split(path.sep).join('/');
    }
  }
  return filePath.split(path.sep).join('/');
}

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
  files: readonly ExtractedFile[],
  workspaceRoot?: string
): Promise<{ success: boolean; error?: string; count: number; framework?: string; frameworkWriteError?: string }> {
  try {
    const rows: Array<Record<string, unknown>> = [];
    const snippetCache = new Map<string, string[] | null>();
    for (const file of files) {
      for (const ep of file.entryPoints ?? []) {
        rows.push({
          project_id: projectId,
          extraction_run_id: runId,
          // Stored project-relative (routes/api.js), not the clone's tmp path.
          file_path: toProjectRelative(workspaceRoot, ep.filePath),
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
          // Canonicalized again at the write boundary (defense in depth — the
          // detectors already canonicalize, but determinism is load-bearing
          // for the snapshot suite).
          request_params: canonicalizeParams(ep.requestParams ?? null),
          // The handler's source window, captured here because the DAST worker
          // has no repo — the cross-link copies it onto the finding so the UI
          // can render the receiving code (NOT part of the CLI entry_points.json
          // output, so the snapshot suite is unaffected).
          code_snippet: readHandlerSnippet(workspaceRoot, ep.filePath, ep.lineNumber, snippetCache),
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
