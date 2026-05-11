import type { Storage } from '../storage';
import { Redis } from '@upstash/redis';
import type { ExtractUsageResult } from './index';

/**
 * Persist tree-sitter extractor output.
 *
 * Writes three tables:
 *   - project_usage_slices:         one row per call-site
 *   - project_dependency_functions: distinct (dep, function_name) pairs
 *   - project_dependency_files:     distinct (dep, file_path) pairs (UI)
 * And updates project_dependencies.files_importing_count.
 *
 * Dep name matching is case-insensitive because PyPI distributions are
 * canonicalized case-insensitively (Flask == flask) and npm scoped names can
 * arrive mixed-case from some SBOM generators.
 */
export async function storeUsageExtractionResults(
  supabase: Storage,
  projectId: string,
  organizationId: string,
  runId: string,
  ecosystem: string,
  result: ExtractUsageResult
): Promise<{ success: boolean; error?: string }> {
  try {
    const { data: projectDependencies, error: depsError } = await supabase
      .from('project_dependencies')
      .select('id, name')
      .eq('project_id', projectId)
      .eq('last_seen_extraction_run_id', runId);

    if (depsError) throw new Error(`Failed to fetch project dependencies: ${depsError.message}`);
    if (!projectDependencies || projectDependencies.length === 0) {
      await invalidateProjectCaches(organizationId, projectId);
      return { success: true };
    }

    const depIdByLower = new Map<string, string>();
    for (const dep of projectDependencies as Array<{ id: string; name: string }>) {
      depIdByLower.set(dep.name.toLowerCase(), dep.id);
    }
    const lookup = (depName: string): string | null =>
      depIdByLower.get(depName.toLowerCase()) ?? null;

    const filesByDep = new Map<string, Set<string>>();
    const functionsByDep = new Map<string, Set<string>>();
    const usageSliceRows: Array<Record<string, unknown>> = [];

    for (const file of result.files) {
      for (const imp of file.imports) {
        // Imports drive file-count AND give us the distinct function names
        // that the source actually binds from each dep.
        if (imp.importedName) addToMap(functionsByDep, 'pending', imp.importedName);
        // ^ deferred: we'll reassign to depName after resolving via usages below
      }
      for (const usage of file.usages) {
        if (!usage.depName) continue;
        const depId = lookup(usage.depName);
        if (!depId) continue;

        addToMap(filesByDep, depId, file.filePath);
        if (usage.resolvedMethod) addToMap(functionsByDep, depId, usage.resolvedMethod);

        usageSliceRows.push({
          project_id: projectId,
          extraction_run_id: runId,
          file_path: file.filePath,
          line_number: usage.lineNumber + 1, // DB uses 1-based lines
          containing_method: usage.containingMethod,
          target_name: usage.targetName,
          target_type: usage.targetType,
          resolved_method: usage.resolvedMethod,
          usage_label: usage.usageLabel,
          ecosystem,
        });
      }
    }

    // Drop the placeholder bucket we used while iterating imports.
    functionsByDep.delete('pending');

    // Also count files via the bulk aggregate — imports that have no usages
    // still count as an "imported" file and should bump the counter.
    for (const [depName, count] of Object.entries(result.filesImportingByDep)) {
      const depId = lookup(depName);
      if (!depId) continue;
      if (!filesByDep.has(depId)) filesByDep.set(depId, new Set());
      // Use the set cardinality from usages if it's already larger, otherwise
      // we trust the extractor's aggregate (which counts unique files with
      // an import even when no call-site was matched).
      if (filesByDep.get(depId)!.size < count) {
        // Synthesize a synthetic key so the Set size matches the aggregate
        // without us inventing fake file paths to dedupe later. Downstream
        // only reads .size.
        const set = filesByDep.get(depId)!;
        for (let i = set.size; i < count; i++) set.add(`::import-only::${depName}::${i}`);
      }
    }

    const depFunctionRows: Array<{ project_dependency_id: string; function_name: string; extraction_run_id: string }> = [];
    for (const [depId, fns] of functionsByDep) {
      for (const fn of fns) {
        depFunctionRows.push({ project_dependency_id: depId, function_name: fn, extraction_run_id: runId });
      }
    }

    const depFileRows: Array<{ project_dependency_id: string; file_path: string; extraction_run_id: string }> = [];
    for (const [depId, paths] of filesByDep) {
      for (const p of paths) {
        if (p.startsWith('::import-only::')) continue;
        depFileRows.push({ project_dependency_id: depId, file_path: p, extraction_run_id: runId });
      }
    }

    for (const [depId, set] of filesByDep) {
      // Guard against zombie writes: if this run has been superseded (withTimeout
      // fired but the inner promise keeps running), the dep's last_seen_extraction_run_id
      // has already been advanced by the newer run, and this UPDATE must no-op.
      const { error: updateError } = await supabase
        .from('project_dependencies')
        .update({ files_importing_count: set.size })
        .eq('id', depId)
        .eq('last_seen_extraction_run_id', runId);
      if (updateError) console.error(`Failed to update files_importing_count for ${depId}:`, updateError.message);
    }

    await batchUpsert(supabase, 'project_usage_slices', usageSliceRows,
      'project_id,file_path,line_number,target_name,extraction_run_id');
    await batchUpsert(supabase, 'project_dependency_functions', depFunctionRows,
      'project_dependency_id,function_name,extraction_run_id');
    await batchUpsert(supabase, 'project_dependency_files', depFileRows,
      'project_dependency_id,file_path,extraction_run_id');

    await invalidateProjectCaches(organizationId, projectId);

    return { success: true };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Failed to store usage extraction results:', message);
    return { success: false, error: message };
  }
}

function addToMap(map: Map<string, Set<string>>, key: string, value: string): void {
  if (!map.has(key)) map.set(key, new Set());
  map.get(key)!.add(value);
}

async function batchUpsert(
  supabase: Storage,
  table: string,
  rows: Array<Record<string, unknown>>,
  onConflict: string
): Promise<void> {
  if (rows.length === 0) return;
  // Postgres rejects an upsert batch where two rows share the same conflict
  // key with "ON CONFLICT DO UPDATE command cannot affect row a second time".
  // The tree-sitter extractor can legitimately emit multiple usages per
  // (project_id, file_path, line_number, target_name) — different usageLabel /
  // targetType variants at the same call site — but the table's UNIQUE index
  // doesn't include those discriminator fields. Dedupe last-write-wins to
  // match Postgres ON CONFLICT DO UPDATE semantics.
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
    const { error } = await supabase.from(table).upsert(slice, { onConflict });
    if (error) console.error(`Failed upsert batch for ${table}:`, error.message);
  }
}

async function invalidateProjectCaches(organizationId: string, projectId: string): Promise<void> {
  const url = process.env.UPSTASH_REDIS_URL;
  const token = process.env.UPSTASH_REDIS_TOKEN;
  if (!url || !token) return;
  try {
    const redis = new Redis({ url, token });
    await Promise.all([
      redis.del(`import:v1:${organizationId}:${projectId}`),
      redis.del(`deps:v1:${organizationId}:${projectId}`),
    ]);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn('[Cache] Failed to invalidate project caches after usage extraction:', message);
  }
}
