/**
 * STEP: Dependency sync (CRITICAL).
 *
 * Upserts `dependencies` (per-name), `dependency_versions` (per name@version),
 * `project_dependencies` (per project, with is_direct + source + environment),
 * and `dependency_version_edges` (transitive parent→child). Also queues a
 * populate-dependencies job for any newly-discovered direct dep (registry
 * metadata + GHSA + OpenSSF + policy eval).
 *
 * Phase 19 hybrid behavior: rows survive across re-extractions because the
 * upsert keys on (project_id, name, version, is_direct, source). UUIDs stay
 * stable, lazarus rows (previously soft-deleted then returning) get
 * removed_at cleared, and finalize_extraction marks rows absent from this run
 * as removed_at = NOW().
 */

import { runStage } from '../pipeline-stage-runner';
import type { ParsedSbomDep } from '../sbom';
import { callQueuePopulate, updateStep } from '../pipeline-helpers';
import type { PipelineContext } from '../pipeline-types';
import type { SbomOutput } from './sbom';

export async function doDepsSync(ctx: PipelineContext, sbom: SbomOutput): Promise<void> {
  const { supabase, job, projectId, organizationId, log, jobEcosystem, runId } = ctx;
  const { dependencies, relationships, bomRefMap } = sbom;

  await updateStep(supabase, projectId, 'deps_synced');
  // deps sync — no user-facing log

  await runStage({
    name: 'deps_sync',
    timeoutMs: 5 * 60_000,
    severity: 'error',
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    fn: async () => {
      const uniqueDeps = new Map<string, ParsedSbomDep>();
      for (const d of dependencies) {
        const key = `${d.name}@${d.version}`;
        if (!uniqueDeps.has(key)) uniqueDeps.set(key, d);
      }
      const uniqueNames = [...new Set(Array.from(uniqueDeps.values()).map((d) => d.name))];

      const nameToDependencyId = new Map<string, string>();
      const BATCH = 50;
      for (let i = 0; i < uniqueNames.length; i += BATCH) {
        const batch = uniqueNames.slice(i, i + BATCH);
        const { data } = await supabase.from('dependencies').select('id, name').in('name', batch);
        if (data) for (const r of data) nameToDependencyId.set(r.name, r.id);
      }
      const namesToCreate = uniqueNames.filter((n) => !nameToDependencyId.has(n));

      const nameToLicense = new Map<string, string | null>();
      for (const [, d] of uniqueDeps) {
        if (!nameToLicense.has(d.name)) nameToLicense.set(d.name, d.license);
      }

      for (let i = 0; i < namesToCreate.length; i += 100) {
        const batch = namesToCreate.slice(i, i + 100);
        const rows = batch.map((name) => ({
          name,
          license: nameToLicense.get(name) ?? null,
          ecosystem: jobEcosystem,
        }));
        const { data: inserted, error } = await supabase
          .from('dependencies')
          .insert(rows)
          .select('id, name');
        if (error) throw error;
        if (inserted) for (const r of inserted) nameToDependencyId.set(r.name, r.id);
      }

      const keyToVersionId = new Map<string, string>();
      const entries: Array<{ key: string; dependency_id: string; name: string; version: string }> = [];
      for (const [key, d] of uniqueDeps) {
        const did = nameToDependencyId.get(d.name);
        if (did) entries.push({ key, dependency_id: did, name: d.name, version: d.version });
      }

      const depIds = [...new Set(entries.map((e) => e.dependency_id))];
      const toUpsert: Array<{ dependency_id: string; version: string }> = [];
      for (const e of entries) {
        toUpsert.push({ dependency_id: e.dependency_id, version: e.version });
      }

      if (toUpsert.length > 0) {
        const { error } = await supabase
          .from('dependency_versions')
          .upsert(toUpsert, { onConflict: 'dependency_id,version', ignoreDuplicates: true });
        if (error) throw error;
      }

      const existingMap = new Map<string, string>();
      for (let offset = 0; offset < depIds.length; offset += 200) {
        const chunk = depIds.slice(offset, offset + 200);
        const { data: existingVersions } = await supabase
          .from('dependency_versions')
          .select('id, dependency_id, version')
          .in('dependency_id', chunk)
          .limit(10000);
        if (existingVersions) {
          for (const r of existingVersions) {
            existingMap.set(`${r.dependency_id}|${r.version}`, r.id);
          }
        }
      }
      for (const e of entries) {
        const id = existingMap.get(`${e.dependency_id}|${e.version}`);
        if (id) keyToVersionId.set(e.key, id);
      }

      const directNames = new Set(dependencies.filter((d) => d.is_direct).map((d) => d.name));
      ctx.newDepsToPopulate = namesToCreate
        .filter((n) => directNames.has(n))
        .map((n) => ({ dependencyId: nameToDependencyId.get(n)!, name: n }))
        .filter((d) => d.dependencyId);

      const backendBaseUrl = process.env.BACKEND_URL || process.env.API_BASE_URL || 'http://localhost:3001';
      const workerSecret = process.env.EXTRACTION_WORKER_SECRET;
      const isCliMode = process.env.DEPTEX_CLI_MODE === '1';
      // In local CLI mode there is no backend to accept the populate job — skip
      // silently. In worker mode a missing secret is a misconfiguration that
      // would silently drop dependency population, so warn.
      const skipPopulate = isCliMode || !workerSecret;
      if (ctx.newDepsToPopulate.length > 0 && !skipPopulate) {
        try {
          await callQueuePopulate(backendBaseUrl, workerSecret, projectId, organizationId, ctx.newDepsToPopulate, jobEcosystem);
        } catch (e: any) {
          await log.warn('populate', `Failed to queue dependency population: ${e.message}`);
        }
      } else if (ctx.newDepsToPopulate.length > 0 && !isCliMode && !workerSecret) {
        await log.warn('populate', 'EXTRACTION_WORKER_SECRET not set — dependency population skipped; registry metadata, GHSA and policy evaluation will not run for new direct dependencies');
      }

      // Phase 19 hybrid: upsert project_dependencies by (project_id, name, version, is_direct, source).
      // UUIDs stay stable across re-extractions; lazarus rows (previously soft-deleted then
      // returning) get removed_at cleared. dependency_notes + ai_usage_summary
      // survive naturally because FKs don't change. finalize_extraction marks rows absent
      // from this run as removed_at = NOW().
      const projectDepsRaw = dependencies.map((d) => {
        const key = `${d.name}@${d.version}`;
        return {
          project_id: projectId,
          dependency_id: nameToDependencyId.get(d.name) ?? null,
          dependency_version_id: keyToVersionId.get(key) ?? null,
          name: d.name,
          version: d.version,
          namespace: d.namespace,
          is_direct: d.is_direct,
          source: d.source,
          // `source` stays the literal SBOM origin; `environment` carries the
          // resolved scope. A transitively-dev-only dep keeps source 'transitive'
          // but `devScoped` flips environment to 'dev'. `environment` is not in
          // the upsert conflict key, so this never destabilises row identity.
          //
          // `d.lockfileDev` (npm only) is the final fallback for the NULL
          // branch: cdxgen's transitive dev propagation frequently leaves a
          // build/test-only transitive un-`devScoped`, but npm's lockfile marks
          // it `"dev": true` directly. It's consulted ONLY when the scope would
          // otherwise be null, so it never downgrades a 'prod' or already-'dev'
          // dep — it can only lift a stray null to 'dev'.
          environment:
            d.source === 'dependencies'
              ? 'prod'
              : d.source === 'devDependencies' || d.devScoped
                ? 'dev'
                : d.lockfileDev
                  ? 'dev'
                  : null,
          last_seen_extraction_run_id: runId,
          removed_at: null,
        };
      });

      const dedupeKey = (r: { name: string; version: string; is_direct: boolean; source: string }) =>
        `${r.name}|${r.version}|${r.is_direct}|${r.source}`;

      // Sticky transitive dev-scope: when cdxgen's edge graph was unwired this
      // run, Layer-2 transitive dev-only propagation was skipped, so a dep a
      // prior trusted run marked `environment='dev'` would re-derive to `null`
      // and briefly inflate its depscore. Carry the prior 'dev' forward; only
      // a trusted run (propagation ran) is allowed to downgrade dev → null.
      if (ctx.sbomGraphWired === false) {
        const { data: priorRows } = await supabase
          .from('project_dependencies')
          .select('name, version, is_direct, source, environment')
          .eq('project_id', projectId);
        if (priorRows && priorRows.length > 0) {
          const priorDev = new Set<string>();
          for (const r of priorRows) {
            if (r.environment === 'dev') priorDev.add(dedupeKey(r));
          }
          for (const row of projectDepsRaw) {
            if (row.environment === null && priorDev.has(dedupeKey(row))) {
              row.environment = 'dev';
            }
          }
        }
      }
      const seenProjDep = new Set<string>();
      const projectDepsToUpsert = projectDepsRaw.filter((r) => {
        const k = dedupeKey(r);
        if (seenProjDep.has(k)) return false;
        seenProjDep.add(k);
        return true;
      });

      for (let i = 0; i < projectDepsToUpsert.length; i += 500) {
        const chunk = projectDepsToUpsert.slice(i, i + 500);
        const { error } = await supabase
          .from('project_dependencies')
          .upsert(chunk, { onConflict: 'project_id,name,version,is_direct,source' });
        if (error) throw error;
      }
      ctx.projectDepsCount = projectDepsToUpsert.length;

      const edgesToInsert: Array<{ parent_version_id: string; child_version_id: string }> = [];
      const seenEdges = new Set<string>();
      for (const rel of relationships) {
        const parentInfo = bomRefMap.get(rel.parentBomRef);
        const childInfo = bomRefMap.get(rel.childBomRef);
        if (!parentInfo || !childInfo) continue;
        const parentKey = `${parentInfo.name}@${parentInfo.version}`;
        const childKey = `${childInfo.name}@${childInfo.version}`;
        const parentVersionId = keyToVersionId.get(parentKey);
        const childVersionId = keyToVersionId.get(childKey);
        if (parentVersionId && childVersionId) {
          const edgeKey = `${parentVersionId}|${childVersionId}`;
          if (!seenEdges.has(edgeKey)) {
            seenEdges.add(edgeKey);
            edgesToInsert.push({ parent_version_id: parentVersionId, child_version_id: childVersionId });
          }
        }
      }

      for (let i = 0; i < edgesToInsert.length; i += 500) {
        const chunk = edgesToInsert.slice(i, i + 500);
        await supabase
          .from('dependency_version_edges')
          .upsert(chunk, { onConflict: 'parent_version_id,child_version_id', ignoreDuplicates: true });
      }
      // deps sync complete (no user-facing log — internal step)
    },
  });
}
