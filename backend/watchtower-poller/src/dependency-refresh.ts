/**
 * Job 1: Dependency refresh – update latest release and vulnerabilities for all dependencies.
 * - npm latest: only for DIRECT dependencies; one fetch per package name (stable-only).
 * - new_version job: when version string actually changed.
 * - Vulnerabilities: GHSA only (GitHub Advisory Database), batched (up to 100 names per request). No OSV.
 */

const DELAY_MS = Number(process.env.DEPENDENCY_REFRESH_DELAY_MS) || 150;
const CONCURRENCY = Math.max(1, Math.min(20, Number(process.env.DEPENDENCY_REFRESH_CONCURRENCY) || 6));
const GHSA_BATCH_SIZE = 100;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

import { fetchLatestNpmVersion } from './osv-checker';
import {
  getDirectDependencyIds,
  getAllDependencies,
  updateDependenciesLatestByName,
  upsertDependencyVulnerabilities,
  ensureDependencyVersion,
  hasQuarantineExpiredForDependency,
} from './storage';
import { enqueueNewVersionJob } from './scheduler';
import { fetchGhsaVulnerabilitiesBatch, ghsaVulnToInsert } from './ghsa';

interface NameGroup {
  ids: string[];
  directIds: string[];
  latest_version: string | null;
  latest_release_date: string | null;
}

/**
 * Run the full dependency refresh:
 * - npm latest version: only for DIRECT dependencies; one fetch per package name (stable release only).
 * - new_version job: only when the version string actually changed (not just release date), one job per name.
 * - Vulnerabilities: GHSA only, batched (up to 100 names per GraphQL request); upsert for all dependency rows.
 */
export async function runDependencyRefresh(): Promise<{ processed: number; errors: number }> {
  const startTime = new Date().toISOString();
  console.log(`[${startTime}] ========================================`);
  console.log(`[${startTime}] 🔄 Job 1: Dependency refresh starting...`);
  console.log(`[${startTime}] ========================================`);

  const [directIds, allRows] = await Promise.all([
    getDirectDependencyIds(),
    getAllDependencies(),
  ]);

  // Group by package name so we process each name once (one npm per direct name, one new_version when changed, vulns batched later)
  const byName = new Map<string, NameGroup>();
  for (const row of allRows) {
    const name = row.name;
    const id = row.id;
    const latest_version = row.latest_version ?? null;
    const latest_release_date = row.latest_release_date ?? null;
    if (!byName.has(name)) {
      byName.set(name, {
        ids: [],
        directIds: [],
        latest_version,
        latest_release_date,
      });
    }
    const g = byName.get(name)!;
    g.ids.push(id);
    if (directIds.has(id)) g.directIds.push(id);
  }

  const uniqueNames = byName.size;
  const totalRows = allRows.length;
  console.log(`[${new Date().toISOString()}] 📦 Found ${totalRows} dependency rows (${uniqueNames} unique names); ${directIds.size} direct (concurrency: ${CONCURRENCY}, delay: ${DELAY_MS}ms)`);

  const entries = Array.from(byName.entries());
  const directNameCount = entries.filter(([, g]) => g.directIds.length > 0).length;
  console.log(`[${new Date().toISOString()}] 📡 npm: checking latest version for ${directNameCount} direct package name(s) (📌 only when a new version is found)`);
  let processed = 0;
  let errors = 0;

  async function processOneName(name: string, group: NameGroup): Promise<{ processed: number; error?: string }> {
    await delay(DELAY_MS);
    try {
      // 1) npm latest version: only for names that have at least one direct dependency
      if (group.directIds.length > 0) {
        const npmInfo = await fetchLatestNpmVersion(name);

        if (npmInfo.latestVersion) {
          const currentLatest = group.latest_version ?? null;
          const currentDate = group.latest_release_date ?? null;
          const newDate = npmInfo.publishedAt
            ? (typeof npmInfo.publishedAt === 'string'
                ? npmInfo.publishedAt
                : new Date(npmInfo.publishedAt).toISOString())
            : null;

          const versionChanged = currentLatest !== npmInfo.latestVersion;
          const dateChanged = Boolean(newDate && currentDate !== newDate);
          const shouldUpdateDb = versionChanged || dateChanged;

          if (shouldUpdateDb) {
            await updateDependenciesLatestByName(name, npmInfo.latestVersion, newDate);
          }

          if (versionChanged) {
            console.log(`[${new Date().toISOString()}] 📌 ${name}: latest_version ${currentLatest ?? 'none'} → ${npmInfo.latestVersion} (enqueueing new_version job)`);
            for (const dependencyId of group.directIds) {
              await ensureDependencyVersion(dependencyId, npmInfo.latestVersion);
            }
            await enqueueNewVersionJob({
              type: 'new_version',
              dependency_id: group.directIds[0],
              name,
              new_version: npmInfo.latestVersion,
              latest_release_date: newDate,
            });
          }
        }

        for (const dependencyId of group.directIds) {
          if (await hasQuarantineExpiredForDependency(dependencyId)) {
            await enqueueNewVersionJob({ type: 'quarantine_expired', dependency_id: dependencyId, name });
          }
        }
      }

      // Vulnerabilities: done in Phase 2 (GHSA batched), not per-name here
      return { processed: group.ids.length };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[${new Date().toISOString()}] ❌ Dependency refresh failed for ${name}: ${msg}`);
      return { processed: 0, error: msg };
    }
  }

  // Phase 1: npm latest + new_version jobs (per name, concurrency)
  for (let i = 0; i < entries.length; i += CONCURRENCY) {
    const batch = entries.slice(i, i + CONCURRENCY);
    const results = await Promise.all(
      batch.map(([name, group]) => processOneName(name, group))
    );
    for (const r of results) {
      processed += r.processed;
      if (r.error) errors++;
    }
  }

  // Phase 2: Vulnerability sync – GHSA only, batched (up to 100 names per request).
  // Upsert inserts new advisories and updates existing rows (e.g. when firstPatchedVersion is set), so both new vulnerabilities and patched-version updates are synced.
  const allNames = Array.from(byName.keys());
  for (let i = 0; i < allNames.length; i += GHSA_BATCH_SIZE) {
    const chunk = allNames.slice(i, i + GHSA_BATCH_SIZE);
    await delay(DELAY_MS);
    const vulnMap = await fetchGhsaVulnerabilitiesBatch(chunk);
    const allInserts: Parameters<typeof upsertDependencyVulnerabilities>[0] = [];
    for (const name of chunk) {
      const group = byName.get(name)!;
      const vulns = vulnMap.get(name) ?? [];
      for (const dependencyId of group.ids) {
        for (const v of vulns) {
          allInserts.push(ghsaVulnToInsert(dependencyId, v));
        }
      }
    }
    if (allInserts.length > 0) {
      await upsertDependencyVulnerabilities(allInserts);
      const vulnCount = new Set(allInserts.map((x) => x.osv_id)).size;
      console.log(`[${new Date().toISOString()}] 🔐 GHSA: synced ${vulnCount} advisory entries for ${chunk.length} package(s)`);
    }
  }

  console.log(`[${new Date().toISOString()}] ========================================`);
  console.log(`[${new Date().toISOString()}] ✅ Job 1: Dependency refresh complete. Processed: ${processed} rows (${uniqueNames} names), Errors: ${errors}`);
  console.log(`[${new Date().toISOString()}] ========================================`);

  return { processed, errors };
}
