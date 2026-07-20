/**
 * Daily maintenance jobs called by the QStash cron at
 * POST /api/workers/dependency-daily-poll: npm latest-version refresh,
 * GHSA batch vuln sync, weekly download counts, webhook health checks,
 * and old webhook-delivery cleanup.
 */

import { supabase } from './supabase';

const DELAY_MS = Number(process.env.DEPENDENCY_REFRESH_DELAY_MS) || 150;
const CONCURRENCY = Math.max(1, Math.min(20, Number(process.env.DEPENDENCY_REFRESH_CONCURRENCY) || 6));
const GHSA_BATCH_SIZE = 100;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface DepRow {
  id: string;
  name: string;
  latest_version: string | null;
  latest_release_date: string | null;
}

async function getDirectDependencyIds(): Promise<Set<string>> {
  const { data } = await supabase
    .from('project_dependencies')
    .select('dependency_id')
    .eq('is_direct', true);
  return new Set((data ?? []).map((r: any) => r.dependency_id));
}

async function getAllDependencies(): Promise<DepRow[]> {
  const all: DepRow[] = [];
  let from = 0;
  const pageSize = 1000;
  while (true) {
    const { data } = await supabase
      .from('dependencies')
      .select('id, name, latest_version, latest_release_date')
      .range(from, from + pageSize - 1);
    if (!data || data.length === 0) break;
    all.push(...(data as DepRow[]));
    if (data.length < pageSize) break;
    from += pageSize;
  }
  return all;
}

async function fetchLatestNpmVersion(name: string): Promise<{ latestVersion: string | null; publishedAt: string | null }> {
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
      headers: { Accept: 'application/json', 'User-Agent': 'Deptex-Poller' },
    });
    if (!res.ok) return { latestVersion: null, publishedAt: null };
    const data = (await res.json()) as any;
    const latest = data?.['dist-tags']?.latest;
    if (!latest) return { latestVersion: null, publishedAt: null };
    const publishedAt = data?.time?.[latest] ?? null;
    return { latestVersion: latest, publishedAt };
  } catch {
    return { latestVersion: null, publishedAt: null };
  }
}

const DOWNLOAD_DELAY_MS = Number(process.env.DOWNLOAD_REFRESH_DELAY_MS) || 2000;

async function fetchNpmWeeklyDownloads(name: string): Promise<number | null> {
  try {
    // npm downloads API expects scoped packages with slash (not encoded)
    const url = `https://api.npmjs.org/downloads/point/last-week/${name}`;
    const res = await fetch(url, {
      headers: { 'User-Agent': 'Deptex-Poller' },
    });
    if (!res.ok) return null;
    const data = (await res.json()) as any;
    return typeof data?.downloads === 'number' ? data.downloads : null;
  } catch {
    return null;
  }
}

async function refreshDownloadCounts(byName: Map<string, { ids: string[]; directIds: string[] }>): Promise<{ updated: number; errors: number }> {
  // Only fetch downloads for direct dependencies (user-facing)
  const directNames = Array.from(byName.entries())
    .filter(([, g]) => g.directIds.length > 0)
    .map(([name]) => name);

  console.log(`[dependency-poll] Refreshing download counts for ${directNames.length} direct dependencies (${DOWNLOAD_DELAY_MS}ms delay)...`);

  let updated = 0;
  let errors = 0;

  for (const name of directNames) {
    await delay(DOWNLOAD_DELAY_MS);
    try {
      const downloads = await fetchNpmWeeklyDownloads(name);
      if (downloads != null) {
        await supabase
          .from('dependencies')
          .update({
            weekly_downloads: downloads,
            updated_at: new Date().toISOString(),
          })
          .eq('name', name);
        updated++;
      }
    } catch {
      errors++;
    }
  }

  console.log(`[dependency-poll] Download refresh complete. Updated: ${updated}, Errors: ${errors}`);
  return { updated, errors };
}

export async function runDependencyRefresh(): Promise<{ processed: number; errors: number; vulnsUpdated: number }> {
  console.log('[dependency-poll] Dependency refresh starting...');

  const [directIds, allRows] = await Promise.all([
    getDirectDependencyIds(),
    getAllDependencies(),
  ]);

  interface NameGroup {
    ids: string[];
    directIds: string[];
    latest_version: string | null;
  }

  const byName = new Map<string, NameGroup>();
  for (const row of allRows) {
    if (!byName.has(row.name)) {
      byName.set(row.name, { ids: [], directIds: [], latest_version: row.latest_version });
    }
    const g = byName.get(row.name)!;
    g.ids.push(row.id);
    if (directIds.has(row.id)) g.directIds.push(row.id);
  }

  console.log(`[dependency-poll] ${allRows.length} deps (${byName.size} unique), ${directIds.size} direct`);

  let processed = 0;
  let errors = 0;

  const entries = Array.from(byName.entries());

  for (let i = 0; i < entries.length; i += CONCURRENCY) {
    const batch = entries.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(async ([name, group]) => {
      await delay(DELAY_MS);
      try {
        if (group.directIds.length > 0) {
          const npm = await fetchLatestNpmVersion(name);
          if (npm.latestVersion && group.latest_version !== npm.latestVersion) {
            await supabase
              .from('dependencies')
              .update({
                latest_version: npm.latestVersion,
                latest_release_date: npm.publishedAt,
                updated_at: new Date().toISOString(),
              })
              .eq('name', name);
            console.log(`[dependency-poll] ${name}: ${group.latest_version ?? 'none'} → ${npm.latestVersion}`);
          }
        }
        return { count: group.ids.length };
      } catch (err: any) {
        console.error(`[dependency-poll] Error refreshing ${name}:`, err?.message);
        return { count: 0, error: true };
      }
    }));
    for (const r of results) {
      processed += r.count;
      if ((r as any).error) errors++;
    }
  }

  let vulnsUpdated = 0;
  try {
    const { fetchGhsaVulnerabilitiesBatch, ghsaVulnToRow } = await import('./ghsa');
    const allNames = Array.from(byName.keys());
    for (let i = 0; i < allNames.length; i += GHSA_BATCH_SIZE) {
      const chunk = allNames.slice(i, i + GHSA_BATCH_SIZE);
      await delay(DELAY_MS);
      const vulnMap = await fetchGhsaVulnerabilitiesBatch(chunk);
      for (const [name, vulns] of vulnMap.entries()) {
        const group = byName.get(name);
        if (!group) continue;
        for (const v of vulns) {
          for (const depId of group.ids) {
            const row = ghsaVulnToRow(depId, v) as Record<string, unknown>;
            const { error } = await supabase
              .from('dependency_vulnerabilities')
              .upsert({
                ...row,
                modified_at: new Date().toISOString(),
              }, { onConflict: 'dependency_id,osv_id' });
            if (!error) vulnsUpdated++;
          }
        }
      }
    }
  } catch (err: any) {
    console.error('[dependency-poll] GHSA sync error:', err?.message);
  }

  // Refresh weekly download counts (sequential, slow — runs after version + vuln refresh)
  const downloads = await refreshDownloadCounts(byName);

  console.log(`[dependency-poll] Refresh complete. Processed: ${processed}, Errors: ${errors}, Vulns: ${vulnsUpdated}, Downloads updated: ${downloads.updated}`);
  return { processed, errors, vulnsUpdated };
}

export async function runWebhookHealthCheck(): Promise<{ markedInactive: number }> {
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

  const { data, error } = await supabase
    .from('project_repositories')
    .update({ webhook_status: 'inactive', updated_at: new Date().toISOString() })
    .eq('webhook_status', 'active')
    .lt('last_webhook_at', sevenDaysAgo)
    .select('id');

  const count = data?.length ?? 0;
  if (count > 0) {
    console.log(`[dependency-poll] Marked ${count} repos as webhook-inactive (no events in 7 days)`);
  }
  return { markedInactive: count };
}

export async function cleanupOldWebhookDeliveries(): Promise<{ deleted: number }> {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

  const { data, error } = await supabase
    .from('webhook_deliveries')
    .delete()
    .lt('created_at', thirtyDaysAgo)
    .select('id');

  const count = data?.length ?? 0;
  if (count > 0) {
    console.log(`[dependency-poll] Cleaned up ${count} webhook deliveries older than 30 days`);
  }
  return { deleted: count };
}
