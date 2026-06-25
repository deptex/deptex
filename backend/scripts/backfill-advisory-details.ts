/**
 * Backfill advisory descriptions from OSV.
 *
 * The vulnerability detail card sources its description only from the global
 * `dependency_vulnerabilities.details` column, populated from GHSA at populate
 * time. CVEs that dep-scan / OSV surface but GHSA's per-package query doesn't
 * return an advisory for end up with a per-project finding row but no cached
 * advisory, so the card shows a blank description. This script finds every finding
 * CVE with no cached advisory (by osv_id OR alias), fetches its `details` from
 * OSV.dev, and upserts a `dependency_vulnerabilities` row so the description
 * resolves. The matching ingestion fix (workers.ts populate, step 5c) keeps the
 * cache filled going forward; this is the one-time catch-up for already-scanned
 * findings.
 *
 * Usage (from backend/):
 *   npm run backfill:advisory-details              # dry run — report only
 *   npm run backfill:advisory-details -- --apply   # actually upsert
 */
import 'dotenv/config';
import { supabase } from '../src/lib/supabase';
import { fetchOsvVuln, osvVulnToAdvisoryRow } from '../src/lib/osv-advisory';

const APPLY = process.argv.includes('--apply');
const PAGE = 1000;

/** Every id the advisory cache already resolves — each row's osv_id plus its
 *  aliases (the detail RPC matches on both). */
async function fetchAllCoveredIds(): Promise<Set<string>> {
  const covered = new Set<string>();
  for (let from = 0; ; from += PAGE) {
    const { data, error } = await supabase
      .from('dependency_vulnerabilities')
      .select('osv_id, aliases')
      .range(from, from + PAGE - 1);
    if (error) throw error;
    if (!data || data.length === 0) break;
    for (const r of data as any[]) {
      if (r.osv_id) covered.add(r.osv_id);
      for (const a of r.aliases ?? []) covered.add(a);
    }
    if (data.length < PAGE) break;
  }
  return covered;
}

/** Distinct CVE/GHSA ids that appear in findings, each mapped to one
 *  representative dependency_id (any affected package — the detail RPC matches
 *  advisories by osv_id/alias, never by dependency_id). */
async function fetchFindingCves(): Promise<Map<string, string>> {
  const byOsv = new Map<string, string>();
  for (let from = 0; ; from += PAGE) {
    const { data, error } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('osv_id, project_dependencies!inner(dependency_id)')
      .range(from, from + PAGE - 1);
    if (error) throw error;
    if (!data || data.length === 0) break;
    for (const r of data as any[]) {
      const osv = r.osv_id as string | null;
      const depId = r.project_dependencies?.dependency_id as string | null;
      if (!osv || !depId) continue;
      if (!/^(CVE|GHSA)-/i.test(osv)) continue;
      if (!byOsv.has(osv)) byOsv.set(osv, depId);
    }
    if (data.length < PAGE) break;
  }
  return byOsv;
}

/** Run `fn` over `items` with bounded concurrency, preserving order. */
async function mapPool<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, async () => {
      while (next < items.length) {
        const idx = next++;
        out[idx] = await fn(items[idx]);
      }
    }),
  );
  return out;
}

async function main() {
  console.log(`[backfill] mode: ${APPLY ? 'APPLY' : 'DRY RUN'}`);

  const covered = await fetchAllCoveredIds();
  console.log(`[backfill] advisory cache resolves ${covered.size} ids (osv_id + aliases)`);

  const findings = await fetchFindingCves();
  console.log(`[backfill] ${findings.size} distinct CVE/GHSA ids across findings`);

  const missing = [...findings.entries()].filter(([osv]) => !covered.has(osv));
  console.log(`[backfill] ${missing.length} finding CVEs have no cached advisory — resolving from OSV...`);

  let resolved = 0, noOsv = 0, noDetails = 0;
  const rows = (
    await mapPool(missing, 6, async ([osv, depId]) => {
      const rec = await fetchOsvVuln(osv);
      if (!rec) { noOsv++; return null; }
      if (!rec.details) { noDetails++; return null; }
      resolved++;
      return osvVulnToAdvisoryRow(depId, rec, osv);
    })
  ).filter(Boolean) as Record<string, unknown>[];

  console.log(
    `[backfill] resolved ${resolved} with details | ${noDetails} in-OSV-but-no-details | ${noOsv} not in OSV`,
  );
  for (const r of rows.slice(0, 6)) {
    console.log(`  · ${r.osv_id}  aliases=${JSON.stringify(r.aliases)}  details=${String((r.details as string)?.length)} chars`);
  }

  if (!APPLY) {
    console.log(`[backfill] DRY RUN — would upsert ${rows.length} advisory rows. Re-run with --apply to write.`);
    return;
  }

  let written = 0;
  for (let i = 0; i < rows.length; i += 200) {
    const batch = rows.slice(i, i + 200);
    const { error } = await supabase
      .from('dependency_vulnerabilities')
      .upsert(batch, { onConflict: 'dependency_id,osv_id' });
    if (error) throw error;
    written += batch.length;
  }
  console.log(`[backfill] APPLIED — upserted ${written} advisory rows.`);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
