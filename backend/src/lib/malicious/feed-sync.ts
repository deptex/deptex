/**
 * Malicious-package feed sync.
 *
 * Pulls advisories from upstream sources (OSV.dev and GHSA `MALWARE`-class)
 * and upserts them into `known_malicious_packages`. Each run records its
 * state in `malicious_feed_sync_runs` so the staleness watchdog (M2.1)
 * has independent visibility into whether the feed is fresh.
 *
 * v1 design: synchronous single-shot per source, called by QStash daily
 * cron via the internal route. M2.1 promotes to a checkpointed
 * workflow if the per-run wall time pushes past QStash's invocation
 * budget.
 *
 * Multi-tenant invariant: cache is global. Ecosystem names are
 * canonicalized at write time so the `known_malicious_packages.ecosystem`
 * CHECK enum holds across heterogeneous source casings (OSV `PyPI`, GHSA
 * `RUBYGEMS`, GuardDog `github-action`).
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import StreamZip from 'node-stream-zip';
import { supabase } from '../supabase';
import { canonicalizeEcosystem, type CanonicalEcosystem } from './ecosystem';
import type { MaliciousFeedSource, MaliciousFeedSyncState, MaliciousSeverity } from './types';
import { getGitHubToken } from '../ghsa';
import { resolveVulnerableRange, makePackumentCache, type PackumentCache } from './version-range';

export interface FeedSyncResult {
  source: MaliciousFeedSource;
  state: MaliciousFeedSyncState;
  entries_added: number;
  entries_withdrawn: number;
  error_message?: string;
  run_id: string;
}

interface UpsertEntry {
  package_name: string;
  version: string | null;
  ecosystem: string;
  source: MaliciousFeedSource;
  source_id: string;
  severity: MaliciousSeverity | null;
  description: string | null;
  withdrawn: boolean;
}

const OSV_ECOSYSTEMS: Array<{ raw: string; canonical: string }> = [
  { raw: 'npm', canonical: 'npm' },
  { raw: 'PyPI', canonical: 'pypi' },
  { raw: 'Maven', canonical: 'maven' },
  { raw: 'Go', canonical: 'golang' },
  { raw: 'RubyGems', canonical: 'rubygems' },
  { raw: 'GitHub Actions', canonical: 'github-actions' },
];

export async function runMaliciousFeedSync(source: MaliciousFeedSource): Promise<FeedSyncResult> {
  const { data: runRow, error: runError } = await supabase
    .from('malicious_feed_sync_runs')
    .insert({ source, state: 'running' })
    .select('id')
    .single();

  if (runError || !runRow) {
    throw new Error(`feed-sync: failed to start run row: ${runError?.message ?? 'no row'}`);
  }
  const runId = runRow.id;

  try {
    const result = source === 'osv'
      ? await syncOsv()
      : await syncGhsa();

    await supabase
      .from('malicious_feed_sync_runs')
      .update({
        state: 'completed',
        completed_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        entries_added: result.entries_added,
        entries_withdrawn: result.entries_withdrawn,
      })
      .eq('id', runId);

    return {
      source,
      state: 'completed',
      entries_added: result.entries_added,
      entries_withdrawn: result.entries_withdrawn,
      run_id: runId,
    };
  } catch (err: any) {
    await supabase
      .from('malicious_feed_sync_runs')
      .update({
        state: 'failed',
        completed_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        error_message: err?.message ?? String(err),
      })
      .eq('id', runId);

    return {
      source,
      state: 'failed',
      entries_added: 0,
      entries_withdrawn: 0,
      error_message: err?.message ?? String(err),
      run_id: runId,
    };
  }
}

// ───────────────────────────── OSV ─────────────────────────────────────────

async function syncOsv(): Promise<{ entries_added: number; entries_withdrawn: number }> {
  let added = 0;
  let withdrawn = 0;
  // OSV entries usually carry an explicit `versions` array, so the version-range
  // resolver is rarely needed — but pass a cache anyway so the code path is uniform
  // with GHSA. Cache is per-OSV-run, distinct from GHSA's.
  const cache = makePackumentCache();
  for (const eco of OSV_ECOSYSTEMS) {
    const entries = await fetchOsvMaliciousForEcosystem(eco.raw, eco.canonical, cache);
    const summary = await upsertEntries(entries);
    added += summary.added;
    withdrawn += summary.withdrawn;
  }
  return { entries_added: added, entries_withdrawn: withdrawn };
}

async function fetchOsvMaliciousForEcosystem(
  ecoRaw: string,
  canonical: string,
  cache: PackumentCache,
): Promise<UpsertEntry[]> {
  // OSV publishes per-ecosystem bulk archives at
  //   https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip
  // each entry is a single advisory JSON. We only care about MAL-* IDs
  // (OSSF's malicious dataset publishes those into OSV.dev), so we filter
  // by entry name to skip parsing the bulk of CVE-* entries.
  const zipUrl = `https://osv-vulnerabilities.storage.googleapis.com/${encodeURIComponent(ecoRaw)}/all.zip`;
  const res = await fetch(zipUrl);
  if (!res.ok) {
    if (res.status === 404) return [];
    throw new Error(`OSV ${ecoRaw} zip fetch failed: ${res.status} ${res.statusText}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());

  // node-stream-zip can't read from a buffer directly — write to a temp
  // file in /tmp, parse, and unlink.
  const tmpFile = path.join(
    os.tmpdir(),
    `osv-${ecoRaw}-${crypto.randomBytes(6).toString('hex')}.zip`,
  );
  fs.writeFileSync(tmpFile, buf);

  const entries: UpsertEntry[] = [];
  const zip = new StreamZip.async({ file: tmpFile });
  try {
    const zipEntries = await zip.entries();
    let processed = 0;
    for (const name of Object.keys(zipEntries)) {
      // Each entry is named like "MAL-2024-1234.json" or "GHSA-xxxx.json" or
      // "CVE-...json". We only want MAL-*. The npm dataset alone has ~212k
      // MAL-* entries (most are historical OpenSSF batch submissions).
      // Cap is high but finite to bound worst-case memory if upstream balloons.
      if (!name.startsWith('MAL-') || !name.endsWith('.json')) continue;
      if (processed >= 500_000) break;
      processed += 1;
      try {
        const data = await zip.entryData(name);
        const advisory = JSON.parse(data.toString('utf8'));
        for (const e of await advisoryToEntries(advisory, 'osv', canonical, cache)) {
          entries.push(e);
        }
      } catch {
        // Skip malformed individual entries — one bad file shouldn't kill
        // the whole sync run.
      }
    }
  } finally {
    await zip.close();
    try { fs.unlinkSync(tmpFile); } catch { /* best-effort */ }
  }
  return entries;
}

// ───────────────────────────── GHSA ────────────────────────────────────────

// Map canonical ecosystem → GHSA `SecurityAdvisoryEcosystem` enum. v1 ran
// a single un-filtered query and topped out at 5000 advisories total
// (50 pages × 100/page). M2.1 fans out: one paginated query per ecosystem,
// raising the effective cap to 5000 PER ecosystem (~35k aggregate). Skips
// canonical ecosystems with no GHSA representation (vscode).
const GHSA_ECOSYSTEMS: Array<{ canonical: CanonicalEcosystem; ghsa: string }> = [
  { canonical: 'npm', ghsa: 'NPM' },
  { canonical: 'pypi', ghsa: 'PIP' },
  { canonical: 'maven', ghsa: 'MAVEN' },
  { canonical: 'golang', ghsa: 'GO' },
  { canonical: 'rubygems', ghsa: 'RUBYGEMS' },
  { canonical: 'composer', ghsa: 'COMPOSER' },
  { canonical: 'cargo', ghsa: 'RUST' },
  { canonical: 'nuget', ghsa: 'NUGET' },
  { canonical: 'github-actions', ghsa: 'ACTIONS' },
];

const GHSA_MAX_PAGES_PER_ECO = 50; // 50 × 100/page = 5k entries / ecosystem

async function syncGhsa(): Promise<{ entries_added: number; entries_withdrawn: number }> {
  const token = getGitHubToken();
  if (!token) {
    // Without a token we hit unauthenticated rate limits almost immediately
    // on the GraphQL endpoint. We THROW so the run row records state='failed'
    // — silently completing with 0 entries would tell the staleness watchdog
    // everything is fine, when in fact GHSA is fully unsynced.
    console.warn('[malicious feed-sync] GHSA: no GITHUB_TOKEN — failing run so the watchdog alerts');
    throw new Error('GHSA sync skipped: GITHUB_TOKEN not configured');
  }

  let added = 0;
  let withdrawn = 0;

  // Per-run version-list cache so the 12th typosquat advisory targeting
  // `lodash` doesn't trigger a 12th packument fetch. Cache spans all
  // ecosystems — the cache is keyed (ecosystem, name) internally.
  const cache = makePackumentCache();

  for (const eco of GHSA_ECOSYSTEMS) {
    let cursor: string | null = null;
    let pages = 0;

    while (pages < GHSA_MAX_PAGES_PER_ECO) {
      const page = await fetchGhsaMalwarePage(cursor, token, eco.ghsa);
      if (!page || page.advisories.length === 0) break;

      const entries: UpsertEntry[] = [];
      for (const adv of page.advisories) {
        for (const e of await advisoryToEntries(adv, 'ghsa', eco.canonical, cache)) {
          entries.push(e);
        }
      }

      const summary = await upsertEntries(entries);
      added += summary.added;
      withdrawn += summary.withdrawn;

      if (!page.hasNextPage) break;
      cursor = page.endCursor;
      pages++;
    }
  }

  return { entries_added: added, entries_withdrawn: withdrawn };
}

async function fetchGhsaMalwarePage(
  cursor: string | null,
  token: string,
  ghsaEcosystem: string,
  attempt = 0,
): Promise<{ advisories: any[]; hasNextPage: boolean; endCursor: string | null } | null> {
  const after = cursor ? `, after: ${JSON.stringify(cursor)}` : '';
  // The advisory-level `ecosystem` filter is the M2.1 fan-out hinge: each
  // call returns up to 5k MALWARE advisories scoped to one ecosystem,
  // letting us page-walk per-eco without competing for the global 50-page
  // cap. orderBy stays PUBLISHED_AT DESC so we always page through newest
  // first — if we hit the cap, we miss old advisories rather than recent.
  const query = `query {
    securityAdvisories(first: 100${after}, classifications: [MALWARE], ecosystem: ${ghsaEcosystem}, orderBy: { field: PUBLISHED_AT, direction: DESC }) {
      pageInfo { hasNextPage endCursor }
      nodes {
        ghsaId
        summary
        description
        severity
        withdrawnAt
        vulnerabilities(first: 100) {
          nodes {
            package { ecosystem name }
            vulnerableVersionRange
          }
        }
      }
    }
  }`;

  const res = await fetch('https://api.github.com/graphql', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'Deptex-App',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ query }),
  });

  // Authenticated GraphQL is 5000 points/h. We can blow it if the cron run
  // collides with concurrent automation; back off + retry with the cursor
  // intact. 403 is also used for secondary-rate-limit (abuse detection).
  if ((res.status === 429 || res.status === 403) && attempt < 3) {
    const retryAfterRaw = res.headers.get('retry-after');
    const retryAfterMs = retryAfterRaw ? Math.max(1000, parseInt(retryAfterRaw, 10) * 1000) : 30_000 * (attempt + 1);
    await new Promise((resolve) => setTimeout(resolve, retryAfterMs));
    return fetchGhsaMalwarePage(cursor, token, ghsaEcosystem, attempt + 1);
  }
  if (!res.ok) {
    throw new Error(`GHSA GraphQL ${res.status}: ${await res.text()}`);
  }
  const json = (await res.json()) as any;
  if (json.errors) {
    throw new Error(`GHSA GraphQL errors (eco=${ghsaEcosystem}): ${JSON.stringify(json.errors)}`);
  }
  const sa = json.data?.securityAdvisories;
  if (!sa) return null;
  return {
    advisories: sa.nodes ?? [],
    hasNextPage: Boolean(sa.pageInfo?.hasNextPage),
    endCursor: sa.pageInfo?.endCursor ?? null,
  };
}

// ───────────────────────────── shared ──────────────────────────────────────

async function advisoryToEntries(
  advisory: any,
  source: MaliciousFeedSource,
  canonical: string,
  cache: PackumentCache,
): Promise<UpsertEntry[]> {
  const sourceId: string = advisory.id ?? advisory.ghsaId ?? '';
  if (!sourceId) return [];
  const description: string | null = advisory.summary ?? advisory.description ?? null;
  const severity = parseSeverity(advisory.severity);
  const withdrawn = Boolean(advisory.withdrawnAt ?? advisory.withdrawn);

  const affected = advisory.affected ?? advisory.vulnerabilities?.nodes ?? advisory.vulnerabilities ?? [];
  const list = Array.isArray(affected) ? affected : [];

  const entries: UpsertEntry[] = [];
  for (const a of list) {
    const ecoRaw = a?.package?.ecosystem ?? a?.ecosystem;
    const eco = canonicalizeEcosystem(ecoRaw ?? null) ?? canonical;
    const name = a?.package?.name ?? a?.name;
    if (!name) continue;

    // 1. Explicit version list (OSV publishes these for most MAL-* entries).
    let versions: Array<string | null> | null = pickVersions(a);

    // 2. GHSA's `vulnerableVersionRange` — expand to concrete versions via
    //    per-ecosystem registry lookup. Falls through to `[null]` (= "all
    //    versions") when the resolver can't enumerate.
    if (!versions && typeof a?.vulnerableVersionRange === 'string' && a.vulnerableVersionRange.trim()) {
      const resolved = await resolveVulnerableRange(
        eco as CanonicalEcosystem,
        name,
        a.vulnerableVersionRange,
        cache,
      );
      if (resolved && resolved.length > 0) versions = resolved.slice(0, 200);
    }

    // 3. Fallback: one row with version=null = matches every installed version.
    versions = versions ?? [null];

    for (const v of versions) {
      entries.push({
        package_name: name,
        version: v ?? null,
        ecosystem: eco,
        source,
        source_id: sourceId,
        severity,
        description,
        withdrawn,
      });
    }
  }
  return entries;
}

function pickVersions(affected: any): Array<string | null> | null {
  if (Array.isArray(affected?.versions) && affected.versions.length > 0) {
    return affected.versions.slice(0, 50);
  }
  return null;
}

function parseSeverity(raw: unknown): MaliciousSeverity | null {
  if (!raw || typeof raw !== 'string') return null;
  const lower = raw.toLowerCase();
  if (lower === 'critical' || lower === 'high' || lower === 'medium' || lower === 'low' || lower === 'info') {
    return lower as MaliciousSeverity;
  }
  if (lower === 'moderate') return 'medium';
  return null;
}

async function upsertEntries(
  entries: UpsertEntry[],
): Promise<{ added: number; withdrawn: number }> {
  if (entries.length === 0) return { added: 0, withdrawn: 0 };

  // Dedup on the natural key BEFORE the upsert. One advisory can list the
  // same (package, ecosystem) twice with different vulnerableVersionRange
  // strings — and since we collapse all ranges into version=null for v1,
  // those become duplicate rows in the batch. Postgres rejects that with
  // "ON CONFLICT DO UPDATE command cannot affect row a second time", so we
  // must collapse to one row per natural key in JS first.
  const dedup = new Map<string, UpsertEntry>();
  for (const e of entries) {
    const key = `${e.source}\x00${e.source_id}\x00${e.package_name}\x00${e.version ?? ''}\x00${e.ecosystem}`;
    const prev = dedup.get(key);
    if (!prev) {
      dedup.set(key, e);
    } else if (!prev.withdrawn && e.withdrawn) {
      // Prefer withdrawn=true if the upstream withdrew this one — strictly
      // safer than dropping the withdrawal signal.
      dedup.set(key, e);
    }
  }
  const deduped = Array.from(dedup.values());

  const now = new Date().toISOString();
  const rows = deduped.map((e) => ({
    package_name: e.package_name,
    version: e.version,
    ecosystem: e.ecosystem,
    source: e.source,
    source_id: e.source_id,
    severity: e.severity,
    description: e.description,
    last_seen_at: now,
    withdrawn_at: e.withdrawn ? now : null,
  }));

  // Supabase / PostgREST chokes on huge single payloads (default body cap +
  // single transaction lock). The npm OSV dataset alone is ~212k MAL-*
  // entries. Batch in 1000-row chunks; each chunk is its own UPSERT.
  const BATCH = 1000;
  for (let i = 0; i < rows.length; i += BATCH) {
    const chunk = rows.slice(i, i + BATCH);
    const { error } = await supabase
      .from('known_malicious_packages')
      .upsert(chunk, { onConflict: 'source,source_id,package_name,version,ecosystem' });
    if (error) {
      throw new Error(
        `known_malicious_packages upsert failed at offset ${i}/${rows.length}: ${error.message}`,
      );
    }
  }

  const withdrawnCount = deduped.filter((e) => e.withdrawn).length;
  return { added: deduped.length - withdrawnCount, withdrawn: withdrawnCount };
}
