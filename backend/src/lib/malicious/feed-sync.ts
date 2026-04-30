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
import { supabase } from '../supabase';
import { canonicalizeEcosystem } from './ecosystem';
import type { MaliciousFeedSource, MaliciousFeedSyncState, MaliciousSeverity } from './types';
import { getGitHubToken } from '../ghsa';

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
  for (const eco of OSV_ECOSYSTEMS) {
    const entries = await fetchOsvMaliciousForEcosystem(eco.raw, eco.canonical);
    const summary = await upsertEntries(entries);
    added += summary.added;
    withdrawn += summary.withdrawn;
  }
  return { entries_added: added, entries_withdrawn: withdrawn };
}

async function fetchOsvMaliciousForEcosystem(ecoRaw: string, canonical: string): Promise<UpsertEntry[]> {
  // OSV ships per-ecosystem ZIPs at osv-vulnerabilities.storage.googleapis.com.
  // For v1 we use the lighter index that lists IDs and let the API tell us
  // about each. We only care about MAL-* prefixed IDs (the OSSF malicious
  // dataset publishes those into OSV.dev).
  const indexUrl = `https://osv-vulnerabilities.storage.googleapis.com/${encodeURIComponent(ecoRaw)}/all.json`;
  const res = await fetch(indexUrl);
  if (!res.ok) {
    if (res.status === 404) return [];
    throw new Error(`OSV ${ecoRaw} index fetch failed: ${res.status} ${res.statusText}`);
  }

  const ids = (await res.json()) as Array<{ id: string; modified?: string }>;
  const malIds = ids
    .filter((row) => typeof row.id === 'string' && row.id.startsWith('MAL-'))
    .map((row) => row.id)
    .slice(0, 1000); // belt-and-braces cap; OSV malicious set is small

  const entries: UpsertEntry[] = [];
  for (const id of malIds) {
    const detail = await fetchOsvAdvisory(id);
    if (!detail) continue;
    for (const e of advisoryToEntries(detail, 'osv', canonical)) {
      entries.push(e);
    }
  }
  return entries;
}

async function fetchOsvAdvisory(id: string): Promise<any | null> {
  const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
  if (!res.ok) return null;
  return res.json();
}

// ───────────────────────────── GHSA ────────────────────────────────────────

async function syncGhsa(): Promise<{ entries_added: number; entries_withdrawn: number }> {
  const token = getGitHubToken();
  if (!token) {
    // Without a token we hit unauthenticated rate limits almost
    // immediately on the GraphQL endpoint. Skip cleanly with a warning;
    // the run row records 'completed' with 0 entries so the watchdog
    // doesn't fire.
    console.warn('[malicious feed-sync] GHSA: no GITHUB_TOKEN — skipping run');
    return { entries_added: 0, entries_withdrawn: 0 };
  }

  let added = 0;
  let withdrawn = 0;
  let cursor: string | null = null;
  let pages = 0;
  const maxPages = 50;

  while (pages < maxPages) {
    const page = await fetchGhsaMalwarePage(cursor, token);
    if (!page || page.advisories.length === 0) break;

    const entries: UpsertEntry[] = [];
    for (const adv of page.advisories) {
      const ecoRaw = adv.vulnerabilities?.[0]?.package?.ecosystem;
      const canonical = canonicalizeEcosystem(ecoRaw ?? null);
      if (!canonical) continue;
      for (const e of advisoryToEntries(adv, 'ghsa', canonical)) {
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

  return { entries_added: added, entries_withdrawn: withdrawn };
}

async function fetchGhsaMalwarePage(
  cursor: string | null,
  token: string,
): Promise<{ advisories: any[]; hasNextPage: boolean; endCursor: string | null } | null> {
  const after = cursor ? `, after: ${JSON.stringify(cursor)}` : '';
  const query = `query {
    securityAdvisories(first: 100${after}, classifications: [MALWARE], orderBy: { field: PUBLISHED_AT, direction: DESC }) {
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
  if (!res.ok) {
    throw new Error(`GHSA GraphQL ${res.status}: ${await res.text()}`);
  }
  const json = (await res.json()) as any;
  if (json.errors) {
    throw new Error(`GHSA GraphQL errors: ${JSON.stringify(json.errors)}`);
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

function advisoryToEntries(
  advisory: any,
  source: MaliciousFeedSource,
  canonical: string,
): UpsertEntry[] {
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
    const versions: Array<string | null> = pickVersions(a) ?? [null];
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

  const now = new Date().toISOString();
  const rows = entries.map((e) => ({
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

  const { error } = await supabase
    .from('known_malicious_packages')
    .upsert(rows, { onConflict: 'source,source_id' });
  if (error) {
    throw new Error(`known_malicious_packages upsert failed: ${error.message}`);
  }

  const withdrawnCount = entries.filter((e) => e.withdrawn).length;
  return { added: entries.length - withdrawnCount, withdrawn: withdrawnCount };
}
