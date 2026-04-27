/**
 * OSV.dev advisory fetcher.
 *
 * Calls https://api.osv.dev/v1/vulns/{id} (free, public, no auth) to retrieve
 * the structured advisory for a given CVE/GHSA identifier. We pull the
 * affected ranges (for the prompt) and the FIX commit URL (for patch fetch +
 * validation cloning).
 *
 * OSV is the only data source we rely on; if a CVE has no OSV entry, or its
 * entry has no GitHub fix-commit reference, we cannot generate a rule and the
 * caller should mark the CVE as `no_advisory` / `no_fix_commit` and move on.
 */

const OSV_BASE = 'https://api.osv.dev/v1/vulns';
const REQUEST_TIMEOUT_MS = 15_000;

export interface OsvAffectedRange {
  type?: string;
  events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
}

export interface OsvAffectedPackage {
  package?: { name?: string; ecosystem?: string; purl?: string };
  ranges?: OsvAffectedRange[];
  versions?: string[];
}

export interface OsvReference {
  type: string;
  url: string;
}

export interface OsvAdvisory {
  id: string;
  aliases: string[];
  summary: string;
  details: string;
  affected: OsvAffectedPackage[];
  references: OsvReference[];
}

export interface FixCommit {
  /** Full commit URL on github.com (other forges are skipped). */
  url: string;
  owner: string;
  repo: string;
  sha: string;
}

export class OsvFetchError extends Error {
  readonly code: 'not_found' | 'network' | 'parse' | 'unexpected';

  constructor(code: OsvFetchError['code'], message: string) {
    super(message);
    this.name = 'OsvFetchError';
    this.code = code;
  }
}

export async function fetchOsvAdvisory(cveId: string, signal?: AbortSignal): Promise<OsvAdvisory | null> {
  const trimmed = cveId.trim();
  if (!trimmed) throw new OsvFetchError('unexpected', 'cveId is empty');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  // Forward an outer abort signal too so a pipeline timeout cancels the
  // outstanding request rather than letting it run to its own timeout.
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', () => controller.abort(), { once: true });
  }

  let res: Response;
  try {
    res = await fetch(`${OSV_BASE}/${encodeURIComponent(trimmed)}`, {
      method: 'GET',
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
  } catch (err) {
    throw new OsvFetchError('network', `OSV fetch failed: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    clearTimeout(timer);
  }

  if (res.status === 404) return null;
  if (!res.ok) {
    throw new OsvFetchError('network', `OSV returned ${res.status} for ${trimmed}`);
  }

  let body: unknown;
  try {
    body = await res.json();
  } catch (err) {
    throw new OsvFetchError('parse', `OSV body was not JSON: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (!body || typeof body !== 'object') {
    throw new OsvFetchError('parse', 'OSV body was not an object');
  }
  const obj = body as Record<string, unknown>;
  if (typeof obj.id !== 'string') {
    throw new OsvFetchError('parse', 'OSV body missing id');
  }

  return {
    id: obj.id,
    aliases: Array.isArray(obj.aliases) ? obj.aliases.filter((x): x is string => typeof x === 'string') : [],
    summary: typeof obj.summary === 'string' ? obj.summary : '',
    details: typeof obj.details === 'string' ? obj.details : '',
    affected: Array.isArray(obj.affected) ? (obj.affected as OsvAffectedPackage[]) : [],
    references: Array.isArray(obj.references) ? (obj.references as OsvReference[]) : [],
  };
}

/**
 * Walk the references array and pull every github.com commit URL. We prefer
 * `type=FIX` references but fall back to any commit URL — some OSV entries
 * tag the patch commit only as `WEB`. Returned in OSV order (the entries are
 * already roughly chronological).
 */
export function extractFixCommits(advisory: OsvAdvisory): FixCommit[] {
  const out: FixCommit[] = [];
  const seen = new Set<string>();

  const consider = (ref: OsvReference) => {
    const parsed = parseGithubCommitUrl(ref.url);
    if (!parsed) return;
    const key = `${parsed.owner}/${parsed.repo}@${parsed.sha}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(parsed);
  };

  for (const ref of advisory.references) {
    if (ref.type === 'FIX') consider(ref);
  }
  for (const ref of advisory.references) {
    if (ref.type !== 'FIX') consider(ref);
  }

  return out;
}

const COMMIT_URL_RE = /^https?:\/\/(?:www\.)?github\.com\/([^/\s]+)\/([^/\s]+)\/commit\/([0-9a-f]{7,40})\b/i;

export function parseGithubCommitUrl(url: string): FixCommit | null {
  if (!url) return null;
  const m = url.match(COMMIT_URL_RE);
  if (!m) return null;
  const owner = m[1];
  // Strip a trailing `.git` if someone put the .git URL form into a commit URL.
  const repo = m[2].replace(/\.git$/, '');
  const sha = m[3].toLowerCase();
  return { url: `https://github.com/${owner}/${repo}/commit/${sha}`, owner, repo, sha };
}

/**
 * Try to summarise the affected version range for use in the prompt. OSV
 * encodes ranges as `events` arrays; we want a concise human-readable string
 * like "<4.17.21" or "1.0.0-1.2.3". Returns the first matching range we find,
 * or undefined if the advisory doesn't carry a structured range.
 */
export function summarizeAffectedRange(advisory: OsvAdvisory, packageName: string): string | undefined {
  const lower = packageName.toLowerCase();
  for (const aff of advisory.affected) {
    const name = aff.package?.name;
    if (!name) continue;
    if (name.toLowerCase() !== lower) continue;
    for (const range of aff.ranges ?? []) {
      const intro = range.events?.find((e) => e.introduced)?.introduced;
      const fixed = range.events?.find((e) => e.fixed)?.fixed;
      const last = range.events?.find((e) => e.last_affected)?.last_affected;
      if (fixed && (!intro || intro === '0')) return `<${fixed}`;
      if (intro && fixed) return `>=${intro} <${fixed}`;
      if (intro && last) return `>=${intro} <=${last}`;
      if (fixed) return `<${fixed}`;
    }
  }
  return undefined;
}
