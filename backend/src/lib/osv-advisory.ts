/**
 * OSV advisory fetch — fills the `dependency_vulnerabilities` advisory cache with
 * a description (`details`) for CVEs the GHSA per-package query doesn't return.
 *
 * Why this exists: the vulnerability detail card sources its description ONLY from
 * the global `dependency_vulnerabilities.details` column, which today is populated
 * from GHSA (see `ghsaVulnToRow`). CVEs that dep-scan / OSV surface but GHSA's
 * per-package query doesn't return an advisory for — OSV aggregates PySec, the Go
 * vuln DB, RustSec, etc. well beyond GHSA — end up with a per-project finding row
 * but no cached advisory, so the card renders a blank description. OSV.dev has a
 * `details` field for essentially all of them, so we fall back to it.
 *
 * The vuln-detail RPC (phase49) matches an advisory by `osv_id` OR alias and never
 * filters by `dependency_id`, so one cached row per CVE is enough for the
 * description to resolve.
 *
 * OSV API reference: https://google.github.io/osv.dev/api/
 */

const OSV_API = 'https://api.osv.dev/v1';

export interface OsvVuln {
  id: string;
  summary?: string | null;
  details?: string | null;
  aliases?: string[];
  published?: string | null;
  modified?: string | null;
  database_specific?: { cwe_ids?: string[]; severity?: string } | null;
}

async function getJson(
  url: string,
  timeoutMs = 10_000,
): Promise<{ ok: boolean; status: number; body: any }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { accept: 'application/json' } });
    const text = await res.text();
    let body: any = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = text; }
    return { ok: res.ok, status: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch an OSV advisory by id. When OSV doesn't index the requested id directly
 * (common for CVE ids that OSV stores under a GHSA id), it returns a 404 whose
 * message names the alias(es) — e.g. `Bug not found, but the following aliases
 * were: GHSA-cwxw-98qj-8qjx` — which we follow once. Returns null when the
 * advisory genuinely isn't in OSV (or on a network error — callers soft-fail).
 */
export async function fetchOsvVuln(id: string): Promise<OsvVuln | null> {
  try {
    const first = await getJson(`${OSV_API}/vulns/${encodeURIComponent(id)}`);
    if (first.ok && first.body?.id) return first.body as OsvVuln;
    // 404 shape: { code: 5, message: "Bug not found, but the following aliases were: GHSA-..." }
    const msg: string = typeof first.body?.message === 'string' ? first.body.message : '';
    const alias = msg.match(/\b(GHSA-[0-9a-z-]+|CVE-\d{4}-\d+|[A-Z][A-Z0-9]+-\d{4}-\d+)\b/i)?.[1];
    if (alias && alias.toLowerCase() !== id.toLowerCase()) {
      const second = await getJson(`${OSV_API}/vulns/${encodeURIComponent(alias)}`);
      if (second.ok && second.body?.id) return second.body as OsvVuln;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Map an OSV advisory to a `dependency_vulnerabilities` row. Only `details` (the
 * point of this), `summary`, `aliases`, and the dates come from OSV. `severity`,
 * `fixed_versions`, and `affected_versions` are deliberately left NULL so the
 * detail endpoint's `globalVuln?.x ?? vuln.x` fallback uses the per-project (PDV)
 * values — writing an empty `[]` for fixed_versions here would hide the PDV's
 * "Fixed in vX" badge. `requestedId` (the id the finding actually uses) is added
 * to the aliases when it isn't already the row's osv_id, so the detail RPC's alias
 * match always resolves the finding to this advisory.
 */
export function osvVulnToAdvisoryRow(
  dependencyId: string,
  rec: OsvVuln,
  requestedId?: string,
): Record<string, unknown> {
  const aliases = new Set<string>((rec.aliases ?? []).filter(Boolean));
  if (requestedId && requestedId !== rec.id) aliases.add(requestedId);
  return {
    dependency_id: dependencyId,
    osv_id: rec.id,
    severity: null,
    classification: 'GENERAL',
    summary: rec.summary || null,
    details: rec.details || null,
    aliases: [...aliases],
    affected_versions: null,
    fixed_versions: null,
    published_at: rec.published || null,
    modified_at: rec.modified || null,
    cwe_ids: rec.database_specific?.cwe_ids ?? [],
  };
}
