/**
 * STEP: OSV-API vulnerability fallback.
 *
 * Runs after dep-scan when its local VDB lookup returned an empty VDR. We've
 * observed dep-scan's bundled VDB silently miss findings on whole ecosystems
 * (cargo, maven, some npm dev-scope clusters) even when the underlying OSV
 * advisory database has the data — confirmed by direct probes of
 * https://api.osv.dev/v1/query against PURLs known to be in OSV.
 *
 * Rather than debug OWASP's tool, this step reads the SBOM dep-scan
 * generated (which IS produced regardless of VDB hit-rate), queries OSV
 * directly in batches of up to 1000 PURLs via `/v1/querybatch`, fetches full
 * advisory details via `/v1/vulns/{id}` (only the ones we hit, deduplicated),
 * and emits a CycloneDX-shaped VDR file under depscan-reports/. The existing
 * dep-scan post-processing in pipeline-steps/dep-scan.ts then picks the VDR
 * up unchanged — zero downstream changes.
 *
 * Triggered when:
 *   - DEPTEX_OSV_FALLBACK=1 (forces always-on; used by the corpus harness)
 *   - OR dep-scan's VDR is missing/empty AND DEPTEX_OSV_FALLBACK is not '0'
 *
 * The fallback is best-effort: network failures, schema oddities, and
 * rate-limit responses get logged and downgraded to "no findings", same
 * shape dep-scan would have produced. It will NEVER write a VDR if dep-scan
 * already wrote a non-empty one — single source of truth invariant.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { PipelineLogger } from '../pipeline-types';

const OSV_QUERYBATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULNS_URL = 'https://api.osv.dev/v1/vulns';
const OSV_BATCH_SIZE = 1000;
/** Bounded concurrency on per-vuln detail fetch — OSV rate-limits aggressively. */
const VULN_DETAIL_CONCURRENCY = 8;
const FETCH_TIMEOUT_MS = 30_000;

interface SbomComponent {
  purl?: string;
  'bom-ref'?: string;
  name?: string;
  version?: string;
  group?: string;
}

interface SbomDocument {
  components?: SbomComponent[];
}

interface OsvVulnRef {
  id: string;
  modified?: string;
}

interface OsvBatchResponse {
  results?: Array<{ vulns?: OsvVulnRef[]; next_page_token?: string }>;
}

interface OsvAffectedRange {
  type?: string;
  events?: Array<{ introduced?: string; fixed?: string }>;
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string; purl?: string };
  ranges?: OsvAffectedRange[];
  versions?: string[];
}

interface OsvSeverity {
  type?: string;
  score?: string;
}

interface OsvVulnDetail {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  affected?: OsvAffected[];
  severity?: OsvSeverity[];
  database_specific?: { severity?: string };
}

/** A single CycloneDX-VDR vulnerability record (subset the pipeline reads). */
interface VdrVulnerability {
  id: string;
  description?: string;
  ratings?: Array<{ severity?: string; score?: number }>;
  affects?: Array<{ ref?: string; versions?: Array<{ version?: string; status?: string }> }>;
  properties?: Array<{ name?: string; value?: string }>;
  published?: string;
  /** Every other id this advisory is known by (CVE/GHSA/RUSTSEC/PYSEC/…),
   *  minus the canonical `id`. dep-scan.ts persists these onto the PDV's
   *  `aliases` column so the reachability classifier can match a taint flow
   *  keyed on an alias (e.g. RUSTSEC-2018-0006) against a PDV keyed on the
   *  CVE (e.g. CVE-2018-20993). */
  aliases?: string[];
}

// --- CVSS v3.x vector → base score (O1) -----------------------------------
//
// OSV advisories on cargo/maven/PYSEC frequently carry severity ONLY as a CVSS
// vector string (`severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/...' }]`)
// with no database_specific.severity word. The old stub returned undefined, so
// the PDV landed with null severity + null CVSS and dep-scan.ts/reachability.ts
// defaulted it to 4.0/medium — burying genuine criticals. We now compute the
// base score from the vector per the CVSS v3.1 spec (the v3.0 formula is
// identical) so the real band survives.

const CVSS3_METRICS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  // PR is scope-dependent — resolved in parseCvss3Vector.
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

/** CVSS v3.1 Roundup: round UP to one decimal place (spec appendix A). */
function cvssRoundup(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/**
 * Parse a CVSS v3.0/v3.1 vector string to its numeric base score [0,10].
 * Returns undefined for non-v3 vectors (v2/v4) or malformed input — callers
 * then fall back to the severity word.
 */
export function parseCvss3Vector(vector: string | undefined): number | undefined {
  if (!vector || typeof vector !== 'string') return undefined;
  const trimmed = vector.trim();
  if (!/^CVSS:3\.[01]\//i.test(trimmed)) return undefined;

  const parts = new Map<string, string>();
  for (const seg of trimmed.split('/')) {
    const [k, v] = seg.split(':');
    if (k && v) parts.set(k.toUpperCase(), v.toUpperCase());
  }

  const av = CVSS3_METRICS.AV[parts.get('AV') as keyof typeof CVSS3_METRICS.AV];
  const ac = CVSS3_METRICS.AC[parts.get('AC') as keyof typeof CVSS3_METRICS.AC];
  const ui = CVSS3_METRICS.UI[parts.get('UI') as keyof typeof CVSS3_METRICS.UI];
  const scope = parts.get('S'); // 'U' | 'C'
  const prTable = scope === 'C' ? CVSS3_METRICS.PR_C : CVSS3_METRICS.PR_U;
  const pr = prTable[parts.get('PR') as keyof typeof prTable];
  const c = CVSS3_METRICS.CIA[parts.get('C') as keyof typeof CVSS3_METRICS.CIA];
  const i = CVSS3_METRICS.CIA[parts.get('I') as keyof typeof CVSS3_METRICS.CIA];
  const a = CVSS3_METRICS.CIA[parts.get('A') as keyof typeof CVSS3_METRICS.CIA];

  // Every base metric is mandatory; a missing/unknown one means we can't score.
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined) || (scope !== 'U' && scope !== 'C')) {
    return undefined;
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scope === 'C'
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = scope === 'C'
    ? 1.08 * (impact + exploitability)
    : impact + exploitability;
  return cvssRoundup(Math.min(raw, 10));
}

/** Map a numeric CVSS base score to the qualitative band dep-scan.ts keys on. */
export function severityBandFromScore(score: number): 'critical' | 'high' | 'medium' | 'low' | null {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return null;
}

/** Pick the first CVSS v3.x vector from an OSV severity array and score it. */
function scoreFromOsvSeverity(severities: OsvSeverity[]): number | null {
  for (const s of severities) {
    const score = parseCvss3Vector(s?.score);
    if (score != null) return score;
  }
  return null;
}

function normalizeSeverity(detail: OsvVulnDetail): { severity: string | null; score: number | null } {
  // Prefer GHSA's database_specific.severity (UPPERCASE word: LOW/MODERATE/HIGH/CRITICAL).
  const dbSpec = detail.database_specific?.severity;
  if (dbSpec) {
    const upper = dbSpec.trim().toUpperCase();
    const normalized: Record<string, string> = {
      LOW: 'low',
      MODERATE: 'medium',
      MEDIUM: 'medium',
      HIGH: 'high',
      CRITICAL: 'critical',
    };
    if (normalized[upper]) {
      // Carry a numeric score too when a parseable vector is present, so the
      // VDR rating exposes both the word and the precise base score.
      const score = Array.isArray(detail.severity) ? scoreFromOsvSeverity(detail.severity) : null;
      return { severity: normalized[upper], score };
    }
  }
  // O1: no severity word — derive band + numeric score from the CVSS v3.x vector
  // instead of returning null (which the depscore path back-filled to medium).
  if (Array.isArray(detail.severity) && detail.severity.length > 0) {
    const score = scoreFromOsvSeverity(detail.severity);
    if (score != null) return { severity: severityBandFromScore(score), score };
  }
  return { severity: null, score: null };
}

type AffectsEntry = NonNullable<VdrVulnerability['affects']>[number];

function buildAffectsForVdr(detail: OsvVulnDetail, queriedPurl: string): AffectsEntry[] {
  // The dep-scan post-processor parses `ref` as a purl, finds the package
  // in project_dependencies by `name@version`, and reads `versions[*].status`
  // for fixed versions. We just echo back the purl we queried — that purl is
  // already in the SBOM at exactly the version we want to attach the PDV to.
  const fixed: Array<{ version: string; status: string }> = [];
  for (const aff of detail.affected ?? []) {
    for (const r of aff.ranges ?? []) {
      for (const ev of r.events ?? []) {
        if (ev.fixed) fixed.push({ version: ev.fixed, status: 'unaffected' });
      }
    }
  }
  return [{ ref: queriedPurl, versions: fixed.length > 0 ? fixed : undefined }];
}

/**
 * Parse an SBOM file (CycloneDX 1.x) and emit a deduped list of PURLs to
 * query. Filters: must start with `pkg:`, must have an `@version` component.
 * The SBOM's top-level "component" (the project itself) is dropped — we don't
 * want OSV vulns *of* the org's own package.
 */
export function extractPurlsFromSbom(sbomJson: SbomDocument, projectBomRef: string | null): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const c of sbomJson.components ?? []) {
    if (!c.purl) continue;
    if (typeof c.purl !== 'string' || !c.purl.startsWith('pkg:')) continue;
    if (!c.purl.includes('@')) continue;
    if (projectBomRef && c['bom-ref'] === projectBomRef) continue;
    if (seen.has(c.purl)) continue;
    seen.add(c.purl);
    out.push(c.purl);
  }
  return out;
}

async function fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
}

/** Query /v1/querybatch in chunks of up to 1000. Returns one OsvVulnRef[] per input PURL. */
export async function queryOsvBatch(purls: string[]): Promise<Array<OsvVulnRef[]>> {
  const out: Array<OsvVulnRef[]> = new Array(purls.length).fill(null).map(() => []);
  for (let i = 0; i < purls.length; i += OSV_BATCH_SIZE) {
    const chunk = purls.slice(i, i + OSV_BATCH_SIZE);
    const body = JSON.stringify({
      queries: chunk.map((p) => ({ package: { purl: p } })),
    });
    const res = await fetchWithTimeout(OSV_QUERYBATCH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'deptex-depscanner/1.0' },
      body,
    });
    if (!res.ok) {
      throw new Error(`OSV querybatch HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    }
    const json = (await res.json()) as OsvBatchResponse;
    const results = json.results ?? [];
    for (let j = 0; j < chunk.length; j++) {
      out[i + j] = Array.isArray(results[j]?.vulns) ? results[j]!.vulns! : [];
    }
  }
  return out;
}

/** Fetch full detail for an OSV id with bounded concurrency. */
async function fetchVulnDetails(
  ids: string[],
  logger: Pick<PipelineLogger, 'warn'>,
): Promise<Map<string, OsvVulnDetail>> {
  const out = new Map<string, OsvVulnDetail>();
  let cursor = 0;
  async function worker() {
    while (true) {
      const idx = cursor++;
      if (idx >= ids.length) return;
      const id = ids[idx];
      try {
        const res = await fetchWithTimeout(`${OSV_VULNS_URL}/${encodeURIComponent(id)}`, {
          headers: { 'User-Agent': 'deptex-depscanner/1.0' },
        });
        if (res.ok) {
          const detail = (await res.json()) as OsvVulnDetail;
          out.set(id, detail);
        }
        // 404 = the id was returned by querybatch but the detail endpoint
        // doesn't know it (alias mismatch). Drop silently.
      } catch (e) {
        await logger.warn?.('vuln_scan', `OSV detail fetch failed for ${id}: ${(e as Error).message}`);
      }
    }
  }
  const workers = Array.from({ length: Math.min(VULN_DETAIL_CONCURRENCY, ids.length) }, () => worker());
  await Promise.all(workers);
  return out;
}

/**
 * Prefer CVE alias as the canonical id, since the rest of the pipeline (CISA
 * KEV match, EPSS lookup, deduplication) keys on CVE strings. Falls back to
 * the OSV native id (GHSA-/RUSTSEC-/PYSEC-) when no CVE alias exists.
 */
function pickCanonicalId(detail: OsvVulnDetail): string {
  const aliases = Array.isArray(detail.aliases) ? detail.aliases : [];
  const cve = aliases.find((a) => /^CVE-\d{4}-\d+$/i.test(a));
  return cve ?? detail.id;
}

function vulnToVdrEntry(detail: OsvVulnDetail, queriedPurl: string): VdrVulnerability {
  const canonical = pickCanonicalId(detail);
  const { severity, score } = normalizeSeverity(detail);
  // Carry every id this advisory is known by (its OSV-native id + all aliases)
  // minus the canonical id, so the PDV's `aliases` column lets the reachability
  // classifier bridge a flow keyed on a GHSA/RUSTSEC alias to a PDV keyed on
  // the CVE. Without this, alias-keyed reachable flows never promote.
  const aliasSet = new Set<string>([detail.id, ...(Array.isArray(detail.aliases) ? detail.aliases : [])]);
  aliasSet.delete(canonical);
  const aliases = [...aliasSet].filter((a) => typeof a === 'string' && a.length > 0);
  // O1: emit the numeric base score alongside the band so dep-scan.ts reads a
  // precise CVSS (it prefers ratings[0].score) instead of the SEVERITY_TO_CVSS
  // bucket. Carry a rating whenever we have either signal.
  const ratings = severity != null || score != null
    ? [{
        ...(severity != null ? { severity } : {}),
        ...(score != null ? { score } : {}),
      }]
    : undefined;
  return {
    id: canonical,
    description: detail.summary ?? detail.details ?? undefined,
    ratings,
    affects: buildAffectsForVdr(detail, queriedPurl),
    properties: [{ name: 'depscan:insights', value: 'osv-fallback' }],
    published: detail.published,
    aliases: aliases.length > 0 ? aliases : undefined,
  };
}

/**
 * Top-level entry. Inspects `reportsDir` for an existing non-empty VDR; if
 * found, returns without doing anything (dep-scan won). If not, parses the
 * SBOM in the same dir, queries OSV, writes synthetic VDR, returns
 * `{ wrote: true, vulnCount: N }`.
 */
export async function runOsvFallback(opts: {
  reportsDir: string;
  jobEcosystem: string;
  logger: Pick<PipelineLogger, 'info' | 'warn'>;
  /** Force-on; bypasses the "skip when dep-scan VDR is non-empty" guard. */
  force?: boolean;
  /**
   * PURLs the caller captured from the pipeline's own SBOM *before* dep-scan
   * ran. dep-scan can run for many minutes and crash, leaving reportsDir with
   * no usable SBOM (and it can churn the workspace), so passing the
   * pre-captured purls directly guarantees the OSV query still runs against the
   * real dependency set. Unioned with whatever SBOM/extra-purls are on disk.
   */
  callerPurls?: string[];
}): Promise<{ wrote: boolean; vulnCount: number; reason?: string; failed?: boolean }> {
  const { reportsDir, jobEcosystem, logger } = opts;
  const callerPurls = (opts.callerPurls ?? []).filter(
    (p): p is string => typeof p === 'string' && p.startsWith('pkg:'),
  );

  const sbomCandidates: string[] = [];
  let existingVdrHasVulns = false;
  let extraPurlsFile: string | null = null;
  try {
    for (const entry of fs.readdirSync(reportsDir, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      const full = path.join(reportsDir, entry.name);
      if (entry.name.endsWith('.vdr.json')) {
        try {
          const parsed = JSON.parse(fs.readFileSync(full, 'utf8')) as { vulnerabilities?: unknown };
          if (Array.isArray(parsed.vulnerabilities) && parsed.vulnerabilities.length > 0) {
            existingVdrHasVulns = true;
          }
        } catch { /* malformed VDR — treat as empty */ }
      } else if (entry.name.endsWith('.cdx.json')) {
        sbomCandidates.push(full);
      } else if (entry.name === 'osv-extra-purls.json') {
        extraPurlsFile = full;
      }
    }
  } catch (e) {
    // O2: an unreadable reportsDir is an infra failure, not "zero vulns".
    return { wrote: false, vulnCount: 0, failed: true, reason: `reportsDir not readable: ${(e as Error).message}` };
  }

  if (existingVdrHasVulns && !opts.force) {
    return { wrote: false, vulnCount: 0, reason: 'dep-scan VDR non-empty; skipping fallback' };
  }
  if (sbomCandidates.length === 0 && callerPurls.length === 0 && !extraPurlsFile) {
    return { wrote: false, vulnCount: 0, reason: 'no SBOM file or caller PURLs available' };
  }

  // dep-scan can crash AFTER emitting an empty `.cdx.json` (bad `-t`, VDB
  // corruption), while the pipeline's own SBOM — copied in as
  // `_pipeline-sbom.cdx.json` by the dep-scan step — carries the full
  // dependency set. Picking the FIRST cdx on disk would let an empty dep-scan
  // SBOM starve the fallback to zero PURLs, so choose whichever candidate
  // yields the most PURLs.
  let sbom: SbomDocument | null = null;
  let sbomPurls: string[] = [];
  for (const cand of sbomCandidates) {
    let parsed: SbomDocument;
    try {
      parsed = JSON.parse(fs.readFileSync(cand, 'utf8')) as SbomDocument;
    } catch {
      continue;
    }
    const bomRef =
      (parsed as unknown as { metadata?: { component?: { 'bom-ref'?: string } } })?.metadata?.component?.['bom-ref']
      ?? null;
    const purls = extractPurlsFromSbom(parsed, bomRef);
    if (purls.length > sbomPurls.length) {
      sbom = parsed;
      sbomPurls = purls;
    }
  }

  // No parseable on-disk SBOM is fine as long as the caller supplied purls (or
  // a transitive-resolver sidecar exists) — those carry the dependency set.
  if (!sbom && callerPurls.length === 0 && !extraPurlsFile) {
    return { wrote: false, vulnCount: 0, reason: 'no parseable SBOM file found in reportsDir' };
  }

  // v3 extension: union in any purls the transitive resolver added in the
  // SBOM step (gomod/pypi shallow-SBOM workaround). cdxgen for those ecos
  // emits only direct deps, so without this the OSV fallback would
  // vuln-query just the 29 directs and miss the 500+ transitives the
  // resolver supplied to the classifier.
  let extraPurls: string[] = [];
  if (extraPurlsFile) {
    try {
      const parsed = JSON.parse(fs.readFileSync(extraPurlsFile, 'utf8')) as { purls?: unknown };
      if (Array.isArray(parsed.purls)) {
        extraPurls = parsed.purls.filter((p): p is string => typeof p === 'string' && p.startsWith('pkg:'));
      }
    } catch (e) {
      await logger.warn?.('vuln_scan', `osv-extra-purls.json parse failed: ${(e as Error).message}`);
    }
  }

  const seen = new Set(sbomPurls);
  const purls = [...sbomPurls];
  for (const p of [...extraPurls, ...callerPurls]) {
    if (!seen.has(p)) {
      seen.add(p);
      purls.push(p);
    }
  }

  if (purls.length === 0) {
    return { wrote: false, vulnCount: 0, reason: 'SBOM had zero PURL-bearing components' };
  }

  await logger.info?.(
    'vuln_scan',
    `OSV fallback querying ${purls.length} PURLs (dep-scan VDR was empty)`,
  );

  let batchResults: Array<OsvVulnRef[]>;
  try {
    batchResults = await queryOsvBatch(purls);
  } catch (e) {
    // O2: the OSV API itself failed (network error / non-2xx batch response).
    // We HAD PURLs to query but couldn't — that is a degraded run, NOT a clean
    // "no vulns found". Flag it so the caller can fail loudly when OSV is the
    // sole vulnerability source instead of silently shipping zero findings.
    await logger.warn?.('vuln_scan', `OSV batch query failed: ${(e as Error).message}`);
    return { wrote: false, vulnCount: 0, failed: true, reason: `osv-batch failed: ${(e as Error).message}` };
  }

  // Collect unique OSV ids, mapping each id back to the (potentially multiple)
  // purls that produced it. A single advisory can hit many of our deps.
  const idToPurls = new Map<string, string[]>();
  for (let i = 0; i < purls.length; i++) {
    for (const v of batchResults[i] ?? []) {
      if (!v?.id) continue;
      const arr = idToPurls.get(v.id) ?? [];
      arr.push(purls[i]);
      idToPurls.set(v.id, arr);
    }
  }
  if (idToPurls.size === 0) {
    // Still write an empty VDR so downstream knows we tried.
    const emptyVdr = { bomFormat: 'CycloneDX-VDR', specVersion: '1.5', vulnerabilities: [] };
    const outPath = path.join(reportsDir, 'osv-fallback.vdr.json');
    fs.writeFileSync(outPath, JSON.stringify(emptyVdr));
    return { wrote: true, vulnCount: 0, reason: 'no vulns matched any PURL' };
  }

  const details = await fetchVulnDetails(Array.from(idToPurls.keys()), logger);

  // De-dupe by canonical id (post-alias). If two OSV ids resolve to the same
  // CVE (RUSTSEC + GHSA + CVE three-way mapping), pick one detail to emit.
  const byCanonical = new Map<string, VdrVulnerability>();
  for (const [osvId, hitPurls] of idToPurls.entries()) {
    const detail = details.get(osvId);
    if (!detail) continue;
    const canonical = pickCanonicalId(detail);
    if (byCanonical.has(canonical)) {
      // Merge affects — add purls from this duplicate that weren't already covered.
      const existing = byCanonical.get(canonical)!;
      const seenRefs = new Set((existing.affects ?? []).map((a) => a.ref).filter(Boolean) as string[]);
      for (const p of hitPurls) {
        if (!seenRefs.has(p)) {
          existing.affects = [...(existing.affects ?? []), ...buildAffectsForVdr(detail, p)];
          seenRefs.add(p);
        }
      }
      continue;
    }
    // First hit — emit one entry per unique purl this id was found against.
    const firstPurl = hitPurls[0];
    const entry = vulnToVdrEntry(detail, firstPurl);
    if (hitPurls.length > 1) {
      const extra = hitPurls.slice(1).map((p) => buildAffectsForVdr(detail, p)).flat();
      entry.affects = [...(entry.affects ?? []), ...extra];
    }
    byCanonical.set(canonical, entry);
  }

  const vulnerabilities = Array.from(byCanonical.values());
  const vdr = {
    bomFormat: 'CycloneDX-VDR',
    specVersion: '1.5',
    vulnerabilities,
  };
  const outPath = path.join(reportsDir, 'osv-fallback.vdr.json');
  fs.writeFileSync(outPath, JSON.stringify(vdr, null, 2));

  await logger.info?.(
    'vuln_scan',
    `OSV fallback wrote ${vulnerabilities.length} vulnerabilities (ecosystem=${jobEcosystem}) to ${path.basename(outPath)}`,
  );
  return { wrote: true, vulnCount: vulnerabilities.length };
}

/** Cheap accessor for the env flag — exported so dep-scan.ts can branch on it. */
export function osvFallbackMode(): 'force' | 'auto' | 'off' {
  const v = process.env.DEPTEX_OSV_FALLBACK?.trim();
  if (v === '1' || v === 'true' || v === 'force') return 'force';
  if (v === '0' || v === 'false' || v === 'off') return 'off';
  return 'auto';
}
