import { createHash } from 'crypto';

import type { SupabaseClient } from '@supabase/supabase-js';
import type { ContainerFinding, IaCFinding } from './types';

const BATCH_SIZE = 100;

/**
 * Multiplier applied to a container finding's severity-based depscore when the
 * reachability classifier proved the OS package is NOT loaded by the image's
 * entrypoint. `module` and unclassified (`null`) findings keep the full
 * severity score — fail-closed by construction.
 *
 * Deliberately diverges from `depscanner/src/depscore.ts`'s
 * `REACHABILITY_WEIGHT_UNREACHABLE = 0.0` for code-dependency findings:
 *
 *   - Code-dependency reachability comes from a call-graph traversal of the
 *     project's own source. An `unreachable` verdict there is strong evidence
 *     the package can't be invoked, so the depscore zeroes out.
 *   - Container OS-package reachability is a static inference from DT_NEEDED
 *     chains + dlopen literals against the image's dpkg/apk DB. The binutils
 *     and `exec "$@"`-wrapper fallbacks both fail closed to `module`, so an
 *     `unreachable` verdict here means "we positively determined nothing
 *     reaches it" — a weaker signal than the code-dep call graph. We downweight
 *     it hard but never zero it.
 *
 * Locked at 0.4: a HIGH `unreachable` finding lands at 28 (just below LOW=30),
 * CRITICAL at 36 (above LOW), MEDIUM at 20. The named constant exists for
 * future tuning, not a deferred decision.
 */
export const CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER = 0.4;

interface IaCRow extends Record<string, unknown> {
  project_id: string;
  extraction_run_id: string;
  scanner: 'trivy' | 'checkov';
  scanner_version: string | null;
  rule_id: string;
  framework: string;
  file_path: string;
  start_line: number | null;
  end_line: number | null;
  severity: string | null;
  depscore: number | null;
  message: string | null;
  description: string | null;
  cwe_ids: string[];
  code_snippet: string | null;
  rule_doc_url: string | null;
  iac_fingerprint: string | null;
  compliance_refs: Record<string, string[]> | null;
  metadata: Record<string, unknown> | null;
}

type ContainerImageSource = 'dockerfile_base' | 'configured_image';

interface ContainerRow extends Record<string, unknown> {
  project_id: string;
  extraction_run_id: string;
  scanner_version: string | null;
  image_reference: string;
  image_digest: string;
  image_source: ContainerImageSource;
  os_package_name: string;
  os_package_version: string;
  os_package_ecosystem: string | null;
  osv_id: string | null;
  cve_id: string | null;
  // NOTE: vulnerability_id is intentionally absent — column is GENERATED ALWAYS.
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  fix_versions: string[];
  layer_digest: string | null;
  depscore: number | null;
  description: string | null;
  rule_doc_url: string | null;
  container_fingerprint: string | null;
  reachability_level: 'module' | 'unreachable' | null;
  reachability_details: Record<string, unknown> | null;
}

export interface UpsertResult {
  inserted: number;
  staleDeleted: number;
}

function severityToDepscore(severity: string | null): number | null {
  switch ((severity ?? '').toUpperCase()) {
    case 'CRITICAL': return 90;
    case 'HIGH': return 70;
    case 'MEDIUM': return 50;
    case 'LOW': return 30;
    case 'INFO': return 10;
    default: return null;
  }
}

/**
 * Compute the depscore for a container finding, folding in the static OS-
 * package reachability verdict so an `unreachable` finding ranks below a
 * `module`/unclassified finding of equal severity. Used only by
 * upsertContainerFindings — IaC findings have no reachability signal and
 * continue to use `severityToDepscore` directly.
 */
export function containerDepscore(f: ContainerFinding): number | null {
  const base = severityToDepscore(f.severity);
  if (base === null) return null;
  if (f.reachability_level === 'unreachable') {
    return Math.round(base * CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER);
  }
  return base;
}

/**
 * Bulk upsert IaC findings against the `(project_id, rule_id, file_path,
 * start_line_key, extraction_run_id)` UNIQUE index. Patch A: start_line_key is
 * GENERATED, never supplied in payload. Patch D: organization_id is set by
 * BEFORE INSERT trigger from projects.organization_id, so the worker never
 * passes organization_id either — preventing caller-side mis-attribution.
 */
export async function upsertIaCFindings(
  supabase: SupabaseClient,
  projectId: string,
  runId: string,
  findings: IaCFinding[]
): Promise<UpsertResult> {
  if (findings.length === 0) {
    return { inserted: 0, staleDeleted: 0 };
  }

  const rows: IaCRow[] = findings.map((f) => ({
    project_id: projectId,
    extraction_run_id: runId,
    scanner: f.scanner,
    scanner_version: f.scanner_version,
    rule_id: f.rule_id,
    framework: f.framework,
    file_path: f.file_path,
    start_line: f.start_line,
    end_line: f.end_line,
    severity: f.severity,
    depscore: severityToDepscore(f.severity),
    message: f.message,
    description: f.description,
    cwe_ids: f.cwe_ids ?? [],
    code_snippet: f.code_snippet,
    rule_doc_url: f.rule_doc_url,
    iac_fingerprint: f.iac_fingerprint,
    compliance_refs: f.compliance_refs,
    metadata: f.metadata,
  }));

  let inserted = 0;
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    const { error } = await supabase
      .from('project_iac_findings')
      .upsert(batch, {
        onConflict:
          'project_id,rule_id,file_path,start_line_key,extraction_run_id',
      });
    if (error) {
      throw new Error(`upsertIaCFindings batch ${i}: ${error.message}`);
    }
    inserted += batch.length;
  }
  return { inserted, staleDeleted: 0 };
}

/**
 * Bulk upsert container findings. Patch B: vulnerability_id is GENERATED
 * ALWAYS and MUST NOT appear in the payload. Patch D: same trigger semantics
 * as IaC.
 */
export async function upsertContainerFindings(
  supabase: SupabaseClient,
  projectId: string,
  runId: string,
  findings: ContainerFinding[],
  imageSource: ContainerImageSource = 'dockerfile_base'
): Promise<UpsertResult> {
  if (findings.length === 0) {
    return { inserted: 0, staleDeleted: 0 };
  }

  const rows: ContainerRow[] = findings.map((f) => ({
    project_id: projectId,
    extraction_run_id: runId,
    scanner_version: f.scanner_version,
    image_reference: f.image_reference,
    image_digest: f.image_digest,
    image_source: imageSource,
    os_package_name: f.os_package_name,
    os_package_version: f.os_package_version,
    os_package_ecosystem: f.os_package_ecosystem,
    osv_id: f.osv_id,
    cve_id: f.cve_id,
    severity: f.severity,
    cvss_score: f.cvss_score,
    epss_score: f.epss_score,
    is_kev: f.is_kev,
    fix_versions: f.fix_versions ?? [],
    layer_digest: f.layer_digest,
    depscore: containerDepscore(f),
    description: f.description,
    rule_doc_url: f.rule_doc_url,
    container_fingerprint: f.container_fingerprint,
    reachability_level: f.reachability_level ?? null,
    reachability_details: f.reachability_details ?? null,
  }));

  let inserted = 0;
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    const { error } = await supabase
      .from('project_container_findings')
      .upsert(batch, {
        onConflict:
          'project_id,image_digest,os_package_name,os_package_version,vulnerability_id,extraction_run_id',
      });
    if (error) {
      throw new Error(`upsertContainerFindings batch ${i}: ${error.message}`);
    }
    inserted += batch.length;
  }
  return { inserted, staleDeleted: 0 };
}

// ============================================================================
// project_native_bindings — SONAME bridge rows (Item G)
// ============================================================================
// Two scopes share one table:
//   'language' — Python wheel / Node native module → DT_NEEDED soname.
//   'os'       — dpkg-managed binary's own DT_SONAME.
// composition.ts pairs them on `soname` to derive PCF↔PDV edges.

type NativeBindingScope = 'language' | 'os';
type NativeBindingLinkMethod =
  | 'elf_needed'
  | 'dpkg_soname'
  | 'elf_dlopen'
  | 'ctypes_grep'
  | 'apk_provided'
  | 'rpm_provided';

export interface NativeBindingInsert {
  scope: NativeBindingScope;
  package_identifier: string;
  package_ecosystem: string | null;
  soname: string;
  install_path: string;
  link_method: NativeBindingLinkMethod;
}

interface NativeBindingRow extends Record<string, unknown> {
  project_id: string;
  extraction_run_id: string;
  scope: NativeBindingScope;
  package_identifier: string;
  package_ecosystem: string | null;
  soname: string;
  install_path: string;
  link_method: NativeBindingLinkMethod;
  extractor_version: string;
}

/**
 * Bulk upsert SONAME bridge rows. Tenant-derived organization_id is set
 * by the `project_native_bindings_enforce_org_id` trigger from projects.
 */
export async function upsertNativeBindings(
  supabase: SupabaseClient,
  projectId: string,
  runId: string,
  bindings: NativeBindingInsert[],
  extractorVersion = 'v1'
): Promise<UpsertResult> {
  if (bindings.length === 0) return { inserted: 0, staleDeleted: 0 };
  const rows: NativeBindingRow[] = bindings.map((b) => ({
    project_id: projectId,
    extraction_run_id: runId,
    scope: b.scope,
    package_identifier: b.package_identifier,
    package_ecosystem: b.package_ecosystem,
    soname: b.soname,
    // empty string sentinel — see migration comment in phase30
    install_path: b.install_path ?? '',
    link_method: b.link_method,
    extractor_version: extractorVersion,
  }));
  let inserted = 0;
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    const { error } = await supabase
      .from('project_native_bindings')
      .upsert(batch, {
        onConflict:
          'extraction_run_id,scope,package_identifier,soname,install_path',
      });
    if (error) {
      throw new Error(`upsertNativeBindings batch ${i}: ${error.message}`);
    }
    inserted += batch.length;
  }
  return { inserted, staleDeleted: 0 };
}

// ============================================================================
// project_base_image_recommendations — one card per Dockerfile per run
// ============================================================================

/** Row shape accepted by upsertBaseImageRecommendations — mirrors the advisor's
 *  BaseImageRecommendationRow without importing the advisor module. */
export interface BaseImageRecommendationInsert extends Record<string, unknown> {
  project_id: string;
  organization_id: string;
  extraction_run_id: string;
  dockerfile_path: string;
  current_image: string;
  current_image_digest: string | null;
  current_image_cve_count: number | null;
  recommended_image: string | null;
  recommended_image_cve_count: number | null;
  cve_delta: number | null;
  alternatives: unknown;
  shell_compat_verdict: string;
  shell_compat_evidence: unknown;
  drop_in_score: number;
}

/**
 * Upsert base-image recommendations. The unique key (project, run, dockerfile)
 * means a re-run of the same extraction replaces its prior rows; a new
 * extraction_run_id naturally supersedes the previous run's recommendations.
 */
export async function upsertBaseImageRecommendations(
  supabase: SupabaseClient,
  rows: BaseImageRecommendationInsert[]
): Promise<UpsertResult> {
  if (rows.length === 0) return { inserted: 0, staleDeleted: 0 };
  let inserted = 0;
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    const { error } = await supabase
      .from('project_base_image_recommendations')
      .upsert(batch, { onConflict: 'project_id,extraction_run_id,dockerfile_path' });
    if (error) {
      throw new Error(`upsertBaseImageRecommendations batch ${i}: ${error.message}`);
    }
    inserted += batch.length;
  }
  return { inserted, staleDeleted: 0 };
}

// ============================================================================
// container_image_scan_cache — global digest-keyed result cache (M7)
//
// Lookup is read-only and gated by:
//   1. Composite-PK match: (image_digest, scanner, scanner_version,
//      trivy_db_version_day). All four columns are equality-filtered; PGLite's
//      Storage abstraction only supports eq/in, so freshness is checked in JS.
//   2. 7-day TTL on `scanned_at` (cache rows live up to 30d via the reaper, but
//      we only trust them for 7d so the Trivy CVE DB stays current).
//   3. SHA-256 integrity check on scan_results vs. the column's stored hash —
//      a mismatch logs `cache_integrity_mismatch` and surfaces as a miss so
//      DB-level corruption can never leak into a project's findings table.
//
// Upsert uses ON CONFLICT DO NOTHING (`ignoreDuplicates: true`) so concurrent
// orgs that simultaneously miss the cache and write the same key don't clobber
// each other — and so first_scanned_by_org_id / first_scanned_run_id keep the
// initial-writer attribution they were inserted with.
//
// Truncation: scan_results is bounded by a Postgres CHECK at 1 MB. If the
// findings array would serialize larger, the row is NOT cached at all — a
// partial result must never be served to other orgs as if it were complete.
// `truncateFindingsToFit` still exists to detect the over-budget case; the
// caller logs `cache_row_truncated_skip` and skips the write.
// ============================================================================

export type ContainerCacheScanner = 'trivy';

export interface ContainerScanCacheKey {
  /** Bare 64-hex digest (no `sha256:` prefix, no `<repo>@` prefix) — produced
   *  by normalizeDigest() in trivy.ts. The CHECK constraint also accepts an
   *  optional `+linux/amd64` suffix for manifest-list resolution. */
  image_digest: string;
  scanner: ContainerCacheScanner;
  scanner_version: string;
  /** UTC YYYY-MM-DD; the Trivy CVE DB version-day captured at scan time. */
  trivy_db_version_day: string;
}

export interface ContainerScanCacheHit {
  findings: ContainerFinding[];
  scanner_version: string;
}

interface ContainerScanCacheRow extends Record<string, unknown> {
  image_digest: string;
  scanner: ContainerCacheScanner;
  scanner_version: string;
  trivy_db_version_day: string;
  scan_results: ContainerFinding[];
  scan_results_hash: string;
  first_scanned_by_org_id: string | null;
  first_scanned_run_id: string | null;
}

const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_CACHE_BYTES = 1_048_576;
// Postgres's JSONB-to-text cast inserts `: ` after keys and `, ` between items,
// expanding the byte count vs. JSON.stringify. We budget 100 KB of headroom so
// that anything that fits the in-memory limit also fits the column's CHECK on
// octet_length(scan_results::text).
const EFFECTIVE_MAX_BYTES = MAX_CACHE_BYTES - 100_000;

/** Severity rank used for truncation ordering. Higher = kept first. */
function severityRank(severity: string | null | undefined): number {
  switch ((severity ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 5;
    case 'HIGH':
      return 4;
    case 'MEDIUM':
      return 3;
    case 'LOW':
      return 2;
    case 'INFO':
      return 1;
    default:
      return 0;
  }
}

/** Recursive key-sort so JSON.stringify is byte-stable across runs. The hash
 *  has to round-trip Postgres → Node, so any property-order drift would manifest
 *  as a false `cache_integrity_mismatch`.
 *
 *  Skips properties whose value is `undefined` to match `JSON.stringify` /
 *  Postgres JSONB semantics (both drop undefined). Without this guard, a future
 *  parser that emits `field: undefined` (instead of `field: null`) would
 *  produce a write-side hash that includes `"field":undefined` while the
 *  read-side rebuilds the object without the field, hashes differently, and
 *  every read of that row trips integrity-mismatch.
 */
function canonicalJson(value: unknown): string {
  if (value === undefined) return JSON.stringify(null); // unreachable at top, defensive
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => (v === undefined ? 'null' : canonicalJson(v))).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

export function computeScanResultsHash(findings: ContainerFinding[]): string {
  return createHash('sha256').update(canonicalJson(findings), 'utf8').digest('hex');
}

/** Trims `findings` to fit within MAX_CACHE_BYTES of JSON.stringify output by
 *  dropping the lowest-severity tail first. Returns the (possibly identical)
 *  array plus a flag the caller can log against. */
export function truncateFindingsToFit(
  findings: ContainerFinding[]
): { findings: ContainerFinding[]; truncated: boolean } {
  const initial = JSON.stringify(findings);
  if (Buffer.byteLength(initial, 'utf8') <= EFFECTIVE_MAX_BYTES) {
    return { findings, truncated: false };
  }
  // Stable sort: severity desc, then index asc so equal-severity rows keep
  // their incoming order.
  const sorted = [...findings]
    .map((f, i) => ({ f, i }))
    .sort((a, b) => severityRank(b.f.severity) - severityRank(a.f.severity) || a.i - b.i)
    .map((x) => x.f);

  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = Math.floor((lo + hi + 1) / 2);
    const candidate = JSON.stringify(sorted.slice(0, mid));
    if (Buffer.byteLength(candidate, 'utf8') <= EFFECTIVE_MAX_BYTES) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  return { findings: sorted.slice(0, lo), truncated: true };
}

export async function lookupContainerScanCache(
  supabase: SupabaseClient,
  key: ContainerScanCacheKey
): Promise<ContainerScanCacheHit | null> {
  const { data, error } = await supabase
    .from('container_image_scan_cache')
    .select('image_digest, scanner, scanner_version, trivy_db_version_day, scan_results, scan_results_hash, scanned_at')
    .eq('image_digest', key.image_digest)
    .eq('scanner', key.scanner)
    .eq('scanner_version', key.scanner_version)
    .eq('trivy_db_version_day', key.trivy_db_version_day)
    .maybeSingle();

  if (error) {
    throw new Error(`lookupContainerScanCache: ${error.message}`);
  }
  if (!data) {
    return null;
  }

  const row = data as {
    scan_results: ContainerFinding[];
    scan_results_hash: string;
    scanner_version: string;
    scanned_at: string;
  };

  // 7-day TTL — checked here rather than via .gte() so PGLite (eq/in only) is
  // a drop-in for tests.
  const scannedAtMs = new Date(row.scanned_at).getTime();
  if (Number.isNaN(scannedAtMs) || Date.now() - scannedAtMs > CACHE_TTL_MS) {
    return null;
  }

  const expectedHash = computeScanResultsHash(row.scan_results);
  if (expectedHash !== row.scan_results_hash) {
    console.warn(
      `cache_integrity_mismatch digest=${key.image_digest} scanner=${key.scanner} ` +
        `version=${key.scanner_version} day=${key.trivy_db_version_day} ` +
        `expected=${expectedHash} stored=${row.scan_results_hash}`
    );
    return null;
  }

  return { findings: row.scan_results, scanner_version: row.scanner_version };
}

export async function upsertContainerScanCache(
  supabase: SupabaseClient,
  key: ContainerScanCacheKey,
  parsedFindings: ContainerFinding[],
  orgId: string,
  runId: string
): Promise<void> {
  const { findings, truncated } = truncateFindingsToFit(parsedFindings);
  if (truncated) {
    // A truncated row is a partial scan result. Writing it would silently
    // serve the lossy subset to every other org that later hits this digest,
    // with no signal that findings were dropped. There is no DB column to
    // flag the row as partial, so we simply don't cache it — subsequent orgs
    // become a clean cache miss and run their own full Trivy scan.
    console.warn(
      `cache_row_truncated_skip digest=${key.image_digest} ` +
        `original=${parsedFindings.length} would_keep=${findings.length} — not caching`
    );
    return;
  }

  const row: ContainerScanCacheRow = {
    image_digest: key.image_digest,
    scanner: key.scanner,
    scanner_version: key.scanner_version,
    trivy_db_version_day: key.trivy_db_version_day,
    scan_results: findings,
    scan_results_hash: computeScanResultsHash(findings),
    first_scanned_by_org_id: orgId,
    first_scanned_run_id: runId,
  };

  // ON CONFLICT DO NOTHING preserves first_scanned_* attribution and is safe
  // under concurrent cache-miss writes from different orgs.
  const { error } = await supabase
    .from('container_image_scan_cache')
    .upsert(row, {
      onConflict: 'image_digest,scanner,scanner_version,trivy_db_version_day',
      ignoreDuplicates: true,
    });
  if (error) {
    throw new Error(`upsertContainerScanCache: ${error.message}`);
  }
}
