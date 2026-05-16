/**
 * Feed lookup against `known_malicious_packages`.
 *
 * Cheap, network-free (just a DB query) — runs first so we don't pay for a
 * tarball download on packages already known-malicious. A hit becomes a
 * `scanner='feed'` finding with severity `critical`.
 */
import type { Storage } from '../storage';
import {
  canonicalizeEcosystem,
  canonicalizePackageName,
  type CanonicalEcosystem,
} from './ecosystem';

/**
 * Normalize a version string for cross-source equality comparison.
 *
 * Feed-side versions (OSV/GHSA/registry) and scan-side versions (cdxgen
 * SBOM) routinely differ in normalization: a leading `v`, build metadata
 * (`+build`), PEP 440 `1.0` vs `1.0.0`, Maven `.RELEASE` casing. A raw
 * string `!==` therefore silently fails to flag a known-malicious package.
 *
 * Returns `null` when the input can't be coerced to a comparable form —
 * the caller treats `null` on either side as "can't decide, flag anyway"
 * so a parse failure never causes a false negative.
 */
export function normalizeVersionForCompare(
  raw: string,
  ecosystem: CanonicalEcosystem,
): string | null {
  let v = raw.trim();
  if (!v) return null;
  // Strip a single leading `v`/`V` (npm tags, Go module versions).
  v = v.replace(/^[vV](?=\d)/, '');
  // Strip build metadata (`+sha`, `+build123`) — never part of identity.
  const plus = v.indexOf('+');
  if (plus >= 0) v = v.slice(0, plus);
  v = v.trim();
  if (!v) return null;

  switch (ecosystem) {
    case 'npm':
    case 'cargo': {
      // semver: coerce to `major.minor.patch[-prerelease]`. Extract the
      // first three numeric segments; keep a `-prerelease` tail if present.
      const m = v.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-.]([0-9A-Za-z.-]+))?/);
      if (!m) return null;
      const core = `${m[1]}.${m[2] ?? '0'}.${m[3] ?? '0'}`;
      return m[4] ? `${core}-${m[4].toLowerCase()}` : core;
    }
    case 'pypi': {
      // PEP 440 normalization: lowercase, collapse separators in the
      // pre/post/dev suffix, drop a leading epoch's `!` only after the
      // numeric release. We do a pragmatic normalize: lowercase, strip
      // leading zeros per release segment, and pad the release to 3
      // segments so `1.0` == `1.0.0`.
      const lower = v.toLowerCase();
      const relMatch = lower.match(/^(\d+(?:\.\d+)*)(.*)$/);
      if (!relMatch) return null;
      const segs = relMatch[1].split('.').map((s) => String(parseInt(s, 10)));
      while (segs.length < 3) segs.push('0');
      const suffix = relMatch[2].replace(/[-_]/g, '').replace(/\s+/g, '');
      return segs.join('.') + suffix;
    }
    case 'maven': {
      // Maven versions are case-insensitive on the qualifier (`.RELEASE`
      // vs `.release`); normalize case and treat `-`/`.` as equivalent
      // separators between the numeric core and the qualifier.
      return v.toLowerCase().replace(/[-_]/g, '.');
    }
    default:
      // golang/rubygems/composer/nuget/github-actions: lowercase only.
      return v.toLowerCase();
  }
}

export interface FeedHit {
  source: 'osv' | 'ghsa';
  source_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  description: string | null;
}

export async function lookupFeed(
  supabase: Storage,
  packageName: string,
  ecosystem: string,
  version: string | null,
): Promise<FeedHit[]> {
  const canonical = canonicalizeEcosystem(ecosystem);
  if (!canonical) return [];

  // Canonicalize package_name on the read path so a GHSA advisory for
  // `Django` (mixed case, written canonically as `django` per PEP 503)
  // matches an installed `django` from cdxgen. MUST stay in sync with
  // feed-sync's write-side canonicalization in advisoryToEntries.
  let canonicalName = canonicalizePackageName(packageName, canonical);

  // Maven: advisories use `groupId:artifactId`, but cdxgen sometimes emits
  // a bare `artifactId`. canonicalizePackageName is identity for maven, so
  // normalize the casing here. When the scan side has a colon-joined name
  // we can match the feed `.eq()` exactly; when it only has the bare
  // artifactId there is no groupId to reconstruct — that lookup will miss
  // (known limitation: a bare-artifactId Maven dep can't be feed-matched).
  if (canonical === 'maven') {
    canonicalName = canonicalName.trim();
  }

  const { data, error } = await supabase
    .from('known_malicious_packages')
    .select('source, source_id, severity, description, version, withdrawn_at')
    .eq('package_name', canonicalName)
    .eq('ecosystem', canonical);

  if (error || !data) return [];

  const hits: FeedHit[] = [];
  for (const row of data as Array<{
    source: 'osv' | 'ghsa';
    source_id: string;
    severity: string | null;
    description: string | null;
    version: string | null;
    withdrawn_at: string | null;
  }>) {
    if (row.withdrawn_at) continue;
    // version=null in feed → covers all versions of this package.
    // Feed-side and scan-side versions are normalized per-ecosystem before
    // comparison (leading `v`, build metadata, PEP 440 padding, Maven
    // qualifier casing all differ across sources). If either side fails to
    // normalize we FLAG rather than skip — a parse failure must never cause
    // a silent false negative for a known-malicious package.
    if (row.version && version) {
      const feedNorm = normalizeVersionForCompare(row.version, canonical);
      const scanNorm = normalizeVersionForCompare(version, canonical);
      if (feedNorm !== null && scanNorm !== null && feedNorm !== scanNorm) {
        continue;
      }
    }
    hits.push({
      source: row.source,
      source_id: row.source_id,
      severity: (row.severity as FeedHit['severity']) ?? 'critical',
      description: row.description,
    });
  }
  return hits;
}
