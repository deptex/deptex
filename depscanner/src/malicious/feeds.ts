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
 * Returns `null` when the input can't be coerced to a comparable form. The
 * caller then falls back to a raw-string comparison and still requires
 * equality — under the precision-first policy we only flag on a positive
 * version match, never on "can't decide".
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
      // semver: coerce to `major.minor.patch[-prerelease]`. Anchor the whole
      // string and only accept a `-`-delimited prerelease tail — a 4th
      // dotted numeric segment (`1.2.3.4`) is not semver, so it fails the
      // match and returns null ("flag anyway") rather than colliding with
      // `1.2.3-4`.
      const m = v.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?$/);
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
      // Maven qualifiers are case-insensitive and the separator before a
      // qualifier varies (`1.0.RELEASE` vs `1.0-RELEASE`). Lowercase, and
      // normalize only a separator that precedes an alphabetic qualifier —
      // a separator before a numeric segment is left intact so `1.0-1`
      // (build number) does not collide with `1.0.1`.
      return v.toLowerCase().replace(/[-_.]+([a-z])/g, '.$1');
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
    // Precision-first matching: only flag when we can positively confirm the
    // INSTALLED version equals a known-malicious version. A feed row with no
    // concrete version ("flag every version of this name") cannot confirm
    // that, so we DROP it — otherwise a clean install of a package whose one
    // bad version was briefly compromised (e.g. the Sept-2025 npm worm:
    // chalk@5.6.1) gets a name-only CRITICAL on chalk@5.6.2. Genuine
    // version-specific malware still matches via the concrete-version rows
    // the GHSA range resolver writes at sync time; guarddog's tarball scan is
    // the backstop for all-versions typosquats.
    if (!row.version || !version) continue;
    // Normalize per-ecosystem (leading `v`, build metadata, PEP 440 padding,
    // Maven qualifier casing all differ across sources); fall back to the raw
    // trimmed string when a side won't normalize. Flag only on equality.
    const feedNorm = normalizeVersionForCompare(row.version, canonical) ?? row.version.trim();
    const scanNorm = normalizeVersionForCompare(version, canonical) ?? version.trim();
    if (feedNorm !== scanNorm) continue;
    hits.push({
      source: row.source,
      source_id: row.source_id,
      severity: (row.severity as FeedHit['severity']) ?? 'critical',
      description: row.description,
    });
  }
  return hits;
}
