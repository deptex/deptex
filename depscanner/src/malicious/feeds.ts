/**
 * Feed lookup against `known_malicious_packages`.
 *
 * Cheap, network-free (just a DB query) — runs first so we don't pay for a
 * tarball download on packages already known-malicious. A hit becomes a
 * `scanner='feed'` finding with severity `critical`.
 */
import { satisfies as semverSatisfies, validRange as semverValidRange } from 'semver';
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
  // normalize the casing here. A colon-joined scan name matches the feed
  // `.eq()` exactly; a bare artifactId is handled by the N6 fallback below.
  if (canonical === 'maven') {
    canonicalName = canonicalName.trim();
  }

  const { data, error } = await supabase
    .from('known_malicious_packages')
    .select('source, source_id, severity, description, version, vulnerable_range, withdrawn_at')
    .eq('package_name', canonicalName)
    .eq('ecosystem', canonical);

  if (error || !data) return [];

  let rows = data as FeedRow[];

  // N6 — Maven bare-artifactId fallback. cdxgen sometimes emits a Maven dep
  // as just `artifactId` (no `groupId`), but advisories store the full
  // `groupId:artifactId` coordinate, so the exact query above misses them.
  // Only run when the exact query found nothing and the scan name is a bare
  // artifactId (no colon). `lookupMavenBareArtifact` resolves matches whose
  // coordinate ends with `:artifactId` and only returns them when the
  // artifactId is GLOBALLY UNIQUE in the feed (single groupId) — a bare `core`
  // must not inherit every `*:core` advisory.
  if (canonical === 'maven' && rows.length === 0 && !canonicalName.includes(':')) {
    rows = await lookupMavenBareArtifact(supabase, canonicalName);
  }

  const hits: FeedHit[] = [];
  for (const row of rows) {
    if (row.withdrawn_at) continue;

    // N4 — semver RANGE match. Scoped to npm: semver is the one range grammar
    // the worker evaluates correctly. Fires ONLY when the row carries a
    // populated, VALID range AND we know the installed version. A malformed /
    // unparseable range is treated as NO match (never match-all). Range rows
    // are written with version=null, so they are evaluated solely by the range.
    if (canonical === 'npm' && row.vulnerable_range && version) {
      const range = row.vulnerable_range.trim();
      if (!range || !semverValidRange(range)) continue; // malformed → skip, never flag-all
      const installed = normalizeVersionForCompare(version, canonical) ?? version.trim();
      let satisfied = false;
      try {
        satisfied = semverSatisfies(installed, range, { includePrerelease: true });
      } catch {
        satisfied = false;
      }
      if (satisfied) {
        hits.push({
          source: row.source,
          source_id: row.source_id,
          severity: (row.severity as FeedHit['severity']) ?? 'critical',
          description: row.description,
        });
      }
      continue;
    }

    // Precision-first EXACT-version matching: only flag when we can positively
    // confirm the INSTALLED version equals a known-malicious version. A feed
    // row with NEITHER a concrete version NOR a (npm) range ("flag every
    // version of this name") cannot confirm that, so it falls through here and
    // is DROPPED — otherwise a clean install of a package whose one bad version
    // was briefly compromised (e.g. the Sept-2025 npm worm: chalk@5.6.1) gets a
    // name-only CRITICAL on chalk@5.6.2. Genuine version-specific malware still
    // matches via the concrete-version rows the GHSA resolver writes at sync
    // time (or the npm range rows above); guarddog's tarball scan is the
    // backstop for all-versions typosquats.
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

/** Row shape selected from `known_malicious_packages` for matching. */
interface FeedRow {
  source: 'osv' | 'ghsa';
  source_id: string;
  severity: string | null;
  description: string | null;
  version: string | null;
  vulnerable_range: string | null;
  withdrawn_at: string | null;
  /** Only selected by the Maven bare-artifactId fallback (for disambiguation). */
  package_name?: string;
}

// Safety bound on the Maven suffix query. If the feed returns this many rows
// for a bare artifactId we can't prove the artifactId is globally unique
// (the set may be truncated), so we conservatively decline to match.
const MAVEN_SUFFIX_LIMIT = 50;

/**
 * Resolve a bare Maven `artifactId` against `groupId:artifactId` advisory rows.
 *
 * Returns the matching rows ONLY when the artifactId maps to a single groupId
 * in the feed (globally unique) — otherwise it returns `[]` to avoid attaching
 * one group's advisory to a different group's artifact (cross-group FP). The
 * `LIKE` query is a coarse pre-filter; an authoritative literal `:artifactId`
 * suffix check in JS guarantees backend (PostgREST) vs PGLite wildcard-escaping
 * differences can never widen the match.
 */
async function lookupMavenBareArtifact(
  supabase: Storage,
  artifactId: string,
): Promise<FeedRow[]> {
  const pattern = `%:${escapeLikePattern(artifactId)}`;
  const { data, error } = await supabase
    .from('known_malicious_packages')
    .select('source, source_id, severity, description, version, vulnerable_range, withdrawn_at, package_name')
    .eq('ecosystem', 'maven')
    .like('package_name', pattern)
    .limit(MAVEN_SUFFIX_LIMIT);
  if (error || !data) return [];

  const all = data as FeedRow[];
  // Possibly truncated → can't prove global uniqueness → decline (safe FN).
  if (all.length >= MAVEN_SUFFIX_LIMIT) return [];

  const suffix = `:${artifactId}`;
  const matched = all.filter(
    (r) => typeof r.package_name === 'string' && r.package_name.endsWith(suffix),
  );
  if (matched.length === 0) return [];

  // Cross-group guard: only safe when every match shares one coordinate.
  const distinctCoords = new Set(matched.map((r) => r.package_name));
  if (distinctCoords.size !== 1) return [];

  return matched;
}

/**
 * Escape SQL `LIKE` wildcards so an artifactId containing `_`, `%`, or `\`
 * (underscore is a legal Maven artifactId char) is matched literally.
 * Backslash is the default PostgreSQL `LIKE` escape character.
 */
function escapeLikePattern(s: string): string {
  return s.replace(/[\\%_]/g, (ch) => `\\${ch}`);
}
