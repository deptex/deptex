/**
 * RubyGems version-range resolver: rubygems.org versions API + RubyGems
 * version comparator.
 *
 * RubyGems uses semver-ish dotted versions with optional pre-release labels
 * separated by `.` or `-` (e.g. `1.2.3.beta1`, `1.2.3-rc.1`). For the GHSA
 * shapes we see in practice (almost always plain `X.Y.Z` or `X.Y`) a numeric
 * dot-segment compare with pre-release tail handling matches the official
 * Gem::Version semantics.
 */
import type { ParsedRange, PackumentCache } from './index';
import { packumentCacheKey } from './index';

export async function resolveRubygemsRange(
  packageName: string,
  parsed: ParsedRange,
  cache: PackumentCache,
): Promise<string[] | null> {
  const versions = await fetchVersions(packageName, cache);
  if (!versions) return null;
  return versions.filter((v) => satisfiesAll(v, parsed));
}

async function fetchVersions(
  packageName: string,
  cache: PackumentCache,
): Promise<string[] | null> {
  const key = packumentCacheKey('rubygems', packageName);
  let pending = cache.get(key);
  if (!pending) {
    pending = (async () => {
      try {
        const res = await fetch(`https://rubygems.org/api/v1/versions/${encodeURIComponent(packageName)}.json`, {
          headers: { 'User-Agent': 'Deptex-App' },
        });
        if (!res.ok) return null;
        const json = (await res.json()) as any;
        if (!Array.isArray(json)) return null;
        return json.map((row: any) => row.number).filter((v: any): v is string => typeof v === 'string');
      } catch {
        return null;
      }
    })();
    cache.set(key, pending);
  }
  return pending;
}

function satisfiesAll(version: string, parsed: ParsedRange): boolean {
  for (const c of parsed) {
    const cmp = compareGem(version, c.version);
    if (cmp === null) return false;
    if (c.op === '='  && cmp !== 0) return false;
    if (c.op === '>'  && cmp <= 0) return false;
    if (c.op === '>=' && cmp < 0) return false;
    if (c.op === '<'  && cmp >= 0) return false;
    if (c.op === '<=' && cmp > 0) return false;
  }
  return true;
}

/**
 * Gem::Version-style compare. Normalises pre-release separators to `.`,
 * splits on `.`, then segment-by-segment compares numerics-as-numbers and
 * strings-as-strings (with strings sorting before numerics — RubyGems
 * convention so `1.0.0.alpha` < `1.0.0`).
 */
function compareGem(a: string, b: string): number | null {
  const sa = segment(a);
  const sb = segment(b);
  if (!sa || !sb) return null;
  const max = Math.max(sa.length, sb.length);
  for (let i = 0; i < max; i++) {
    // Missing trailing segments imply 0 (numeric) or absent pre-release tail.
    const ai = sa[i];
    const bi = sb[i];
    if (ai === undefined && bi === undefined) return 0;
    if (ai === undefined) {
      // a runs out first. If b's next is a string (pre-release), b is older.
      return typeof bi === 'string' ? 1 : -1;
    }
    if (bi === undefined) {
      return typeof ai === 'string' ? -1 : 1;
    }
    if (typeof ai === 'number' && typeof bi === 'number') {
      if (ai !== bi) return ai < bi ? -1 : 1;
    } else if (typeof ai === 'string' && typeof bi === 'string') {
      if (ai !== bi) return ai < bi ? -1 : 1;
    } else {
      // Mixed: string sorts before number (pre-release < release).
      return typeof ai === 'string' ? -1 : 1;
    }
  }
  return 0;
}

function segment(version: string): Array<number | string> | null {
  const trimmed = version.trim().replace(/-/g, '.');
  if (!trimmed) return null;
  return trimmed.split('.').map((s) => {
    if (/^\d+$/.test(s)) return parseInt(s, 10);
    return s.toLowerCase();
  });
}
