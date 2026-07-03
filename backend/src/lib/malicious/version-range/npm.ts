/**
 * npm version-range resolver: pacote packument + semver.satisfies.
 *
 * Translates the parsed GHSA constraint list into a semver range string and
 * filters the package's published versions against it.
 */
import * as pacote from 'pacote';
import semver from 'semver';
import type { ParsedRange, PackumentCache } from './index';
import { packumentCacheKey } from './index';

export async function resolveNpmRange(
  packageName: string,
  parsed: ParsedRange,
  cache: PackumentCache,
): Promise<string[] | null> {
  const semverRange = parsedToSemver(parsed);
  if (!semverRange) return null;

  const versions = await fetchVersions(packageName, cache);
  if (!versions) return null;

  return versions.filter((v) => {
    try {
      return semver.satisfies(v, semverRange, { includePrerelease: true });
    } catch {
      return false;
    }
  });
}

async function fetchVersions(
  packageName: string,
  cache: PackumentCache,
): Promise<string[] | null> {
  const key = packumentCacheKey('npm', packageName);
  let pending = cache.get(key);
  if (!pending) {
    pending = (async () => {
      try {
        const packument = (await pacote.packument(packageName, { fullMetadata: false } as any)) as any;
        return Object.keys(packument?.versions ?? {});
      } catch {
        return null;
      }
    })();
    cache.set(key, pending);
  }
  return pending;
}

/**
 * Convert a parsed GHSA range to a `semver`-compatible range string
 * (space = AND, e.g. `>=1.0.0 <2.0.0`). Exported so the feed-sync write side
 * can store the range on `known_malicious_packages.vulnerable_range` (N4)
 * instead of enumerating concrete npm versions. Returns null when any
 * constraint can't be coerced to a valid semver.
 */
export function parsedToSemver(parsed: ParsedRange): string | null {
  const parts: string[] = [];
  for (const c of parsed) {
    if (!semver.valid(semver.coerce(c.version))) {
      // GHSA occasionally emits non-semver values (`0`, `latest`, etc.).
      // semver.coerce normalises `0` → `0.0.0` and `1.2` → `1.2.0`.
      const coerced = semver.coerce(c.version);
      if (!coerced) return null;
      parts.push(c.op === '=' ? coerced.version : `${c.op}${coerced.version}`);
    } else {
      parts.push(c.op === '=' ? c.version : `${c.op}${c.version}`);
    }
  }
  return parts.join(' ');
}
