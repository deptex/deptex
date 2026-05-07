/**
 * PyPI version-range resolver: PyPI JSON API + minimal PEP 440 comparator.
 *
 * PyPI's JSON endpoint at https://pypi.org/pypi/<pkg>/json includes the full
 * `releases` map, keyed by version string. We compare each released version
 * against the GHSA-style constraints using a hand-rolled PEP 440 comparator
 * (release-segment + pre/post/dev tail). It's not a full PEP 440 implementation
 * — it covers the shapes GHSA actually emits, which is enough to differentiate
 * `1.2.3` vs `1.2.3rc1` vs `1.2.3.post1`.
 */
import type { ParsedRange, PackumentCache } from './index';
import { packumentCacheKey } from './index';

export async function resolvePypiRange(
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
  const key = packumentCacheKey('pypi', packageName);
  let pending = cache.get(key);
  if (!pending) {
    pending = (async () => {
      try {
        const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`, {
          headers: { 'User-Agent': 'Deptex-App' },
        });
        if (!res.ok) return null;
        const json = (await res.json()) as any;
        const releases = json?.releases ?? {};
        return Object.keys(releases).filter((k) => Array.isArray(releases[k]) && releases[k].length > 0);
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
    const cmp = comparePep440(version, c.version);
    if (cmp === null) return false;
    if (c.op === '='  && cmp !== 0) return false;
    if (c.op === '>'  && cmp <= 0) return false;
    if (c.op === '>=' && cmp < 0) return false;
    if (c.op === '<'  && cmp >= 0) return false;
    if (c.op === '<=' && cmp > 0) return false;
  }
  return true;
}

interface ParsedVer {
  release: number[];
  pre: [string, number] | null;   // a/b/rc + n
  post: number | null;
  dev: number | null;
}

function parsePep440(raw: string): ParsedVer | null {
  // Strip leading 'v' and an epoch prefix like '1!2.3'.
  const stripped = raw.trim().replace(/^v/i, '').replace(/^\d+!/, '');
  const m = stripped.match(/^(\d+(?:\.\d+)*)((?:a|b|rc)\d+)?(?:\.post(\d+))?(?:\.dev(\d+))?$/i);
  if (!m) {
    // fallback: still try to split numeric components for a best-effort compare
    const lead = stripped.match(/^(\d+(?:\.\d+)*)/);
    if (!lead) return null;
    return { release: lead[1].split('.').map((n) => parseInt(n, 10)), pre: null, post: null, dev: null };
  }
  const release = m[1].split('.').map((n) => parseInt(n, 10));
  let pre: [string, number] | null = null;
  if (m[2]) {
    const tag = m[2].toLowerCase();
    const num = parseInt(tag.replace(/^[a-z]+/, ''), 10);
    const kind = tag.startsWith('rc') ? 'rc' : tag.startsWith('b') ? 'b' : 'a';
    pre = [kind, num];
  }
  return {
    release,
    pre,
    post: m[3] ? parseInt(m[3], 10) : null,
    dev: m[4] ? parseInt(m[4], 10) : null,
  };
}

/**
 * Returns -1/0/1 for a < b / a == b / a > b. null when either side is unparseable.
 *
 * PEP 440 ordering (release > pre, release == post added on top):
 *   1.0.dev < 1.0a1 < 1.0b1 < 1.0rc1 < 1.0 < 1.0.post1
 */
function comparePep440(a: string, b: string): number | null {
  const va = parsePep440(a);
  const vb = parsePep440(b);
  if (!va || !vb) return null;

  // Pad release tuples to equal length with zeros.
  const max = Math.max(va.release.length, vb.release.length);
  for (let i = 0; i < max; i++) {
    const ai = va.release[i] ?? 0;
    const bi = vb.release[i] ?? 0;
    if (ai !== bi) return ai < bi ? -1 : 1;
  }

  // dev (lowest) before pre, pre before normal, normal before post.
  const aWeight = phaseWeight(va);
  const bWeight = phaseWeight(vb);
  if (aWeight !== bWeight) return aWeight < bWeight ? -1 : 1;

  if (va.pre && vb.pre) {
    if (va.pre[0] !== vb.pre[0]) return va.pre[0] < vb.pre[0] ? -1 : 1;
    if (va.pre[1] !== vb.pre[1]) return va.pre[1] < vb.pre[1] ? -1 : 1;
  }
  const ap = va.post ?? 0, bp = vb.post ?? 0;
  if (ap !== bp) return ap < bp ? -1 : 1;
  const ad = va.dev ?? 0, bd = vb.dev ?? 0;
  if (ad !== bd) return ad < bd ? -1 : 1;
  return 0;
}

function phaseWeight(v: ParsedVer): number {
  if (v.dev !== null && !v.pre && v.post === null) return 0;  // .dev
  if (v.pre) return 1;                                         // a/b/rc
  if (v.post !== null) return 3;                               // .post
  return 2;                                                     // normal
}
