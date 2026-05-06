/**
 * GHSA `vulnerableVersionRange` resolver.
 *
 * GHSA returns range expressions like `= 2.10.1`, `>= 0`, `< 2.0.0`,
 * `>= 1.0, < 2.0`. v1 collapsed every range to `version=null` (= "all
 * versions") which over-flagged every package version once any single
 * version had been advised against. v2 expands the range to a concrete
 * version set at sync time so the worker can match feed rows to the
 * project's actual installed version.
 *
 * Per-ecosystem strategies:
 *   - npm:      pacote packument + semver.satisfies         (full)
 *   - pypi:     PyPI JSON API + PEP 440 prefix-comparator   (full)
 *   - rubygems: rubygems.org API + version comparator       (best-effort)
 *   - maven:    parse-only (exact `=` returns one version)  (best-effort)
 *   - golang:   parse-only (exact `=` returns one version)  (best-effort)
 *
 * Anything we can't expand falls back to `null` and the caller writes a
 * single row with `version=null`. This is strictly safer than dropping
 * the advisory.
 */
import type { CanonicalEcosystem } from '../ecosystem';
import { resolveNpmRange } from './npm';
import { resolvePypiRange } from './pypi';
import { resolveRubygemsRange } from './rubygems';
import { resolveMavenRange } from './maven';
import { resolveGolangRange } from './golang';

/** A single parsed constraint (e.g. `>= 1.2.3`). */
export interface RangeConstraint {
  op: '=' | '>' | '>=' | '<' | '<=';
  version: string;
}

/** AND-combined constraints. e.g. `>= 1.0, < 2.0` parses to two constraints. */
export type ParsedRange = RangeConstraint[];

/**
 * Parse a GHSA `vulnerableVersionRange` string into AND-combined constraints.
 * Returns null when the shape is unrecognised (caller falls back to version=null).
 *
 * Recognised shapes:
 *   - `2.10.1`              → [{ op:'=', version:'2.10.1' }]
 *   - `= 2.10.1`            → [{ op:'=', version:'2.10.1' }]
 *   - `< 2.0.0`             → [{ op:'<', version:'2.0.0' }]
 *   - `>= 1.0, < 2.0`       → [>=1.0, <2.0]
 *   - `>= 0`                → [{ op:'>=', version:'0' }]
 */
export function parseGhsaRange(raw: string): ParsedRange | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;

  // Bare version like `2.10.1` (no operator) → exact match
  if (/^[\w.+-]+$/.test(trimmed) && !/^[<>=]/.test(trimmed)) {
    return [{ op: '=', version: trimmed }];
  }

  const parts = trimmed.split(',').map((p) => p.trim()).filter(Boolean);
  const out: ParsedRange = [];
  for (const part of parts) {
    const match = part.match(/^(>=|<=|>|<|=)\s*([\w.+-]+)$/);
    if (!match) return null;
    out.push({ op: match[1] as RangeConstraint['op'], version: match[2] });
  }
  return out.length === 0 ? null : out;
}

/**
 * Resolve a GHSA range to a concrete version array for the given (ecosystem,
 * package). Returns `null` if the range is unparseable or the ecosystem
 * resolver can't enumerate versions — caller writes a single `version=null`
 * row instead of dropping the advisory.
 *
 * `cache` is a per-sync-run shared map so we don't refetch the same packument
 * for the 12th typosquat advisory targeting `lodash` in the same run.
 */
export async function resolveVulnerableRange(
  ecosystem: CanonicalEcosystem,
  packageName: string,
  range: string,
  cache: PackumentCache,
): Promise<string[] | null> {
  const parsed = parseGhsaRange(range);
  if (!parsed) {
    console.warn(`[version-range] unparseable ${ecosystem} range for ${packageName}: ${JSON.stringify(range)}`);
    return null;
  }

  // Exact-match shortcut: every ecosystem can answer `= X.Y.Z` without a
  // registry call.
  if (parsed.length === 1 && parsed[0].op === '=') {
    return [parsed[0].version];
  }

  try {
    switch (ecosystem) {
      case 'npm':      return await resolveNpmRange(packageName, parsed, cache);
      case 'pypi':     return await resolvePypiRange(packageName, parsed, cache);
      case 'rubygems': return await resolveRubygemsRange(packageName, parsed, cache);
      case 'maven':    return await resolveMavenRange(packageName, parsed, cache);
      case 'golang':   return await resolveGolangRange(packageName, parsed, cache);
      default:         return null;
    }
  } catch (err: any) {
    console.warn(`[version-range] ${ecosystem}/${packageName} ${range}: ${err?.message ?? err}`);
    return null;
  }
}

/** Per-sync-run version-list cache, keyed by `${ecosystem}\x00${packageName}`. */
export type PackumentCache = Map<string, Promise<string[] | null>>;

export function makePackumentCache(): PackumentCache {
  return new Map();
}

export function packumentCacheKey(ecosystem: CanonicalEcosystem, packageName: string): string {
  return `${ecosystem}\x00${packageName}`;
}
