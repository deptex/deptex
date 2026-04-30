/**
 * Ecosystem name canonicalization for the malicious-packages feature.
 *
 * Inputs come from four shapes:
 *   - OSV.dev (mixed case, e.g. `npm`, `PyPI`, `Go`, `RubyGems`, `GitHub Actions`)
 *   - GHSA enum (uppercase, e.g. `NPM`, `PIP`, `MAVEN`, `GO`, `RUBYGEMS`)
 *   - GuardDog flags (lowercase, e.g. `npm`, `pypi`, `maven`, `go`, `rubygems`,
 *     `github-action`, `vscode`)
 *   - Deptex-internal `dependencies.ecosystem` (lowercase, e.g. `npm`, `pypi`,
 *     `maven`, `golang`, `gem`)
 *
 * Output is the canonical lowercase string enforced by the CHECK constraint
 * on `known_malicious_packages.ecosystem` and `package_security_cache.ecosystem`.
 */

export type CanonicalEcosystem =
  | 'npm'
  | 'pypi'
  | 'maven'
  | 'golang'
  | 'rubygems'
  | 'github-actions'
  | 'vscode';

export const CANONICAL_ECOSYSTEMS: readonly CanonicalEcosystem[] = [
  'npm',
  'pypi',
  'maven',
  'golang',
  'rubygems',
  'github-actions',
  'vscode',
] as const;

const ALIASES: Record<string, CanonicalEcosystem> = {
  // npm
  npm: 'npm',
  // pypi
  pypi: 'pypi',
  pip: 'pypi',
  // maven
  maven: 'maven',
  // golang
  golang: 'golang',
  go: 'golang',
  // rubygems  (Deptex-internal `gem` maps here; OSV `RubyGems` and GHSA `RUBYGEMS` lowercase to `rubygems`)
  rubygems: 'rubygems',
  gem: 'rubygems',
  // github-actions (GuardDog ships `github-action` singular; OSV uses `GitHub Actions` plural)
  'github-actions': 'github-actions',
  'github-action': 'github-actions',
  'github actions': 'github-actions',
  // vscode
  vscode: 'vscode',
};

/**
 * Canonicalize an ecosystem name from any source. Returns `null` when the
 * input is not recognised — callers should skip / log unrecognised inputs
 * rather than silently writing them.
 */
export function canonicalizeEcosystem(raw: string | null | undefined): CanonicalEcosystem | null {
  if (!raw) return null;
  const key = raw.trim().toLowerCase();
  return ALIASES[key] ?? null;
}

/** Type guard for canonical values. */
export function isCanonicalEcosystem(value: string): value is CanonicalEcosystem {
  return (CANONICAL_ECOSYSTEMS as readonly string[]).includes(value);
}
