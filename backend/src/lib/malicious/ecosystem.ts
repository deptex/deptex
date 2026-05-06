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
  | 'composer'
  | 'cargo'
  | 'nuget'
  | 'github-actions'
  | 'vscode';

export const CANONICAL_ECOSYSTEMS: readonly CanonicalEcosystem[] = [
  'npm',
  'pypi',
  'maven',
  'golang',
  'rubygems',
  'composer',
  'cargo',
  'nuget',
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
  // composer (PHP) — packagist.org. v2-added for capability detector parity.
  composer: 'composer',
  packagist: 'composer',
  php: 'composer',
  // cargo (Rust) — crates.io.
  cargo: 'cargo',
  rust: 'cargo',
  'crates.io': 'cargo',
  // nuget (C# / .NET).
  nuget: 'nuget',
  csharp: 'nuget',
  dotnet: 'nuget',
  '.net': 'nuget',
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

/**
 * Canonicalize a package name for cross-source matching against
 * `known_malicious_packages`.
 *
 * MUST run on BOTH the write path (feed-sync writing advisory rows) AND the
 * read path (feeds.ts looking up an installed package) — otherwise GHSA's
 * mixed-case names (`Django`, `Flask`, `Pillow`) silently miss installed
 * packages whose SBOM-extracted names are lowercase.
 *
 * Per-ecosystem normalization rules (the safe over-match direction —
 * applying the same transform on both sides preserves the equality):
 *   - pypi: PEP 503 — lowercase + collapse `[-_.]+` to `-`
 *   - npm, nuget, composer, cargo, vscode: lowercase (registry-canonical form)
 *   - maven, golang, rubygems, github-actions: case-sensitive — preserve
 */
export function canonicalizePackageName(
  name: string,
  ecosystem: CanonicalEcosystem,
): string {
  switch (ecosystem) {
    case 'pypi':
      return name.toLowerCase().replace(/[-_.]+/g, '-');
    case 'npm':
    case 'nuget':
    case 'composer':
    case 'cargo':
    case 'vscode':
      return name.toLowerCase();
    case 'maven':
    case 'golang':
    case 'rubygems':
    case 'github-actions':
      return name;
  }
}
