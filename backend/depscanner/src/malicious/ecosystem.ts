/**
 * Worker-side mirror of `backend/src/lib/malicious/ecosystem.ts`.
 *
 * Kept as a tiny standalone copy because the extraction worker is a separate
 * Fly.io app with its own package.json — it cannot reach back into the
 * backend src tree at runtime. The two files MUST stay in sync; the SQL
 * helper `public.canonicalize_malicious_ecosystem` is the third copy and
 * also needs to match.
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

const ALIASES: Record<string, CanonicalEcosystem> = {
  npm: 'npm',
  pypi: 'pypi',
  pip: 'pypi',
  maven: 'maven',
  golang: 'golang',
  go: 'golang',
  rubygems: 'rubygems',
  gem: 'rubygems',
  composer: 'composer',
  packagist: 'composer',
  php: 'composer',
  cargo: 'cargo',
  rust: 'cargo',
  'crates.io': 'cargo',
  nuget: 'nuget',
  csharp: 'nuget',
  dotnet: 'nuget',
  '.net': 'nuget',
  'github-actions': 'github-actions',
  'github-action': 'github-actions',
  'github actions': 'github-actions',
  vscode: 'vscode',
};

export function canonicalizeEcosystem(raw: string | null | undefined): CanonicalEcosystem | null {
  if (!raw) return null;
  return ALIASES[raw.trim().toLowerCase()] ?? null;
}

/**
 * GuardDog's CLI takes a different keyword for some ecosystems than the
 * canonical Deptex name. This maps canonical → guarddog-cli verb.
 *
 * GuardDog 2.9.0 doesn't ship rule packs for composer/cargo/nuget — those
 * three return null and the GuardDog dispatch in the worker is short-circuited.
 * Capability detection still runs for them via tree-sitter regardless.
 */
const GUARDDOG_CLI: Partial<Record<CanonicalEcosystem, string>> = {
  npm: 'npm',
  pypi: 'pypi',
  golang: 'go',
  'github-actions': 'github-action',
};

export function guarddogCliVerb(ecosystem: CanonicalEcosystem): string | null {
  return GUARDDOG_CLI[ecosystem] ?? null;
}
