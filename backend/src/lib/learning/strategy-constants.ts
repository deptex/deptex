export const CANONICAL_STRATEGIES = [
  'bump_version', 'code_patch', 'add_wrapper', 'pin_transitive',
  'remove_unused', 'fix_semgrep', 'remediate_secret',
] as const;

export type CanonicalStrategy = typeof CANONICAL_STRATEGIES[number];

export const STRATEGY_DISPLAY_NAMES: Record<string, string> = {
  bump_version: 'Version Bump',
  code_patch: 'Code Patch',
  add_wrapper: 'Add Wrapper',
  pin_transitive: 'Pin Transitive',
  remove_unused: 'Remove Unused',
  fix_semgrep: 'Fix Semgrep',
  remediate_secret: 'Remediate Secret',
};

export const LEGACY_TO_CANONICAL: Record<string, CanonicalStrategy> = {
  version_bump: 'bump_version',
  targeted_patch: 'code_patch',
  lockfile_only: 'pin_transitive',
  semgrep_fix: 'fix_semgrep',
  secret_rotation: 'remediate_secret',
};

export function normalizeStrategy(strategy: string): string {
  return LEGACY_TO_CANONICAL[strategy] ?? strategy;
}
