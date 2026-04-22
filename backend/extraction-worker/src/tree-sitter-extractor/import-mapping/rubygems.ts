/**
 * RubyGems require-path → gem resolution.
 *
 * Ruby's `require 'rest-client'` ↔ gem `rest-client`, `require 'active_support'`
 * ↔ gem `activesupport`. Implemented in M4 with a curated snake↔kebab map for
 * the top gems.
 *
 * Stub until then.
 */
export function resolveRubygemsImport(
  _importName: string,
  _knownDeps: readonly string[] = []
): string | null {
  return null;
}
