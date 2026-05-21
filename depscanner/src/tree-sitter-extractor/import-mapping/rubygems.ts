/**
 * RubyGems require-path → gem name resolution.
 *
 * Most gems follow the convention that `require 'gem-name'` corresponds to
 * the gem published as `gem-name`. A meaningful minority use underscores in
 * their require path but hyphens in the gem name (`rest-client`,
 * `net-http-persistent`, `rspec-core`) — or the reverse (`active_support` in
 * `activesupport`). Subpath requires resolve to the same top gem
 * (`active_support/core_ext` → `activesupport`).
 *
 * We match case-insensitively, trying hyphen, underscore, AND
 * separators-stripped variants of the require root against the known
 * deps list. The stripped variant catches Rails 5+ splits where the
 * require path is `action_view` but the gem is `actionview` (no
 * underscore, no hyphen). Hand-curated `REQUIRE_TO_GEM` covers the
 * cases where variantsOf() can't infer correctly.
 */

/**
 * Hand-curated require → gem overrides. Used only when the simple
 * variants below can't be derived from the require path itself.
 *
 * Rails 5+ split each Action* / Active* sub-framework into its own gem
 * (`actionview`, `actionpack`, `actioncable`, …). The previous version
 * of this table conflated `action_view → actionpack`; in Rails 5+ those
 * are separate gems and that mapping is wrong. We let `variantsOf()`
 * produce the stripped form (`action_view` → `actionview`) so the
 * resolver matches the correct gem.
 */
const REQUIRE_TO_GEM: Record<string, string> = {
  // Long-standing renames pip-style (require name on the left, gem on the right).
  rest_client: 'rest-client',
  net_http_persistent: 'net-http-persistent',
  google_api_client: 'google-api-client',
  aws_sdk: 'aws-sdk',
  // Aliases that don't match any variantsOf() transformation.
  nokogumbo: 'nokogiri',
};

function variantsOf(name: string): string[] {
  const out = new Set<string>();
  out.add(name);
  out.add(name.replace(/_/g, '-'));
  out.add(name.replace(/-/g, '_'));
  // Separators-stripped: handles `action_view` → `actionview` (Rails 5+
  // split-package names), `active_record` → `activerecord`, etc.
  out.add(name.replace(/[-_]/g, ''));
  return [...out];
}

export function resolveRubygemsImport(
  importName: string,
  knownDeps: readonly string[] = []
): string | null {
  if (!importName) return null;
  const root = importName.split('/')[0];
  if (!root) return null;

  const mapped = REQUIRE_TO_GEM[root];
  // When an override exists, ALSO emit the natural variants — Rails 5+
  // app code requires `active_support/core_ext/…` which we want to
  // match both `activesupport` (Rails 5+) and any future `active-support`
  // split, not block on the curated table being out of date.
  const candidates = mapped ? [mapped, ...variantsOf(root)] : variantsOf(root);

  if (knownDeps.length === 0) return candidates[0];

  const knownLower = new Map<string, string>();
  for (const dep of knownDeps) knownLower.set(dep.toLowerCase(), dep);

  for (const c of candidates) {
    const hit = knownLower.get(c.toLowerCase());
    if (hit) return hit;
  }
  return null;
}
