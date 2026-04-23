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
 * We match case-insensitively, trying both hyphen and underscore variants of
 * the require root against the known deps list.
 */

/** Common split-distribution gems where the require name and gem name don't trivially match. */
const REQUIRE_TO_GEM: Record<string, string> = {
  active_support: 'activesupport',
  active_record: 'activerecord',
  active_job: 'activejob',
  active_model: 'activemodel',
  action_controller: 'actionpack',
  action_view: 'actionpack',
  action_mailer: 'actionmailer',
  action_cable: 'actioncable',
  action_dispatch: 'actionpack',
  rest_client: 'rest-client',
  net_http_persistent: 'net-http-persistent',
  google_api_client: 'google-api-client',
  aws_sdk: 'aws-sdk',
};

function variantsOf(name: string): string[] {
  const out = new Set<string>();
  out.add(name);
  out.add(name.replace(/_/g, '-'));
  out.add(name.replace(/-/g, '_'));
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
  const candidates = mapped ? [mapped] : variantsOf(root);

  if (knownDeps.length === 0) return candidates[0];

  const knownLower = new Map<string, string>();
  for (const dep of knownDeps) knownLower.set(dep.toLowerCase(), dep);

  for (const c of candidates) {
    const hit = knownLower.get(c.toLowerCase());
    if (hit) return hit;
  }
  return null;
}
