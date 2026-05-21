/**
 * Composer namespace → package (vendor/name) resolution.
 *
 * PHP `use Symfony\Component\HttpFoundation\Request` imports the class
 * `Request` from namespace `Symfony\Component\HttpFoundation`. Composer
 * packages use `vendor/name` form (e.g. `symfony/http-foundation`). The
 * vendor is typically the top namespace segment lowercased; the package
 * name follows the second segment but with the "component" level often
 * flattened (Symfony\Component\Foo → symfony/foo, not symfony/component-foo).
 *
 * Resolution strategy:
 *   1. Split namespace into segments.
 *   2. Lowercase the vendor segment (namespace[0]).
 *   3. Build candidate package names by joining subsequent segments in a
 *      few common shapes: `<vendor>/<seg1>`, `<vendor>/<seg1>-<seg2>`,
 *      `<vendor>/<kebab-of-all-after-vendor>`. Skip the redundant
 *      "Component" level that Symfony uses.
 *   4. Case-insensitive match against known deps keyed `vendor/name`.
 *
 * IMPORTANT: cdxgen emits composer SBOM entries as `{ name: "console",
 * group: "symfony" }`, NOT `{ name: "symfony/console" }`. The earlier
 * implementation flattened deps to names only, which built a lookup
 * map keyed on just `console`/`framework-bundle`/etc — so no candidate
 * like `symfony/console` ever matched. Always key the lookup on
 * `${namespace}/${name}` (composer's canonical PURL form).
 */

import type { KnownDep } from '../languages/types';

const KNOWN_INTERIOR_SEGMENTS = new Set([
  'Component', 'Contracts', 'Bundle', 'Bridge',
]);

function kebab(s: string): string {
  return s
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1-$2')
    .toLowerCase();
}

function candidatePackages(namespace: string): string[] {
  const segments = namespace.split('\\').filter(Boolean);
  if (segments.length === 0) return [];
  const vendor = segments[0].toLowerCase();
  const rest = segments.slice(1).filter((s) => !KNOWN_INTERIOR_SEGMENTS.has(s));
  const kebabedRest = rest.map(kebab);

  const out = new Set<string>();
  // Vendor-only (single-package vendors like `monolog/monolog`).
  out.add(`${vendor}/${vendor}`);
  // ALWAYS include the bare vendor — covers the case where the SBOM
  // dep is recorded with namespace=null (a flat name) but the source
  // `use Monolog\Logger` points to a vendor-only package. The bare-name
  // lookup map indexes on dep.name for exactly this fallback.
  out.add(vendor);
  if (rest.length >= 1) {
    out.add(`${vendor}/${kebabedRest[0]}`);
    out.add(`${vendor}/${kebabedRest.join('-')}`);
  }
  return [...out];
}

/**
 * Resolve a PHP namespace import to a composer dep entry.
 *
 * Returns the *bare* dep name (matching `project_dependencies.name`) for
 * downstream code that keys storage on name alone. The caller may need
 * to round-trip through deps[] to recover the full vendor/name; we keep
 * the API symmetric with the other resolvers so all `filesByDep` maps
 * remain name-keyed.
 */
export function resolveComposerImport(
  importName: string,
  knownDeps: readonly KnownDep[] = []
): string | null {
  if (!importName) return null;
  const candidates = candidatePackages(importName);
  if (candidates.length === 0) return null;
  if (knownDeps.length === 0) return candidates[0].split('/').pop() ?? null;

  // Build a lookup keyed on the canonical PURL form `vendor/name`. cdxgen
  // emits composer SBOM entries with split `name`+`group` so we must
  // reconstruct the full identifier here, NOT rely on `name` alone.
  const knownLower = new Map<string, KnownDep>();
  for (const dep of knownDeps) {
    if (dep.namespace) {
      knownLower.set(`${dep.namespace}/${dep.name}`.toLowerCase(), dep);
    }
    // Also index by bare name so vendor-only packages (rare on composer
    // but possible) and any downstream caller passing pre-joined names
    // still resolve.
    knownLower.set(dep.name.toLowerCase(), dep);
  }

  for (const c of candidates) {
    const hit = knownLower.get(c.toLowerCase());
    if (hit) return hit.name;
  }
  return null;
}
