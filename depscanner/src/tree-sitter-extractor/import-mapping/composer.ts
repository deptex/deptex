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
 *   4. Case-insensitive match against known deps.
 */

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
  if (rest.length === 0) out.add(vendor);
  if (rest.length >= 1) {
    out.add(`${vendor}/${kebabedRest[0]}`);
    out.add(`${vendor}/${kebabedRest.join('-')}`);
  }
  return [...out];
}

export function resolveComposerImport(
  importName: string,
  knownDeps: readonly string[] = []
): string | null {
  if (!importName) return null;
  const candidates = candidatePackages(importName);
  if (candidates.length === 0) return null;
  if (knownDeps.length === 0) return candidates[0];

  const knownLower = new Map<string, string>();
  for (const dep of knownDeps) knownLower.set(dep.toLowerCase(), dep);

  for (const c of candidates) {
    const hit = knownLower.get(c.toLowerCase());
    if (hit) return hit;
  }
  return null;
}
