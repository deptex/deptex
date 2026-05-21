/**
 * Composer transitive dependency resolver.
 *
 * cdxgen for `composer` emits a partial SBOM in the common case: it
 * reads `composer.json` (declared requires) and may follow part of the
 * `composer.lock` graph, but real-world Symfony / Laravel / Drupal apps
 * routinely have transitive trees of 100-500 packages where the
 * classifier needs every transitive present to fire `unreachable`.
 *
 * We parse `composer.lock` directly — it is a deterministic JSON file
 * that ALWAYS enumerates the full resolved set with versions, including
 * dev-only packages in `packages-dev`. No `composer install` invocation
 * is needed (and we want to avoid it — `composer install` for a real
 * Laravel skeleton can hang cdxgen for hours, as the v3 corpus run
 * surfaced with `laravel/laravel@v8.6.7`). Direct parse takes milliseconds.
 *
 * composer.lock shape (excerpt):
 *   {
 *     "packages": [
 *       { "name": "symfony/console", "version": "v5.0.1",
 *         "type": "library", "require": { "php": "^7.2.5", ... }, ... },
 *       ...
 *     ],
 *     "packages-dev": [ ... ]
 *   }
 *
 * Each entry's `name` is the canonical `vendor/name` form (matches
 * cdxgen's PURL `pkg:composer/<vendor>/<name>@<version>` namespace+name).
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ParsedSbomDep, ParsedSbomRelationship } from '../sbom';
import type { TransitiveResolverResult } from './go';

interface ComposerLockEntry {
  name?: string;
  version?: string;
  type?: string;
  // We only consume name+version; the resolver doesn't need require[].
}

interface ComposerLock {
  packages?: ComposerLockEntry[];
  'packages-dev'?: ComposerLockEntry[];
}

/**
 * Resolve transitive composer packages by parsing composer.lock. Returns
 * null when `composer.lock` is absent (soft-fail — many composer repos
 * commit only `composer.json`, in which case cdxgen's SBOM is the only
 * source we have).
 */
export async function resolveComposerTransitives(
  repoRoot: string,
): Promise<TransitiveResolverResult | null> {
  const lockPath = path.join(repoRoot, 'composer.lock');
  if (!fs.existsSync(lockPath)) return null;

  const raw = fs.readFileSync(lockPath, 'utf8');
  let parsed: ComposerLock;
  try {
    parsed = JSON.parse(raw) as ComposerLock;
  } catch (err) {
    throw new Error(`composer.lock parse failed: ${(err as Error).message}`);
  }

  const all = [
    ...(Array.isArray(parsed.packages) ? parsed.packages : []),
    ...(Array.isArray(parsed['packages-dev']) ? parsed['packages-dev'] : []),
  ];

  const deps: ParsedSbomDep[] = [];
  for (const entry of all) {
    if (!entry.name || !entry.version) continue;
    // composer-lock names ALWAYS have vendor/name shape (the manifest
    // forbids unscoped packages outside `metapackage`/local stubs).
    // Split into namespace+name to match the ParsedSbom convention.
    const slash = entry.name.indexOf('/');
    const namespace = slash >= 0 ? entry.name.slice(0, slash) : null;
    const name = slash >= 0 ? entry.name.slice(slash + 1) : entry.name;
    if (!name) continue;
    deps.push({
      name,
      version: entry.version.replace(/^v/, ''),
      namespace,
      license: null,
      is_direct: false,
      source: 'transitive',
      // composer-lock entries don't carry direct/dev distinction at this
      // level (the distinction is which top-level array they live in,
      // which the classifier doesn't currently consume); treat all as
      // non-dev to avoid silent dev-scoping that would short-circuit
      // unreachable demotion.
      devScoped: false,
      bomRef: `composer-resolver:${entry.name}@${entry.version}`,
    });
  }

  return {
    deps,
    relationships: [],
    rawModuleCount: all.length,
    source: 'composer-lock-parse',
  };
}
