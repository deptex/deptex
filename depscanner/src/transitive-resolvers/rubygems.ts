/**
 * RubyGems transitive dependency resolver.
 *
 * cdxgen for `gem` reads `Gemfile` (and may follow part of `Gemfile.lock`)
 * but in our corpus runs it routinely returns the directly-declared
 * set only, missing transitives that Bundler resolved. Real Rails apps
 * have 100-500-gem transitive trees that the reachability classifier
 * needs in full to fire `unreachable`.
 *
 * We parse `Gemfile.lock` directly. The format is deterministic and
 * well-documented (see Bundler::LockfileParser in bundler). No `bundle
 * lock` invocation is needed (it would shell out to bundler which we
 * don't ship in the depscanner image and which can churn the lockfile
 * if the resolver disagrees with the committed pins).
 *
 * Gemfile.lock format (excerpt):
 *
 *   GEM
 *     remote: https://rubygems.org/
 *     specs:
 *       actionpack (5.2.0)
 *         actionview (= 5.2.0)
 *         activesupport (= 5.2.0)
 *         rack (~> 2.0)
 *       actionview (5.2.0)
 *         activesupport (= 5.2.0)
 *
 *   PLATFORMS
 *     ruby
 *
 *   DEPENDENCIES
 *     actionpack
 *
 *
 * We extract every entry under `GEM > specs:` (and any other source
 * blocks like `GIT`, `PATH`) that matches `<name> (<version>)` — that
 * IS the resolved transitive set, by construction of how Bundler emits
 * Gemfile.lock.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ParsedSbomDep, ParsedSbomRelationship } from '../sbom';
import type { TransitiveResolverResult } from './go';

// Matches a top-level spec line under `specs:`: two-space indent, then
// "name (version)". Sub-dep lines are four-space-indented and contain
// version constraints we ignore (they're recoverable from the spec
// lines themselves, since Bundler only lists resolved transitives).
const SPEC_LINE_RE = /^\s{4}([a-zA-Z0-9._-]+)\s+\(([^)]+)\)\s*$/;

/**
 * Resolve transitive gems by parsing Gemfile.lock. Returns null when the
 * lockfile is absent (some pre-Bundler-1.x repos ship only Gemfile, in
 * which case cdxgen's SBOM is the only source we have).
 */
export async function resolveRubygemsTransitives(
  repoRoot: string,
): Promise<TransitiveResolverResult | null> {
  const lockPath = path.join(repoRoot, 'Gemfile.lock');
  if (!fs.existsSync(lockPath)) return null;

  const raw = fs.readFileSync(lockPath, 'utf8');
  const lines = raw.split(/\r?\n/);

  // Collect every `<name> (<version>)` line that lives in a `specs:`
  // block. Bundler emits one specs: block per source (GEM, GIT, PATH);
  // we treat all of them as resolved, which is what they are.
  const deps: ParsedSbomDep[] = [];
  const seen = new Set<string>();
  let inSpecs = false;
  let specsIndent = 0;
  for (const line of lines) {
    const trimmed = line.replace(/\s+$/, '');
    if (/^\s*specs:\s*$/.test(trimmed)) {
      inSpecs = true;
      specsIndent = (trimmed.match(/^(\s*)/)?.[1].length ?? 0);
      continue;
    }
    // A blank line OR a left-margin section header (`GEM`, `PLATFORMS`,
    // `DEPENDENCIES`, `BUNDLED WITH`) ends the current specs: block.
    if (inSpecs) {
      if (trimmed === '') {
        inSpecs = false;
        continue;
      }
      const leading = trimmed.match(/^(\s*)/)?.[1].length ?? 0;
      if (leading <= specsIndent) {
        inSpecs = false;
        // Fall through to header-handling below (this line might be
        // a new source block).
      } else {
        const m = SPEC_LINE_RE.exec(line);
        if (m) {
          const [, name, version] = m;
          const key = `${name}@${version}`;
          if (!seen.has(key)) {
            seen.add(key);
            deps.push({
              name,
              version,
              namespace: null,
              license: null,
              is_direct: false,
              source: 'transitive',
              devScoped: false,
              bomRef: `gemfile-lock-resolver:${name}@${version}`,
            });
          }
        }
        continue;
      }
    }
  }

  return {
    deps,
    relationships: [],
    rawModuleCount: deps.length,
    source: 'gemfile-lock-parse',
  };
}
