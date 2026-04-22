import type { KnownDep, SupportedEcosystem } from '../languages/types';
import { resolveNpmImport } from './npm';
import { resolveGoImport } from './go';
import { resolvePypiImport } from './pypi';
import { resolveMavenImport } from './maven';
import { resolveRubygemsImport } from './rubygems';
import { resolveComposerImport } from './composer';
import { resolveCargoImport } from './cargo';
import { resolveNugetImport } from './nuget';

function namesOf(deps: readonly KnownDep[]): readonly string[] {
  return deps.map((d) => d.name);
}

/**
 * Resolve a source-level import identifier to a dependency name known to the
 * project's SBOM.
 *
 * Returns the dep name (matching `project_dependencies.name`) if the import
 * maps to a known dep, or `null` if the import belongs to the stdlib, refers
 * to an unknown package, or is a first-party relative import.
 *
 * Per-ecosystem resolvers handle the quirks: npm scoped/subpath, pypi
 * distribution↔module split, go longest-prefix, maven groupId→artifact.
 */
export function resolveImportToDep(
  importName: string,
  ecosystem: SupportedEcosystem,
  deps: readonly KnownDep[] = []
): string | null {
  switch (ecosystem) {
    case 'npm':
      return resolveNpmImport(importName, namesOf(deps));
    case 'pypi':
      return resolvePypiImport(importName, namesOf(deps));
    case 'maven':
      return resolveMavenImport(importName, deps);
    case 'go':
      return resolveGoImport(importName, namesOf(deps));
    case 'rubygems':
      return resolveRubygemsImport(importName, namesOf(deps));
    case 'composer':
      return resolveComposerImport(importName, namesOf(deps));
    case 'cargo':
      return resolveCargoImport(importName, namesOf(deps));
    case 'nuget':
      return resolveNugetImport(importName, deps);
    default: {
      const _exhaustive: never = ecosystem;
      return _exhaustive;
    }
  }
}
