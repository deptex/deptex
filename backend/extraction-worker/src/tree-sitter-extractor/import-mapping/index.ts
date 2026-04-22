import type { SupportedEcosystem } from '../languages/types';
import { resolveNpmImport } from './npm';
import { resolveGoImport } from './go';
import { resolvePypiImport } from './pypi';
import { resolveMavenImport } from './maven';
import { resolveRubygemsImport } from './rubygems';
import { resolveComposerImport } from './composer';
import { resolveCargoImport } from './cargo';
import { resolveNugetImport } from './nuget';

/**
 * Resolve a source-level import identifier to a dependency name known to the
 * project's SBOM.
 *
 * Returns the dep name (matching `project_dependencies.name`) if the import
 * maps to a known dep, or `null` if the import belongs to the stdlib, refers
 * to an unknown package, or is a first-party relative import.
 *
 * The set of known deps is passed in so per-ecosystem resolvers can short-
 * circuit (e.g. for Go where the import path IS the module path) or apply
 * longest-common-prefix matching (e.g. for Java where `org.apache.logging.log4j.Logger`
 * belongs to the `log4j-core` artifact).
 */
export function resolveImportToDep(
  importName: string,
  ecosystem: SupportedEcosystem,
  knownDeps: readonly string[] = []
): string | null {
  switch (ecosystem) {
    case 'npm':
      return resolveNpmImport(importName, knownDeps);
    case 'pypi':
      return resolvePypiImport(importName, knownDeps);
    case 'maven':
      return resolveMavenImport(importName, knownDeps);
    case 'go':
      return resolveGoImport(importName, knownDeps);
    case 'rubygems':
      return resolveRubygemsImport(importName, knownDeps);
    case 'composer':
      return resolveComposerImport(importName, knownDeps);
    case 'cargo':
      return resolveCargoImport(importName, knownDeps);
    case 'nuget':
      return resolveNugetImport(importName, knownDeps);
    default: {
      const _exhaustive: never = ecosystem;
      return _exhaustive;
    }
  }
}
