import type { KnownDep } from '../languages/types';

/**
 * NuGet namespace → package resolution.
 *
 * .NET `using Microsoft.Extensions.Logging` imports from NuGet package
 * `Microsoft.Extensions.Logging`. Unlike Maven, NuGet packages typically
 * ARE a dotted-namespace prefix of the types they ship — assembly names
 * and namespace roots generally align. So strict prefix match on the dep
 * name (rather than a separate namespace column) works.
 *
 * The `namespace` field on a dep, if populated by the SBOM, is used as a
 * tiebreaker, but most NuGet SBOMs leave it null.
 *
 * stdlib-ish roots (`System.*`) match the `System.*` NuGet metapackages
 * when present, else return null (no third-party dep).
 */

const NUGET_BCL_PACKAGES = new Set(['System', 'Microsoft', 'Windows']);

export function resolveNugetImport(
  importName: string,
  deps: readonly KnownDep[] = []
): string | null {
  if (!importName) return null;

  if (deps.length === 0) {
    // Heuristic baseline: first two segments.
    const segs = importName.split('.');
    if (segs.length >= 2) return `${segs[0]}.${segs[1]}`;
    return null;
  }

  let best: KnownDep | null = null;
  for (const dep of deps) {
    // Check: is dep.name a prefix of the import?
    const match = importName === dep.name || importName.startsWith(`${dep.name}.`);
    if (!match) continue;
    if (best === null || dep.name.length > best.name.length) best = dep;
  }
  if (best) return best.name;

  // Fall back to namespace field if provided (unusual for NuGet).
  for (const dep of deps) {
    if (!dep.namespace) continue;
    if (importName === dep.namespace || importName.startsWith(`${dep.namespace}.`)) {
      return dep.name;
    }
  }

  // Unresolved BCL roots (System.*) aren't third-party deps.
  const root = importName.split('.')[0];
  if (NUGET_BCL_PACKAGES.has(root)) return null;

  return null;
}

