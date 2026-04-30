/**
 * Go import → module-name resolution.
 *
 * Go imports are module paths (`github.com/gin-gonic/gin`). The import path
 * IS the module identity, modulo subpackages (`golang.org/x/text/language` →
 * `golang.org/x/text`). Resolution against the known deps list is done by
 * longest-prefix match.
 *
 * Stdlib paths (no dot in the first path segment) return null.
 */

export function resolveGoImport(
  importPath: string,
  knownDeps: readonly string[] = []
): string | null {
  if (!importPath) return null;

  const firstSegment = importPath.split('/')[0];
  if (!firstSegment.includes('.')) return null;

  if (knownDeps.length === 0) return importPath;

  let best: string | null = null;
  for (const dep of knownDeps) {
    if (importPath === dep || importPath.startsWith(`${dep}/`)) {
      if (best === null || dep.length > best.length) {
        best = dep;
      }
    }
  }
  return best;
}
