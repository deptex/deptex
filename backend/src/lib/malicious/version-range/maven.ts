/**
 * Maven version-range resolver — best-effort.
 *
 * Maven Central does have a versions API (search.maven.org), but the GHSA
 * Maven advisories almost always emit ranges using groupId:artifactId
 * coordinates we'd have to parse separately and the version-comparison
 * semantics (Maven's own ComparableVersion) are non-trivial to reimplement
 * faithfully in TypeScript. v2 takes the pragmatic path: handle exact
 * `=` constraints via the index.ts shortcut and fall back to `null` for
 * everything else, which means the caller writes a `version=null` row and
 * we still flag the package globally.
 *
 * Revisit in v3 if Maven advisory volume grows enough to warrant a real
 * ComparableVersion port.
 */
import type { ParsedRange, PackumentCache } from './index';

export async function resolveMavenRange(
  _packageName: string,
  _parsed: ParsedRange,
  _cache: PackumentCache,
): Promise<string[] | null> {
  return null;
}
