/**
 * Go module version-range resolver — best-effort.
 *
 * The Go module proxy at https://proxy.golang.org/<mod>/@v/list returns the
 * list of published versions. Comparison uses semver, but Go module versions
 * frequently include pseudo-versions like `v0.0.0-20210304101001-deadbeef`
 * which don't sort meaningfully against tagged releases.
 *
 * Like maven.ts, exact `=` constraints are handled by the index.ts shortcut
 * before this resolver is reached. For non-exact ranges we fall back to
 * `null` so the caller writes a `version=null` row.
 *
 * Revisit in v3 if Go-module advisory volume warrants a real comparator.
 */
import type { ParsedRange, PackumentCache } from './index';

export async function resolveGolangRange(
  _packageName: string,
  _parsed: ParsedRange,
  _cache: PackumentCache,
): Promise<string[] | null> {
  return null;
}
