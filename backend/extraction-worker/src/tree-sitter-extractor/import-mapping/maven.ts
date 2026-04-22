/**
 * Maven import → artifact resolution.
 *
 * Java package prefixes (e.g. `org.apache.logging.log4j.Logger`) map to Maven
 * artifacts (`log4j-core`). Implemented in M3 with a bundled Maven Central
 * package-prefix index.
 *
 * Stub until then.
 */
export function resolveMavenImport(
  _importName: string,
  _knownDeps: readonly string[] = []
): string | null {
  return null;
}
