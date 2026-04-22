/**
 * Composer namespace → package resolution.
 *
 * PHP namespaces (`Symfony\Component\HttpFoundation`) map to Packagist
 * `vendor/package` (`symfony/http-foundation`). Implemented in M4.
 *
 * Stub until then.
 */
export function resolveComposerImport(
  _importName: string,
  _knownDeps: readonly string[] = []
): string | null {
  return null;
}
