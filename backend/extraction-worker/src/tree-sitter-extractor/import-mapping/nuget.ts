/**
 * NuGet namespace → package resolution.
 *
 * .NET `using Microsoft.Extensions.Logging` → NuGet `Microsoft.Extensions.Logging`.
 * Requires assembly metadata when available; falls back to longest-prefix
 * match against known deps. Implemented in M4.
 *
 * Stub until then.
 */
export function resolveNugetImport(
  _importName: string,
  _knownDeps: readonly string[] = []
): string | null {
  return null;
}
