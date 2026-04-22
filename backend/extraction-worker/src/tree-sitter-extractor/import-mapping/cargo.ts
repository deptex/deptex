/**
 * Cargo crate → package resolution.
 *
 * Rust `use tokio::sync::Mutex` → crate `tokio`. Mostly 1:1, modulo the
 * hyphen/underscore convention (`serde_json` crate ↔ `serde-json` on
 * crates.io). Implemented in M4.
 *
 * Stub until then.
 */
export function resolveCargoImport(
  _importName: string,
  _knownDeps: readonly string[] = []
): string | null {
  return null;
}
