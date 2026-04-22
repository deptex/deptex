/**
 * Cargo use-path → crate name resolution.
 *
 * Rust `use tokio::sync::Mutex` imports from crate `tokio`. The root
 * segment of a use-path is the crate name, EXCEPT for stdlib prefixes
 * (`std::`, `core::`, `alloc::`) and the current-crate prefix (`crate::`,
 * `super::`, `self::`).
 *
 * Cargo publishes crates with hyphens in the name (`serde-json`,
 * `tokio-stream`) but Rust identifiers use underscores, so `use serde_json`
 * maps to crate `serde-json`. We try both variants against the known
 * deps list.
 */

const RUST_BUILTINS = new Set(['std', 'core', 'alloc', 'crate', 'self', 'super']);

function variantsOf(name: string): string[] {
  const out = new Set<string>();
  out.add(name);
  out.add(name.replace(/_/g, '-'));
  out.add(name.replace(/-/g, '_'));
  return [...out];
}

export function resolveCargoImport(
  importName: string,
  knownDeps: readonly string[] = []
): string | null {
  if (!importName) return null;
  // use-paths come in as `tokio::sync::Mutex`. Take the first component.
  const root = importName.split('::')[0];
  if (!root || RUST_BUILTINS.has(root)) return null;

  const candidates = variantsOf(root);
  if (knownDeps.length === 0) return candidates[0];

  const knownLower = new Map<string, string>();
  for (const dep of knownDeps) knownLower.set(dep.toLowerCase(), dep);

  for (const c of candidates) {
    const hit = knownLower.get(c.toLowerCase());
    if (hit) return hit;
  }
  return null;
}
