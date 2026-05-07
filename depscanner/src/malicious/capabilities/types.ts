/**
 * Shared types for the malicious-packages-v2 capability detector.
 *
 * Locked at 15 deterministic capability tags for v2 (Socket-style). Adding
 * a new tag requires both a new boolean column on `package_capabilities`
 * and a bump to the scanner_version constant in `../capabilities.ts` so
 * stale rows re-scan on next extraction.
 */

export const CAPABILITY_KEYS = [
  'spawns_processes',
  'network_io',
  'eval_dynamic',
  'native_addon_load',
  'filesystem_write',
  'crypto_operations',
  'serialization_deser',
  'install_script',
  'dns_query',
  'websocket',
  'process_signal',
  'encrypted_payload',
  'dynamic_import',
  'reads_env',
  'clipboard_access',
] as const;

export type CapabilityKey = (typeof CAPABILITY_KEYS)[number];

export type CapabilitySet = Record<CapabilityKey, boolean>;

export function emptyCapabilitySet(): CapabilitySet {
  return {
    spawns_processes: false,
    network_io: false,
    eval_dynamic: false,
    native_addon_load: false,
    filesystem_write: false,
    crypto_operations: false,
    serialization_deser: false,
    install_script: false,
    dns_query: false,
    websocket: false,
    process_signal: false,
    encrypted_payload: false,
    dynamic_import: false,
    reads_env: false,
    clipboard_access: false,
  };
}

/**
 * OR-merge: any `true` in `b` flips the corresponding key in `a` to `true`.
 * Mutates `a` and returns it for chaining inside reduce loops.
 */
export function orMerge(a: CapabilitySet, b: Partial<CapabilitySet>): CapabilitySet {
  for (const k of CAPABILITY_KEYS) {
    if (b[k]) a[k] = true;
  }
  return a;
}

/**
 * Per-language detector contract. `detect()` runs against ONE source file
 * and returns a partial set; the dispatcher OR-merges across all files.
 */
export interface CapabilityDetector {
  /** Canonical language id matches the tree-sitter-extractor `SupportedLanguageId`. */
  language: string;
  /** Extension-based file filter. Receives a lowercased path. */
  supportsFile(filePath: string): boolean;
  /** Returns capability flags detected in this single file. Synchronous: pure regex. */
  detect(source: string): Partial<CapabilitySet>;
}
