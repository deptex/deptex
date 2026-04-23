/**
 * npm import → dep-name resolution.
 *
 * npm import specifiers are mostly 1:1 with package names, modulo two cases:
 *   1. Scoped packages — `@scope/name[/subpath]` → `@scope/name`
 *   2. Subpath exports — `lodash/template` → `lodash`
 *
 * Node builtins (`fs`, `path`, `node:fs`, etc.) return null.
 */

const NODE_BUILTINS = new Set([
  'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
  'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
  'events', 'fs', 'http', 'http2', 'https', 'inspector', 'module', 'net',
  'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring',
  'readline', 'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls',
  'trace_events', 'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads',
  'zlib',
]);

export function resolveNpmImport(
  importName: string,
  knownDeps: readonly string[] = []
): string | null {
  if (!importName) return null;
  if (importName.startsWith('.') || importName.startsWith('/')) return null;

  const stripped = importName.startsWith('node:') ? importName.slice(5) : importName;
  if (NODE_BUILTINS.has(stripped)) return null;

  let pkg: string;
  if (importName.startsWith('@')) {
    const parts = importName.split('/');
    if (parts.length < 2) return null;
    pkg = `${parts[0]}/${parts[1]}`;
  } else {
    pkg = importName.split('/')[0];
  }

  if (knownDeps.length === 0) return pkg;
  return knownDeps.includes(pkg) ? pkg : null;
}
