// Express router mount-prefix resolution.
//
// The express detector stores the route literal as written — `router.get('/users')`
// → '/users' — and drops the mount prefix from `app.use('/api', apiRouter)`.
// The DAST synthesizer would then point ZAP at '/users' while the app serves
// '/api/users' → 404, and no param enrichment matters. This post-extraction
// pass composes the prefix back onto the served path so route_pattern reflects
// what's actually mounted.
//
// Handles:
//   - same-file:  const r = express.Router(); app.use('/api', r); r.get('/x')
//   - cross-file: server.js: app.use('/api', require('./routes/api'))
//                 routes/api.js: router.get('/x')  → '/api/x'
//
// The mount entries themselves are method-less `app.use('/api', x)` rows
// (httpMethod === null), which the synthesizer already drops — so they're left
// as-is. Single-pass (one level of mounting); nested router.use chains are a
// fast-follow.

import type { ExtractedFile } from '../tree-sitter-extractor/languages/types';
import type { EntryPoint } from '../framework-rules/types';

function norm(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '');
}

function dirOf(p: string): string {
  const n = norm(p);
  const idx = n.lastIndexOf('/');
  return idx >= 0 ? n.slice(0, idx) : '';
}

/** Posix-normalize `dir + '/' + rel`, collapsing `.`/`..` segments. */
function joinPath(dir: string, rel: string): string {
  // Preserve a leading slash: on the worker every cloned file path is absolute
  // (`/tmp/deptex-extract-XXX/...`), and the leading '' segment from splitting
  // an absolute path would otherwise be dropped as `seg === ''`, yielding a
  // relative result that never matches the absolute byPath keys → cross-file
  // mount resolution silently no-ops and the `/api` prefix is lost.
  const nd = norm(dir);
  const absolute = nd.startsWith('/');
  const parts = (nd ? nd.split('/') : []).concat(rel.split('/'));
  const out: string[] = [];
  for (const seg of parts) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  const joined = out.join('/');
  return absolute ? '/' + joined : joined;
}

function joinRoute(prefix: string, route: string): string {
  const a = prefix.replace(/\/+$/, '');
  const b = route.startsWith('/') ? route : '/' + route;
  if (b === '/') return a || '/';
  return a + b || '/';
}

const BARE_IDENT = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

function isRealRoute(ep: EntryPoint): boolean {
  return ep.framework === 'express' && ep.httpMethod !== null && !!ep.routePattern;
}

function resolveTargetFile(
  byPath: Map<string, ExtractedFile>,
  mountFilePath: string,
  source: string,
): ExtractedFile | undefined {
  const base = joinPath(dirOf(mountFilePath), source);
  const candidates = [
    base,
    `${base}.js`,
    `${base}.ts`,
    `${base}.mjs`,
    `${base}.cjs`,
    `${base}.jsx`,
    `${base}.tsx`,
    `${base}/index.js`,
    `${base}/index.ts`,
  ];
  for (const c of candidates) {
    const f = byPath.get(norm(c));
    if (f) return f;
  }
  return undefined;
}

export function resolveMountPrefixes(files: readonly ExtractedFile[]): void {
  const byPath = new Map<string, ExtractedFile>();
  for (const f of files) byPath.set(norm(f.filePath), f);

  // Collect the prefix to apply to each real route BEFORE mutating any of them.
  // Resolving into a map first (rather than mutating in the mount loop) makes
  // the pass idempotent against the double-prefix bug: when one router instance
  // or module is mounted at several prefixes, an in-place mutate would compose
  // the second prefix onto the already-prefixed value (`/api/x` → `/admin/api/x`,
  // a path the app never serves → ZAP 404s and misses the route). Here every
  // route is composed exactly once, from its original literal.
  //
  // A router mounted at multiple prefixes keeps the FIRST mount's served path
  // (deterministic in file/mount order). We deliberately don't fan out one
  // entry point per prefix: the entry-point upsert is keyed on
  // (file, line, framework, handler) with no route_pattern, so two siblings
  // sharing a handler would collide on conflict (a Postgres cardinality
  // violation) — emitting both `/api/x` and `/admin/x` needs route_pattern in
  // that key, a migration-scoped follow-up.
  const prefixOf = new Map<EntryPoint, string>();
  const claim = (route: EntryPoint, prefix: string): void => {
    if (!prefixOf.has(route)) prefixOf.set(route, prefix);
  };

  for (const mountFile of files) {
    for (const ep of mountFile.entryPoints ?? []) {
      if (ep.framework !== 'express' || ep.httpMethod !== null) continue;
      const call = typeof ep.metadata?.call === 'string' ? ep.metadata.call : '';
      if (!call.endsWith('.use')) continue;
      const prefix = ep.routePattern;
      if (!prefix || prefix === '/' || !prefix.startsWith('/')) continue;
      const target = ep.handlerName;
      if (!target || !BARE_IDENT.test(target)) continue; // bare router identifier only

      // (a) same-file router instance mounted here.
      let appliedSameFile = false;
      for (const other of mountFile.entryPoints ?? []) {
        if (other === ep || !isRealRoute(other)) continue;
        if (other.metadata?.instance === target) {
          claim(other, prefix);
          appliedSameFile = true;
        }
      }
      if (appliedSameFile) continue;

      // (b) cross-file: the mounted identifier is an imported router module.
      const imp = mountFile.imports.find((i) => i.localName === target);
      if (!imp || !imp.source.startsWith('.')) continue;
      const targetFile = resolveTargetFile(byPath, mountFile.filePath, imp.source);
      if (!targetFile || targetFile === mountFile) continue;
      for (const r of targetFile.entryPoints ?? []) {
        if (isRealRoute(r)) claim(r, prefix);
      }
    }
  }

  for (const [route, prefix] of prefixOf) {
    route.routePattern = joinRoute(prefix, route.routePattern!);
  }
}
