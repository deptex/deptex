import * as fs from 'fs';
import * as path from 'path';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';
import { walkTree, textOf } from '../util/javascript';

// Next.js is file-path-routed, not AST-routed:
//   pages/api/users.js        → any HTTP method → handler is default export
//   pages/api/users/[id].ts   → dynamic segment
//   app/api/users/route.ts    → exports GET / POST / etc. by function name
// We treat the file path as the route pattern after stripping the api/ prefix
// and transforming `[id]` → `:id` for friendliness.

const NEXT_FILE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs']);

function pathFromFilename(relativePath: string): {
  variant: 'pages' | 'app' | null;
  route: string | null;
} {
  // `relativePath` is workspace-relative — anchoring on `^` or a `/` prevents
  // an ancestor directory named `pages`/`app` outside the repo from matching.
  const normalized = relativePath.replace(/\\/g, '/');
  const ext = path.extname(normalized);
  if (!NEXT_FILE_EXTENSIONS.has(ext)) return { variant: null, route: null };

  const pagesApiMatch = normalized.match(/(?:^|\/)pages\/api\/(.+)$/);
  if (pagesApiMatch) {
    const rel = pagesApiMatch[1].replace(new RegExp(`\\${ext}$`), '');
    return { variant: 'pages', route: `/${normalize(rel)}` };
  }

  const appRouteMatch = normalized.match(/(?:^|\/)app\/(.+)\/route$/);
  if (appRouteMatch) {
    return { variant: 'app', route: `/${normalize(appRouteMatch[1])}` };
  }
  const appRouteExtMatch = normalized.match(/(?:^|\/)app\/(.+)\/route\.(js|jsx|ts|tsx|mjs)$/);
  if (appRouteExtMatch) {
    return { variant: 'app', route: `/${normalize(appRouteExtMatch[1])}` };
  }
  return { variant: null, route: null };
}

/** True only if the repo actually uses Next.js (declared dep or a next.config.* at root). */
function isNextProject(workspaceRoot: string, depNames: readonly string[]): boolean {
  if (depNames.some((d) => d.toLowerCase() === 'next')) return true;
  for (const cfg of ['next.config.js', 'next.config.mjs', 'next.config.ts']) {
    try {
      if (fs.existsSync(path.join(workspaceRoot, cfg))) return true;
    } catch { /* ignore */ }
  }
  return false;
}

function normalize(p: string): string {
  return p
    .split('/')
    .map((seg) => seg.replace(/^\[(\.\.\.)?(\w+)\]$/, ':$2'))
    .filter((seg) => seg !== 'index')
    .join('/');
}

const APP_ROUTE_HANDLER_NAMES: Record<string, HttpMethod> = {
  GET: 'GET', POST: 'POST', PUT: 'PUT', PATCH: 'PATCH',
  DELETE: 'DELETE', HEAD: 'HEAD', OPTIONS: 'OPTIONS',
};

export const nextjsDetector: FrameworkDetector = {
  name: 'nextjs',
  displayName: 'Next.js',
  language: 'javascript',
  // Next.js route files don't necessarily import 'next' — routing is
  // filesystem-based. Empty triggerImports means we run on every file; the
  // filename convention inside `detect` is the real gate.
  triggerImports: [],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { file, tree, source, workspaceRoot, depNames } = ctx;
    if (!isNextProject(workspaceRoot, depNames)) return [];
    const relativePath = path.relative(workspaceRoot, file.filePath);
    // path.relative escaping the root (`..`) means the file is outside the
    // workspace — never a Next.js route.
    if (relativePath.startsWith('..')) return [];
    const { variant, route } = pathFromFilename(relativePath);
    if (!variant || !route) return [];

    const entryPoints: EntryPoint[] = [];

    if (variant === 'pages') {
      // pages/api/*.ts — one handler, default export.
      entryPoints.push({
        filePath: file.filePath,
        lineNumber: 1,
        framework: 'nextjs',
        handlerName: 'default',
        httpMethod: null, // handler dispatches internally on req.method
        routePattern: route,
        entryPointType: 'http_route',
        classification: 'PUBLIC_UNAUTH',
        authenticated: null,
        authMechanism: null,
        middlewareChain: null,
        metadata: { variant: 'pages' },
      });
    } else {
      // app/**/route.ts — one export per HTTP method.
      walkTree(tree, (node) => {
        if (node.type !== 'export_statement') return;
        for (let i = 0; i < node.namedChildCount; i++) {
          const child = node.namedChild(i)!;
          if (child.type === 'function_declaration' || child.type === 'lexical_declaration') {
            const name = findExportedName(child, source);
            const httpMethod = name ? APP_ROUTE_HANDLER_NAMES[name] : null;
            if (name && httpMethod) {
              entryPoints.push({
                filePath: file.filePath,
                lineNumber: node.startPosition.row + 1,
                framework: 'nextjs',
                handlerName: name,
                httpMethod,
                routePattern: route,
                entryPointType: 'http_route',
                classification: 'PUBLIC_UNAUTH',
                authenticated: null,
                authMechanism: null,
                middlewareChain: null,
                metadata: { variant: 'app' },
              });
            }
          }
        }
      });
    }

    return entryPoints;
  },
};

function findExportedName(node: import('web-tree-sitter').Node, source: string): string | null {
  if (node.type === 'function_declaration') {
    const name = node.childForFieldName('name');
    return name ? textOf(name, source) : null;
  }
  if (node.type === 'lexical_declaration') {
    const decl = node.namedChild(0);
    if (decl?.type === 'variable_declarator') {
      const name = decl.childForFieldName('name');
      return name ? textOf(name, source) : null;
    }
  }
  return null;
}
