import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';

function textOf(n: Node | null, src: string): string {
  return n ? src.slice(n.startIndex, n.endIndex) : '';
}

function rustStringLiteral(node: Node | null, source: string): string | null {
  if (!node || node.type !== 'string_literal') return null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'string_content') return textOf(c, source);
  }
  const raw = textOf(node, source);
  const m = raw.match(/^"(.*)"$/s);
  return m ? m[1] : null;
}

// Warp is filter-combinator based — hard to fully model. We detect the common
// shape:  warp::path("users").and(warp::get()).and(...).map(handler)
// and emit one entry per chain where we see both a path and a verb filter.

const VERB_FNS: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
};

export const warpDetector: FrameworkDetector = {
  name: 'warp',
  displayName: 'Warp',
  language: 'rust',
  triggerImports: ['warp'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const entryPoints: EntryPoint[] = [];

    const emittedLines = new Set<number>();
    const walk = (node: Node): void => {
      if (node.type === 'call_expression') {
        const fn = node.childForFieldName('function');
        if (fn?.type === 'scoped_identifier') {
          // warp::path("users"), warp::path!("users" / u32)
          const root = getRootSegment(fn, source);
          const leaf = getLeafSegment(fn, source);
          if (root === 'warp' && leaf === 'path') {
            const args = node.childForFieldName('arguments');
            const first = args?.namedChild(0);
            const path = rustStringLiteral(first ?? null, source);
            const statement = findEnclosingStatement(node);
            if (path && statement) {
              const verb = findVerbFilterInStatement(statement, source);
              const line = node.startPosition.row + 1;
              if (!emittedLines.has(line)) {
                emittedLines.add(line);
                entryPoints.push({
                  filePath: file.filePath,
                  lineNumber: line,
                  framework: 'warp',
                  handlerName: null,
                  httpMethod: verb ?? null,
                  routePattern: path.startsWith('/') ? path : `/${path}`,
                  entryPointType: 'http_route',
                  classification: 'PUBLIC_UNAUTH',
                  authenticated: null,
                  authMechanism: null,
                  middlewareChain: null,
                  metadata: { style: 'filter_chain' },
                });
              }
            }
          }
        }
      }
      for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
    };
    walk(tree.rootNode);
    return entryPoints;
  },
};

function getRootSegment(si: Node, source: string): string | null {
  let cur: Node | null = si;
  while (cur && cur.type === 'scoped_identifier') {
    cur = cur.childForFieldName('path') ?? cur.namedChild(0);
  }
  return cur?.type === 'identifier' ? textOf(cur, source) : null;
}

function getLeafSegment(si: Node, source: string): string | null {
  for (let i = si.namedChildCount - 1; i >= 0; i--) {
    const c = si.namedChild(i)!;
    if (si.fieldNameForChild(i) === 'path') continue;
    if (c.type === 'identifier') return textOf(c, source);
  }
  return null;
}

function findEnclosingStatement(node: Node): Node | null {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (cur.type === 'let_declaration' || cur.type === 'expression_statement' || cur.type === 'return_expression') {
      return cur;
    }
  }
  return null;
}

function findVerbFilterInStatement(statement: Node, source: string): HttpMethod | null {
  const stack: Node[] = [statement];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    if (cur.type === 'call_expression') {
      const fn = cur.childForFieldName('function');
      if (fn?.type === 'scoped_identifier') {
        const root = getRootSegment(fn, source);
        const leaf = getLeafSegment(fn, source);
        if (root === 'warp' && leaf && leaf in VERB_FNS) return VERB_FNS[leaf];
      }
    }
    for (let i = 0; i < cur.namedChildCount; i++) stack.push(cur.namedChild(i)!);
  }
  return null;
}
