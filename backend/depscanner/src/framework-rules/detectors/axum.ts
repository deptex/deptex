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

// Axum builder-chain routing:
//   Router::new()
//       .route("/users", get(list_users))
//       .route("/users", post(create_user))
// Each `.route("/path", VERB(handler))` introduces one entry per verb inside
// the call wrapping the handler.

const VERB_FNS: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
  any: 'GET', // no single method — treated as wildcard; defaulting to GET
};

export const axumDetector: FrameworkDetector = {
  name: 'axum',
  displayName: 'Axum',
  language: 'rust',
  triggerImports: ['axum'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const entryPoints: EntryPoint[] = [];

    const walk = (node: Node): void => {
      if (node.type === 'call_expression') {
        const fn = node.childForFieldName('function');
        if (fn?.type === 'field_expression') {
          const field = fn.childForFieldName('field');
          if (field && textOf(field, source) === 'route') {
            const args = node.childForFieldName('arguments');
            if (args && args.namedChildCount >= 2) {
              const pathArg = args.namedChild(0);
              const verbArg = args.namedChild(1);
              const routePattern = rustStringLiteral(pathArg, source);
              if (routePattern && verbArg?.type === 'call_expression') {
                const verbFn = verbArg.childForFieldName('function');
                let verbName: string | null = null;
                if (verbFn?.type === 'identifier') verbName = textOf(verbFn, source);
                else if (verbFn?.type === 'scoped_identifier') {
                  // e.g. `routing::get(handler)` — take rightmost segment
                  for (let i = verbFn.namedChildCount - 1; i >= 0; i--) {
                    const c = verbFn.namedChild(i)!;
                    if (c.type === 'identifier') { verbName = textOf(c, source); break; }
                  }
                }
                if (verbName && verbName in VERB_FNS) {
                  const handlerArgs = verbArg.childForFieldName('arguments');
                  const handlerArg = handlerArgs?.namedChild(0);
                  entryPoints.push({
                    filePath: file.filePath,
                    lineNumber: node.startPosition.row + 1,
                    framework: 'axum',
                    handlerName: handlerArg ? textOf(handlerArg, source) : null,
                    httpMethod: VERB_FNS[verbName],
                    routePattern,
                    entryPointType: 'http_route',
                    classification: 'PUBLIC_UNAUTH',
                    authenticated: null,
                    authMechanism: null,
                    middlewareChain: null,
                    metadata: { verb_fn: verbName },
                  });
                }
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
