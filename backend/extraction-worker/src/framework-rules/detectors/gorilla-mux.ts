import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';
import {
  classifyFromAuth,
  detectGoAuthMechanism,
  findInstancesFromFactory,
  goStringLiteral,
  handlerTextOf,
  lineOf,
  textOf,
  walkTree,
} from '../util/go';

// Gorilla Mux:
//   r := mux.NewRouter()
//   r.HandleFunc("/users", listUsers).Methods("GET")
//   r.Handle("/users", h).Methods("POST", "PUT")
// We walk top-level call chains, pull HandleFunc/Handle calls, and scan for
// a chained `.Methods(...)` that pins the HTTP verb.

function parseMethodsCall(chain: import('web-tree-sitter').Node, source: string): HttpMethod[] {
  const methods: HttpMethod[] = [];
  // chain is the parent call_expression of `.Methods(...)`
  const args = chain.childForFieldName('arguments');
  if (!args) return methods;
  for (let i = 0; i < args.namedChildCount; i++) {
    const arg = args.namedChild(i)!;
    const s = goStringLiteral(arg, source);
    if (!s) continue;
    const upper = s.toUpperCase();
    if (['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(upper)) {
      methods.push(upper as HttpMethod);
    }
  }
  return methods;
}

export const gorillaMuxDetector: FrameworkDetector = {
  name: 'gorilla-mux',
  displayName: 'Gorilla Mux',
  language: 'go',
  triggerImports: ['github.com/gorilla/mux'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectGoAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);

    const muxImp = file.imports.find((i) => i.source === 'github.com/gorilla/mux');
    const muxAlias = muxImp?.localName ?? 'mux';
    const instances = findInstancesFromFactory(tree.rootNode, source, [
      { pkgAlias: muxAlias, fn: 'NewRouter' },
    ]);
    if (instances.size === 0) return [];

    const entryPoints: EntryPoint[] = [];
    walkTree(tree, (node) => {
      if (node.type !== 'call_expression') return;
      const fn = node.childForFieldName('function');
      if (fn?.type !== 'selector_expression') return;
      const operand = fn.childForFieldName('operand');
      const field = fn.childForFieldName('field');
      if (operand?.type !== 'identifier' || !field) return;
      const op = textOf(operand, source);
      const method = textOf(field, source);
      if (!instances.has(op)) return;
      if (method !== 'HandleFunc' && method !== 'Handle') return;

      const args = node.childForFieldName('arguments');
      const firstArg = args?.namedChild(0);
      const routePattern = goStringLiteral(firstArg ?? null, source);
      if (!routePattern) return;
      const handlerArg = args && args.namedChildCount > 1 ? args.namedChild(1) : null;

      // Inspect parent for a chained .Methods(...) call — the parent
      // selector_expression would have its operand be THIS call_expression.
      let methods: HttpMethod[] = [];
      const parent = node.parent;
      if (parent?.type === 'selector_expression') {
        const parentField = parent.childForFieldName('field');
        const parentParent = parent.parent;
        if (parentField && textOf(parentField, source) === 'Methods' &&
            parentParent?.type === 'call_expression') {
          methods = parseMethodsCall(parentParent, source);
        }
      }

      if (methods.length === 0) methods = [null as unknown as HttpMethod];
      for (const m of methods) {
        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(node),
          framework: 'gorilla-mux',
          handlerName: handlerTextOf(handlerArg, source),
          httpMethod: m || null,
          routePattern,
          entryPointType: 'http_route',
          classification,
          authenticated: !!authMechanism,
          authMechanism,
          middlewareChain: null,
          metadata: { method },
        });
      }
    });
    return entryPoints;
  },
};
