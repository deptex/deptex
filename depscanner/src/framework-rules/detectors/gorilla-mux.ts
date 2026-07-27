import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';
import type { MiddlewareToken } from '../util/auth-evidence';
import {
  addSubrouterInstances,
  classifyGoRoute,
  detectGoAuthMechanism,
  findInstancesFromFactory,
  findUseCalls,
  goHandlerSpan,
  goMiddlewareToken,
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
    // Import hint only — classification comes from Use/wrapper evidence.
    const authMechanismHint = detectGoAuthMechanism(file.imports);

    const muxImp = file.imports.find((i) => i.source === 'github.com/gorilla/mux');
    const muxAlias = muxImp?.localName ?? 'mux';
    const instances = findInstancesFromFactory(tree.rootNode, source, [
      { pkgAlias: muxAlias, fn: 'NewRouter' },
    ]);
    if (instances.size === 0) return [];
    // Track `s := r.PathPrefix("/x").Subrouter()` instances so their Use/routes
    // are visible (the canonical gorilla auth grouping).
    addSubrouterInstances(tree, source, instances);

    const uses = findUseCalls(tree, source, instances);
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

      // Evidence: this instance's prior Use middleware + a wrapped handler.
      const routeTokens: MiddlewareToken[] = [];
      if (handlerArg?.type === 'call_expression') {
        const wrapper = goMiddlewareToken(handlerArg, source);
        if (wrapper) routeTokens.push(wrapper);
      }
      const routeLine = lineOf(node);
      const useTokens = uses
        .filter((u) => u.instance === op && u.line < routeLine)
        .flatMap((u) => u.tokens);
      const { classification, authenticated } = classifyGoRoute({ routeTokens, useTokens, routePattern });
      const { span, eligible } = goHandlerSpan(tree, source, handlerArg);
      const allTokens = [...routeTokens, ...useTokens];

      if (methods.length === 0) methods = [null as unknown as HttpMethod];
      for (const m of methods) {
        entryPoints.push({
          filePath: file.filePath,
          lineNumber: routeLine,
          framework: 'gorilla-mux',
          handlerName: handlerTextOf(handlerArg, source),
          httpMethod: m || null,
          routePattern,
          entryPointType: 'http_route',
          classification,
          authenticated,
          authMechanism: authMechanismHint,
          middlewareChain: allTokens.length ? allTokens.map((t) => t.display) : null,
          handlerSpan: span,
          demotionEligible: eligible,
          metadata: { method },
        });
      }
    });
    return entryPoints;
  },
};
