import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HandlerSpan, HttpMethod } from '../types';
import {
  classifyRoute,
  matchesAuthName,
  isOptionalVetoed,
  spanOfNode,
} from '../util/auth-evidence';

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
//       .route("/admin", get(admin))
//       .route_layer(middleware::from_fn(require_auth))
// Layers apply to routes added BEFORE the layer call in the chain, so a route's
// coverage = the auth-shaped `.layer`/`.route_layer` calls found in its ANCESTOR
// chain (they wrap the sub-router that already contains it).

const VERB_FNS: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
  any: 'GET', // no single method — treated as wildcard; defaulting to GET
};

/** Auth-shaped layer tokens in the route's ancestor chain (Sem 1). */
function ancestorLayerTokens(routeCall: Node, source: string): string[] {
  const out: string[] = [];
  let cur: Node = routeCall;
  for (;;) {
    const field = cur.parent;
    if (!field || field.type !== 'field_expression') break;
    const operand = field.childForFieldName('value') ?? field.namedChild(0);
    if (!operand || operand.startIndex !== cur.startIndex || operand.endIndex !== cur.endIndex) break;
    const call = field.parent;
    if (!call || call.type !== 'call_expression') break;
    const fieldName = textOf(field.childForFieldName('field'), source);
    if (fieldName === 'layer' || fieldName === 'route_layer') {
      const args = call.childForFieldName('arguments');
      if (args) {
        for (let i = 0; i < args.namedChildCount; i++) {
          const t = textOf(args.namedChild(i)!, source);
          if (t) out.push(t);
        }
      }
    }
    cur = call;
  }
  return out;
}

/** Span of exactly ONE same-file `fn <name>` item, plus its pub-ness. */
function resolveRustFnSpan(root: Node, source: string, name: string): { span: HandlerSpan; isPub: boolean } | null {
  const matches: Array<{ node: Node; isPub: boolean }> = [];
  const walk = (n: Node): void => {
    if (n.type === 'function_item') {
      const nm = n.childForFieldName('name');
      if (nm && textOf(nm, source) === name) {
        let isPub = false;
        for (let i = 0; i < n.namedChildCount; i++) {
          if (n.namedChild(i)!.type === 'visibility_modifier') { isPub = true; break; }
        }
        matches.push({ node: n, isPub });
      }
    }
    for (let i = 0; i < n.namedChildCount; i++) walk(n.namedChild(i)!);
  };
  walk(root);
  if (matches.length !== 1) return null;
  return { span: spanOfNode(matches[0].node), isPub: matches[0].isPub };
}

/** Same-file reference guard: identifier occurrences beyond decl + registration. */
function rustNameRefCount(root: Node, source: string, name: string): number {
  let refs = 0;
  const walk = (n: Node): void => {
    if (n.type === 'identifier' && textOf(n, source) === name) refs++;
    for (let i = 0; i < n.namedChildCount; i++) walk(n.namedChild(i)!);
  };
  walk(root);
  return refs;
}

export const axumDetector: FrameworkDetector = {
  name: 'axum',
  displayName: 'Axum',
  language: 'rust',
  triggerImports: ['axum'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const root = tree.rootNode;
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
                  const handlerName = handlerArg ? textOf(handlerArg, source) : null;

                  // Layer coverage (centralized idiom — the belt applies).
                  const layerTokens = ancestorLayerTokens(node, source)
                    .filter((t) => matchesAuthName(t) && !isOptionalVetoed(t));
                  const result = classifyRoute({
                    vettedAuthTokens: layerTokens,
                    routePattern,
                    centralizedOnly: true,
                  });

                  // Span (Sem 6): same-file named handler fn; pub fns are
                  // callable from other modules → ineligible.
                  let handlerSpan: HandlerSpan | null = null;
                  let demotionEligible = false;
                  if (handlerArg?.type === 'identifier' && handlerName) {
                    const resolved = resolveRustFnSpan(root, source, handlerName);
                    if (resolved) {
                      handlerSpan = resolved.span;
                      demotionEligible = !resolved.isPub && rustNameRefCount(root, source, handlerName) <= 2;
                    }
                  }

                  entryPoints.push({
                    filePath: file.filePath,
                    lineNumber: node.startPosition.row + 1,
                    framework: 'axum',
                    handlerName,
                    httpMethod: VERB_FNS[verbName],
                    routePattern,
                    entryPointType: 'http_route',
                    classification: result.classification,
                    authenticated: result.authenticated,
                    authMechanism: null,
                    middlewareChain: layerTokens.length ? layerTokens : null,
                    handlerSpan,
                    demotionEligible,
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
    walk(root);
    return entryPoints;
  },
};
