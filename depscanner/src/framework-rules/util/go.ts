import type { Node, Tree } from 'web-tree-sitter';
import type { EntryPoint, EntryPointClassification, HandlerSpan, HttpMethod } from '../types';
import type { ImportBinding } from '../../tree-sitter-extractor/languages/types';
import {
  categorizeMiddlewareTokens,
  classifyRoute,
  hasRouteLocalAuth,
  spanOfNode,
  type MiddlewareToken,
} from './auth-evidence';

export function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

export function goStringLiteral(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type !== 'interpreted_string_literal' && node.type !== 'raw_string_literal') return null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'interpreted_string_literal_content' || c.type === 'raw_string_literal_content') {
      return textOf(c, source);
    }
  }
  const raw = textOf(node, source);
  const m = raw.match(/^["`](.*)["`]$/s);
  return m ? m[1] : null;
}

export function lineOf(node: Node): number {
  return node.startPosition.row + 1;
}

export function walkTree(tree: Tree, visit: (node: Node) => void): void {
  const walk = (node: Node): void => {
    visit(node);
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(tree.rootNode);
}

/**
 * Find identifiers assigned from calling any of the given package-qualified
 * factory names. For `r := gin.Default()` with `factories = [{pkgAlias:'gin',
 * fn:'Default'}]`, returns `{'r'}`. Handles both `:=` (short_var_declaration)
 * and `=` assignment.
 */
export function findInstancesFromFactory(
  root: Node,
  source: string,
  factories: ReadonlyArray<{ pkgAlias: string; fn: string }>
): Set<string> {
  const out = new Set<string>();

  const matchesFactory = (call: Node): boolean => {
    const fn = call.childForFieldName('function');
    if (fn?.type !== 'selector_expression') return false;
    const operand = fn.childForFieldName('operand');
    const field = fn.childForFieldName('field');
    if (operand?.type !== 'identifier' || !field) return false;
    const op = textOf(operand, source);
    const fname = textOf(field, source);
    return factories.some((f) => f.pkgAlias === op && f.fn === fname);
  };

  const walk = (node: Node): void => {
    if (node.type === 'short_var_declaration' || node.type === 'assignment_statement') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      if (left?.type === 'expression_list' && right?.type === 'expression_list') {
        if (left.namedChildCount === 1 && right.namedChildCount === 1) {
          const l = left.namedChild(0)!;
          const r = right.namedChild(0)!;
          if (l.type === 'identifier' && r.type === 'call_expression' && matchesFactory(r)) {
            out.add(textOf(l, source));
          }
        }
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(root);
  return out;
}

/** Go auth-flavored packages. */
export const GO_AUTH_PACKAGES: ReadonlyArray<{ prefix: string; mechanism: string }> = [
  { prefix: 'github.com/golang-jwt/jwt', mechanism: 'bearer_jwt' },
  { prefix: 'github.com/dgrijalva/jwt-go', mechanism: 'bearer_jwt' },
  { prefix: 'github.com/lestrrat-go/jwx', mechanism: 'bearer_jwt' },
  { prefix: 'github.com/gorilla/sessions', mechanism: 'session_cookie' },
  { prefix: 'github.com/gin-contrib/sessions', mechanism: 'session_cookie' },
];

export function detectGoAuthMechanism(imports: readonly ImportBinding[]): string | null {
  for (const imp of imports) {
    const hit = GO_AUTH_PACKAGES.find((p) => imp.source === p.prefix || imp.source.startsWith(`${p.prefix}/`));
    if (hit) return hit.mechanism;
  }
  return null;
}

export function classifyFromAuth(auth: string | null): EntryPointClassification {
  return auth ? 'AUTH_INTERNAL' : 'PUBLIC_UNAUTH';
}

/** Normalize handler display — returns the selector text or identifier name. */
export function handlerTextOf(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type === 'identifier') return textOf(node, source);
  if (node.type === 'selector_expression') return textOf(node, source);
  if (node.type === 'func_literal') return '(anonymous)';
  return null;
}

export const GO_HTTP_METHODS_UPPER: Record<string, HttpMethod> = {
  GET: 'GET', POST: 'POST', PUT: 'PUT', PATCH: 'PATCH',
  DELETE: 'DELETE', HEAD: 'HEAD', OPTIONS: 'OPTIONS',
};

export const GO_HTTP_METHODS_PASCAL: Record<string, HttpMethod> = {
  Get: 'GET', Post: 'POST', Put: 'PUT', Patch: 'PATCH',
  Delete: 'DELETE', Head: 'HEAD', Options: 'OPTIONS',
};

/**
 * Find `<instanceName>.<Method>(pattern, handler)` call-expressions where
 * Method is in the allowed verb table. Returns matched data ready for
 * entry-point emission.
 */
export interface RouteCall {
  node: Node;
  methodName: string;
  routePattern: string;
  handlerName: string | null;
  /** Terminal handler argument node (span capture, Sem 6). */
  handlerArg: Node | null;
  /** Per-route middleware tokens: middle args + any `.With(...)` chain. */
  middlewareTokens: MiddlewareToken[];
  /** Receiver instance the route was registered on (chain-rooted for .With). */
  instance: string | null;
}

export function findRouteCalls(
  tree: Tree,
  source: string,
  instances: Set<string>,
  verbTable: Record<string, HttpMethod>,
  extraMethods: readonly string[] = []
): Array<RouteCall & { httpMethod: HttpMethod | null }> {
  const out: Array<RouteCall & { httpMethod: HttpMethod | null }> = [];
  const extras = new Set(extraMethods);
  walkTree(tree, (node) => {
    if (node.type !== 'call_expression') return;
    const fn = node.childForFieldName('function');
    if (fn?.type !== 'selector_expression') return;
    const operand = fn.childForFieldName('operand');
    const field = fn.childForFieldName('field');
    if (!field) return;
    const method = textOf(field, source);
    const isVerb = method in verbTable;
    const isExtra = extras.has(method);
    if (!isVerb && !isExtra) return;

    // Receiver forms: a tracked instance identifier, or a chi-style
    // `<instance>.With(mw...)` chain (`r.With(auth).Get(...)`).
    let withTokens: MiddlewareToken[] = [];
    let matched = false;
    let instanceName: string | null = null;
    if (operand?.type === 'identifier') {
      instanceName = textOf(operand, source);
      matched = instances.has(instanceName);
    } else if (operand?.type === 'call_expression') {
      const chain = parseWithChain(operand, source, instances);
      if (chain) {
        matched = true;
        withTokens = chain.tokens;
        instanceName = chain.rootInstance;
      }
    }
    if (!matched) return;

    const args = node.childForFieldName('arguments');
    const firstArg = args?.namedChild(0);
    const routePattern = goStringLiteral(firstArg ?? null, source);
    if (!routePattern) return;
    const handlerArg = args ? args.namedChild(args.namedChildCount - 1) : null;

    // Middle args (between the path and the terminal handler) are per-route
    // middleware (gin/echo variadic style).
    const middlewareTokens: MiddlewareToken[] = [...withTokens];
    if (args) {
      for (let i = 1; i < args.namedChildCount - 1; i++) {
        const t = goMiddlewareToken(args.namedChild(i)!, source);
        if (t) middlewareTokens.push(t);
      }
    }
    // A wrapped terminal handler (`requireAuth(handler)`) carries its wrapper
    // as middleware evidence — the route classifies from the wrapper name; the
    // span resolves from the inner handler (goHandlerSpan).
    if (handlerArg?.type === 'call_expression') {
      const wrapper = goMiddlewareToken(handlerArg, source);
      if (wrapper) middlewareTokens.push(wrapper);
    }

    out.push({
      node,
      methodName: method,
      routePattern,
      handlerName: handlerTextOf(handlerArg, source),
      httpMethod: isVerb ? verbTable[method] : null,
      handlerArg,
      middlewareTokens,
      instance: instanceName,
    });
  });
  return out;
}

/**
 * Parse a `<instance>.With(mw...)` receiver chain (possibly nested:
 * `r.With(a).With(b)`). Returns the collected middleware tokens + root instance
 * when the chain roots at a tracked instance, else null.
 */
function parseWithChain(
  call: Node,
  source: string,
  instances: Set<string>,
): { tokens: MiddlewareToken[]; rootInstance: string } | null {
  const fn = call.childForFieldName('function');
  if (fn?.type !== 'selector_expression') return null;
  const field = fn.childForFieldName('field');
  if (!field || textOf(field, source) !== 'With') return null;
  const operand = fn.childForFieldName('operand');
  let inherited: { tokens: MiddlewareToken[]; rootInstance: string } | null = null;
  if (operand?.type === 'identifier') {
    const name = textOf(operand, source);
    inherited = instances.has(name) ? { tokens: [], rootInstance: name } : null;
  } else if (operand?.type === 'call_expression') {
    inherited = parseWithChain(operand, source, instances);
  }
  if (inherited === null) return null;
  const tokens = [...inherited.tokens];
  const args = call.childForFieldName('arguments');
  if (args) {
    for (let i = 0; i < args.namedChildCount; i++) {
      const t = goMiddlewareToken(args.namedChild(i)!, source);
      if (t) tokens.push(t);
    }
  }
  return { tokens, rootInstance: inherited.rootInstance };
}

// ---------------------------------------------------------------------------
// Go route-auth evidence (entry-point auth classification, T8).
// ---------------------------------------------------------------------------

/** A Go middleware argument → evidence token (identifier / selector / call). */
export function goMiddlewareToken(node: Node, source: string): MiddlewareToken | null {
  if (node.type === 'identifier' || node.type === 'selector_expression') {
    const t = textOf(node, source);
    return { display: t, classify: t };
  }
  if (node.type === 'call_expression') {
    const fn = node.childForFieldName('function');
    const fnText = fn ? textOf(fn, source) : '';
    if (!fnText) return null;
    const argStrings: string[] = [];
    const args = node.childForFieldName('arguments');
    if (args) {
      for (let i = 0; i < args.namedChildCount; i++) {
        const s = goStringLiteral(args.namedChild(i)!, source);
        if (s) argStrings.push(s);
      }
    }
    return { display: fnText, classify: `${fnText} ${argStrings.join(' ')}`.trim() };
  }
  return null;
}

/** A same-file, same-scope `<instance>.Use(mw...)` application. */
export interface GoUse {
  instance: string;
  line: number;
  tokens: MiddlewareToken[];
}

/**
 * Collect `<instance>.Use(mw...)` middleware applications (chi/gin/echo/fiber/
 * gorilla all apply Use'd middleware to routes registered AFTER it on the same
 * instance). Tokens go through the shared name patterns, so chi's parse-only
 * `jwtauth.Verifier` never matches while `jwtauth.Authenticator` does
 * (parse-vs-enforce falls out of the pattern set).
 */
export function findUseCalls(tree: Tree, source: string, instances: Set<string>): GoUse[] {
  const out: GoUse[] = [];
  walkTree(tree, (node) => {
    if (node.type !== 'call_expression') return;
    const fn = node.childForFieldName('function');
    if (fn?.type !== 'selector_expression') return;
    const operand = fn.childForFieldName('operand');
    const field = fn.childForFieldName('field');
    if (operand?.type !== 'identifier' || !field) return;
    if (textOf(field, source) !== 'Use') return;
    const instance = textOf(operand, source);
    if (!instances.has(instance)) return;
    const tokens: MiddlewareToken[] = [];
    const args = node.childForFieldName('arguments');
    if (args) {
      for (let i = 0; i < args.namedChildCount; i++) {
        const t = goMiddlewareToken(args.namedChild(i)!, source);
        if (t) tokens.push(t);
      }
    }
    if (tokens.length > 0) out.push({ instance, line: lineOf(node), tokens });
  });
  return out;
}

/**
 * Track sub-router instances derived from a tracked parent:
 * `s := r.PathPrefix("/x").Subrouter()` (gorilla) — adds `s` to the instance
 * set so its Use/route calls are visible.
 */
export function addSubrouterInstances(tree: Tree, source: string, instances: Set<string>): void {
  // Collect every `x := <chain>.Subrouter()` declaration in ONE tree walk as a
  // child→root edge, then propagate reachability from the seed instances with a
  // worklist. The old `while (grew) { walkTree(entire tree) }` re-walked the whole
  // tree once per newly-discovered subrouter — O(passes × tree) = O(file²) on a
  // reverse-ordered chain, a DoS vector on an untrusted repo. This is O(tree) for
  // the single walk + O(edges) for the propagation.
  const childrenByRoot = new Map<string, string[]>();
  walkTree(tree, (node) => {
    if (node.type !== 'short_var_declaration' && node.type !== 'assignment_statement') return;
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');
    if (left?.type !== 'expression_list' || right?.type !== 'expression_list') return;
    if (left.namedChildCount !== 1 || right.namedChildCount !== 1) return;
    const l = left.namedChild(0)!;
    const r = right.namedChild(0)!;
    if (l.type !== 'identifier' || r.type !== 'call_expression') return;
    const fn = r.childForFieldName('function');
    if (fn?.type !== 'selector_expression') return;
    const field = fn.childForFieldName('field');
    if (!field || textOf(field, source) !== 'Subrouter') return;
    // Root the chain at its base identifier.
    let cur: Node | null = fn.childForFieldName('operand');
    while (cur && cur.type === 'call_expression') {
      const innerFn: Node | null = cur.childForFieldName('function');
      cur = innerFn?.type === 'selector_expression' ? innerFn.childForFieldName('operand') : null;
    }
    if (cur?.type !== 'identifier') return;
    const rootName = textOf(cur, source);
    const childName = textOf(l, source);
    const arr = childrenByRoot.get(rootName);
    if (arr) arr.push(childName);
    else childrenByRoot.set(rootName, [childName]);
  });
  // Any subrouter rooted at a tracked instance is itself tracked (transitively).
  const worklist: string[] = [...instances];
  while (worklist.length > 0) {
    const name = worklist.pop()!;
    const children = childrenByRoot.get(name);
    if (!children) continue;
    for (const child of children) {
      if (!instances.has(child)) {
        instances.add(child);
        worklist.push(child);
      }
    }
  }
}

/**
 * Handler-span capture for a Go route (Sem 6). Inline `func literal` → its own
 * span, always demotion-eligible. Bare identifier → the span of exactly ONE
 * same-file `function_declaration`; eligible only when the name is unexported
 * (lowercase — an exported handler is callable from other packages) AND not
 * referenced elsewhere in this file beyond declaration + registration.
 * Same-package sibling-file references are NOT visible here (documented
 * residual — the accepted rare wrongful-demote shape in the plan's risk list).
 * Wrapped handlers (`authMw(h)`): classified by the caller from the wrapper
 * token; the span resolves from the INNER argument when it is a same-file
 * named func.
 */
export function goHandlerSpan(
  tree: Tree,
  source: string,
  handlerArg: Node | null,
): { span: HandlerSpan | null; eligible: boolean } {
  if (!handlerArg) return { span: null, eligible: false };
  if (handlerArg.type === 'func_literal') {
    return { span: spanOfNode(handlerArg), eligible: true };
  }
  if (handlerArg.type === 'identifier') {
    const name = textOf(handlerArg, source);
    const span = resolveGoFuncSpan(tree, source, name);
    if (!span) return { span: null, eligible: false };
    return { span, eligible: isGoNamedHandlerEligible(tree, source, name) };
  }
  if (handlerArg.type === 'call_expression') {
    // Wrapped: authMw(h) — span from the single inner identifier arg if it
    // resolves same-file; the wrapper itself is middleware evidence.
    const args = handlerArg.childForFieldName('arguments');
    if (args?.namedChildCount === 1 && args.namedChild(0)?.type === 'identifier') {
      const inner = args.namedChild(0)!;
      const name = textOf(inner, source);
      const span = resolveGoFuncSpan(tree, source, name);
      if (span) return { span, eligible: isGoNamedHandlerEligible(tree, source, name) };
    }
    return { span: null, eligible: false };
  }
  return { span: null, eligible: false };
}

/**
 * Per-file Go index — function-declaration spans (null when a name is declared
 * more than once → ambiguous) and identifier reference counts — built in ONE
 * tree walk and memoized on the Tree object. `goHandlerSpan` runs per route, so
 * resolving the span + eligibility by re-walking the whole tree each call was
 * O(routes × nodes) = O(file²), a DoS vector on an untrusted repo with many
 * routes; the index makes each per-route lookup O(1).
 */
interface GoFileIndex {
  funcSpans: Map<string, HandlerSpan | null>;
  refCounts: Map<string, number>;
}
const goFileIndexCache = new WeakMap<Tree, GoFileIndex>();
function goFileIndex(tree: Tree, source: string): GoFileIndex {
  const cached = goFileIndexCache.get(tree);
  if (cached) return cached;
  const decls = new Map<string, { node: Node; count: number }>();
  const refCounts = new Map<string, number>();
  walkTree(tree, (n) => {
    if (n.type === 'function_declaration') {
      const nm = n.childForFieldName('name');
      if (nm) {
        const name = textOf(nm, source);
        const e = decls.get(name);
        if (e) e.count++;
        else decls.set(name, { node: n, count: 1 });
      }
    } else if (n.type === 'identifier') {
      const t = textOf(n, source);
      refCounts.set(t, (refCounts.get(t) ?? 0) + 1);
    }
  });
  const funcSpans = new Map<string, HandlerSpan | null>();
  for (const [name, e] of decls) funcSpans.set(name, e.count === 1 ? spanOfNode(e.node) : null);
  const index: GoFileIndex = { funcSpans, refCounts };
  goFileIndexCache.set(tree, index);
  return index;
}

/** Span of exactly ONE same-file `func <name>(...)` declaration, else null. */
export function resolveGoFuncSpan(tree: Tree, source: string, name: string): HandlerSpan | null {
  return goFileIndex(tree, source).funcSpans.get(name) ?? null;
}

/**
 * Go demotion-eligibility guard (Sem 6): exported (capitalized) handlers are
 * callable from other packages → ineligible; unexported handlers are ineligible
 * when referenced in this file beyond declaration + one registration.
 */
export function isGoNamedHandlerEligible(tree: Tree, source: string, name: string): boolean {
  if (/^[A-Z]/.test(name)) return false;
  return (goFileIndex(tree, source).refCounts.get(name) ?? 0) <= 2;
}

/**
 * Classify a Go route from its per-route middleware + the instance's prior
 * `Use` applications (Sem 1/10/11 — Use is the centralized idiom, so the belt
 * protects belt routes from Use-only demotions).
 */
export function classifyGoRoute(opts: {
  routeTokens: MiddlewareToken[];
  useTokens: MiddlewareToken[];
  routePattern: string | null;
}): { classification: EntryPointClassification; authenticated: boolean } {
  const all = [...opts.routeTokens, ...opts.useTokens];
  const { authTokens, internalTokens, publicOverrides } = categorizeMiddlewareTokens(all);
  const result = classifyRoute({
    authTokens,
    internalTokens,
    publicOverrides,
    routePattern: opts.routePattern,
    centralizedOnly: !hasRouteLocalAuth(opts.routeTokens),
  });
  return { classification: result.classification, authenticated: result.authenticated };
}

/**
 * Assemble a Go route's EntryPoint from its RouteCall + the instance's `Use`
 * applications (before the route line) + span/eligibility. The single shared
 * emission path for gin/echo/fiber/chi so their evidence handling can't
 * diverge; nethttp/gorilla assemble inline (custom walks) but reuse the same
 * helpers.
 */
export function buildGoRouteEntryPoint(opts: {
  call: RouteCall & { httpMethod: HttpMethod | null };
  tree: Tree;
  source: string;
  filePath: string;
  framework: string;
  authMechanismHint: string | null;
  uses: GoUse[];
  metadata: Record<string, unknown> | null;
}): EntryPoint {
  const { call, tree, source } = opts;
  const useTokens = opts.uses
    .filter((u) => call.instance !== null && u.instance === call.instance && u.line < lineOf(call.node))
    .flatMap((u) => u.tokens);
  const { classification, authenticated } = classifyGoRoute({
    routeTokens: call.middlewareTokens,
    useTokens,
    routePattern: call.routePattern,
  });
  const { span, eligible } = goHandlerSpan(tree, source, call.handlerArg);
  const allTokens = [...call.middlewareTokens, ...useTokens];
  return {
    filePath: opts.filePath,
    lineNumber: lineOf(call.node),
    framework: opts.framework,
    handlerName: call.handlerName,
    httpMethod: call.httpMethod,
    routePattern: call.routePattern,
    entryPointType: 'http_route',
    classification,
    authenticated,
    authMechanism: opts.authMechanismHint,
    middlewareChain: allTokens.length ? allTokens.map((t) => t.display) : null,
    handlerSpan: span,
    demotionEligible: eligible,
    metadata: opts.metadata,
  };
}
