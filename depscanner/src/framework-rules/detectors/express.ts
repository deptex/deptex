import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HandlerSpan } from '../types';
import {
  HTTP_METHOD_NAMES,
  detectAuthMechanism,
  findInstancesOfImport,
  handlerDescriptor,
  handlerSpanForArg,
  isNamedHandlerDemotionEligible,
  lineOf,
  stringLiteralValue,
  textOf,
  walkTree,
} from '../util/javascript';
import {
  classifyRoute,
  matchesInternalName,
  matchesPublicOverride,
  prefixCoversRoute,
  type RouteAuthEvidence,
} from '../util/auth-evidence';
import { harvestExpressParams } from '../../param-harvest/express-harvest';

const ROUTE_METHOD_NAMES = new Set([...Object.keys(HTTP_METHOD_NAMES), 'all', 'use']);

/**
 * A middleware argument reduced to two token views: `display` (a clean symbol
 * name for the chain field + the fp-filter prompt) and `classify` (a richer
 * string that also captures string-literal args, so name-pattern vetoes see
 * `passport.authenticate('anonymous')`'s `'anonymous'`).
 */
interface MiddlewareToken {
  display: string;
  classify: string;
}

function middlewareToken(node: Node, source: string): MiddlewareToken | null {
  if (node.type === 'identifier') {
    const t = textOf(node, source);
    return { display: t, classify: t };
  }
  if (node.type === 'member_expression') {
    const t = textOf(node, source);
    return { display: t, classify: t };
  }
  if (node.type === 'call_expression') {
    const fn = node.childForFieldName('function');
    const fnText = fn ? textOf(fn, source) : '';
    // Fold string-literal args into the classify token so `passport.authenticate('anonymous')`
    // and `guard('optional')` are veto-visible without a full arg inspector.
    const argStrings: string[] = [];
    const argsNode = node.childForFieldName('arguments');
    if (argsNode) {
      for (let i = 0; i < argsNode.namedChildCount; i++) {
        const s = stringLiteralValue(argsNode.namedChild(i)!, source);
        if (s) argStrings.push(s);
      }
    }
    if (!fnText) return null;
    return { display: fnText, classify: `${fnText} ${argStrings.join(' ')}`.trim() };
  }
  return null;
}

/** The middleware arg nodes of a route registration (excludes path + terminal handler). */
function routeMiddlewareNodes(args: Node | null): Node[] {
  if (!args) return [];
  const argNodes: Node[] = [];
  for (let i = 0; i < args.namedChildCount; i++) argNodes.push(args.namedChild(i)!);
  const mwNodes = argNodes.slice(0, -1); // drop the terminal handler
  const startIdx = mwNodes.length > 0 && mwNodes[0].type === 'string' ? 1 : 0; // drop the path literal
  return mwNodes.slice(startIdx);
}

/** The middleware arg nodes of a `.use(...)` call (ALL args after the optional path). */
function useMiddlewareNodes(args: Node | null): Node[] {
  if (!args) return [];
  const argNodes: Node[] = [];
  for (let i = 0; i < args.namedChildCount; i++) argNodes.push(args.namedChild(i)!);
  const startIdx = argNodes.length > 0 && argNodes[0].type === 'string' ? 1 : 0;
  return argNodes.slice(startIdx);
}

/** A same-file, top-level `<instance>.use(...)` middleware application (Sem 1b centralized idiom). */
interface CentralUse {
  instance: string;
  line: number;
  /** Mount prefix (null = pathless → covers every route on the instance). */
  prefix: string | null;
  tokens: MiddlewareToken[];
}

/** True when `node` is a program-level statement (no enclosing function/method/arrow). */
function isTopLevel(node: Node): boolean {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    const t = cur.type;
    if (
      t === 'function_declaration' || t === 'function_expression' || t === 'arrow_function' ||
      t === 'generator_function' || t === 'generator_function_declaration' || t === 'method_definition'
    ) {
      return false;
    }
    if (t === 'program') return true;
  }
  return true;
}

/**
 * A same-file inline verifier call is machine evidence (Sem 5): a webhook
 * handler that verifies a signature in its own body (`x.verify(...)`,
 * `stripe.webhooks.constructEvent(...)`). Scanned only inside an inline handler
 * span — cross-file verifier bodies are NOT detectable (documented v1 residual).
 */
function inlineHandlerHasVerifier(handler: Node | null, source: string): string | null {
  if (!handler) return null;
  if (handler.type !== 'arrow_function' && handler.type !== 'function_expression' && handler.type !== 'function_declaration') {
    return null;
  }
  let hit: string | null = null;
  const walk = (n: Node): void => {
    if (hit) return;
    if (n.type === 'call_expression') {
      const fn = n.childForFieldName('function');
      if (fn?.type === 'member_expression') {
        const prop = fn.childForFieldName('property');
        const propName = prop ? textOf(prop, source) : '';
        if (/^verify$/i.test(propName) || /construct_?event/i.test(propName)) {
          hit = textOf(fn, source);
          return;
        }
      }
    }
    for (let i = 0; i < n.namedChildCount; i++) walk(n.namedChild(i)!);
  };
  walk(handler);
  return hit;
}

/** Partition middleware tokens into the three evidence buckets classifyRoute reads. */
function categorize(tokens: MiddlewareToken[]): {
  authTokens: string[];
  internalTokens: string[];
  publicOverrides: string[];
} {
  const authTokens: string[] = [];
  const internalTokens: string[] = [];
  const publicOverrides: string[] = [];
  for (const t of tokens) {
    if (matchesPublicOverride(t.classify)) publicOverrides.push(t.classify);
    else if (matchesInternalName(t.classify)) internalTokens.push(t.classify);
    else authTokens.push(t.classify);
  }
  return { authTokens, internalTokens, publicOverrides };
}

/** Does any token constitute valid (non-veto) route-local auth? Drives centralizedOnly. */
function hasRouteLocalAuth(tokens: MiddlewareToken[]): boolean {
  const { authTokens } = categorize(tokens);
  // classifyRoute applies the same auth-name + optional-veto logic; reuse it via
  // a probe so the definition of "valid auth" stays in one place.
  return classifyRoute({ authTokens }).classification === 'AUTH_INTERNAL';
}

export const expressDetector: FrameworkDetector = {
  name: 'express',
  displayName: 'Express.js',
  language: 'javascript',
  triggerImports: ['express'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const root = tree.rootNode;
    const expressImport = file.imports.find((imp) => imp.source === 'express');
    if (!expressImport?.localName) return [];

    const instances = findInstancesOfImport(root, source, expressImport.localName, {
      extraMethods: ['Router'],
    });
    if (instances.size === 0) return [];

    // Import-derived mechanism hint — kept ONLY for DAST/UI attribution; it no
    // longer decides classification (that now comes from route-level evidence).
    const authMechanismHint = detectAuthMechanism(file.imports);

    // Pre-pass: gather same-file, top-level centralized `<instance>.use(...)`
    // applications (Sem 1b). These cover same-instance routes registered AFTER
    // them (Express applies middleware in source order).
    const centrals: CentralUse[] = [];
    walkTree(tree, (node) => {
      if (node.type !== 'call_expression') return;
      const fn = node.childForFieldName('function');
      if (fn?.type !== 'member_expression') return;
      const object = fn.childForFieldName('object');
      const property = fn.childForFieldName('property');
      if (object?.type !== 'identifier' || property?.type !== 'property_identifier') return;
      if (textOf(property, source) !== 'use') return;
      const instanceName = textOf(object, source);
      if (!instances.has(instanceName)) return;
      if (!isTopLevel(node)) return; // only top-level app.use(...) is a global guard
      const args = node.childForFieldName('arguments');
      const firstArg = args?.namedChild(0) ?? null;
      const prefix = firstArg && firstArg.type === 'string' ? stringLiteralValue(firstArg, source) : null;
      const tokens = useMiddlewareNodes(args)
        .map((n) => middlewareToken(n, source))
        .filter((t): t is MiddlewareToken => t !== null);
      if (tokens.length === 0) return;
      centrals.push({ instance: instanceName, line: lineOf(node), prefix, tokens });
    });

    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'call_expression') return;
      const fn = node.childForFieldName('function');
      if (fn?.type !== 'member_expression') return;
      const object = fn.childForFieldName('object');
      const property = fn.childForFieldName('property');
      if (object?.type !== 'identifier' || property?.type !== 'property_identifier') return;
      const instanceName = textOf(object, source);
      const methodName = textOf(property, source);
      if (!instances.has(instanceName) || !ROUTE_METHOD_NAMES.has(methodName)) return;

      const args = node.childForFieldName('arguments');
      const routeArg = args?.namedChild(0) ?? null;
      const routePattern = stringLiteralValue(routeArg, source);
      if (!routePattern) return;

      const lastArg = args ? args.namedChild(args.namedChildCount - 1) : null;
      const handlerName = handlerDescriptor(lastArg, source);
      const routeLine = lineOf(node);
      const requestParams = harvestExpressParams(lastArg, source);

      // `.use('/prefix', router)` is a mount, not a request handler — emit it as
      // a coarse row (public, no span) so it never demotes a flow.
      const isMount = methodName === 'use';

      const routeTokens = isMount
        ? []
        : routeMiddlewareNodes(args).map((n) => middlewareToken(n, source)).filter((t): t is MiddlewareToken => t !== null);

      // Centralized tokens applicable to THIS route: same instance, applied
      // before the route line, and covering the route path (pathless or
      // segment-bounded prefix).
      const centralTokens: MiddlewareToken[] = [];
      if (!isMount) {
        for (const c of centrals) {
          if (c.instance !== instanceName) continue;
          if (c.line >= routeLine) continue;
          if (!prefixCoversRoute(c.prefix, routePattern)) continue;
          centralTokens.push(...c.tokens);
        }
      }

      // Same-file inline verifier body → machine (OFFLINE_WORKER) evidence.
      const verifierHit = isMount ? null : inlineHandlerHasVerifier(lastArg, source);

      let classification: EntryPoint['classification'] = 'PUBLIC_UNAUTH';
      let authenticated = false;
      if (!isMount) {
        const allTokens = [...routeTokens, ...centralTokens];
        const { authTokens, internalTokens, publicOverrides } = categorize(allTokens);
        if (verifierHit) internalTokens.push(verifierHit);
        const evidence: RouteAuthEvidence = {
          authTokens,
          internalTokens,
          publicOverrides,
          routePattern,
          // The belt only blocks a demotion that rests SOLELY on a centralized
          // idiom; a route-local guard still demotes a belt route.
          centralizedOnly: !hasRouteLocalAuth(routeTokens) && !verifierHit,
        };
        const result = classifyRoute(evidence);
        classification = result.classification;
        authenticated = result.authenticated;
      }

      // Span capture (Sem 6): only real handlers, never mounts.
      let handlerSpan: HandlerSpan | null = null;
      let demotionEligible = false;
      if (!isMount && lastArg) {
        handlerSpan = handlerSpanForArg(lastArg, root, source);
        if (handlerSpan) {
          if (lastArg.type === 'identifier') {
            demotionEligible = isNamedHandlerDemotionEligible(root, source, textOf(lastArg, source));
          } else {
            // Inline function/arrow — can't be referenced elsewhere, always eligible.
            demotionEligible = true;
          }
        }
      }

      const displayChain = [...routeTokens, ...centralTokens].map((t) => t.display);

      entryPoints.push({
        filePath: file.filePath,
        lineNumber: routeLine,
        framework: 'express',
        handlerName,
        httpMethod: HTTP_METHOD_NAMES[methodName] ?? null,
        routePattern,
        entryPointType: 'http_route',
        classification,
        authenticated,
        authMechanism: authMechanismHint,
        middlewareChain: displayChain.length ? displayChain : null,
        handlerSpan,
        demotionEligible,
        metadata: { instance: instanceName, call: `${instanceName}.${methodName}` },
        requestParams,
      });
    });

    return entryPoints;
  },
};
