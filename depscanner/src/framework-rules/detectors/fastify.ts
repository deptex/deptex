import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HandlerSpan } from '../types';
import {
  HTTP_METHOD_NAMES,
  categorizeMiddlewareTokens,
  detectAuthMechanism,
  findInstancesOfImport,
  handlerDescriptor,
  handlerSpanForArg,
  hasRouteLocalAuth,
  isNamedHandlerDemotionEligible,
  lineOf,
  middlewareToken,
  stringLiteralValue,
  textOf,
  walkTree,
  type MiddlewareToken,
} from '../util/javascript';
import { classifyRoute } from '../util/auth-evidence';

// Fastify's typical shape:
//   const fastify = require('fastify')({ logger: true });
//   // or: import Fastify from 'fastify'; const app = Fastify();
//   fastify.get('/path', handler);
//   fastify.get('/path', { preHandler: [fastify.authenticate] }, handler);
//   fastify.route({ method: 'GET', url: '/path', preHandler, handler });
//   fastify.addHook('onRequest', fastify.authenticate);   // context-wide hook
const ROUTE_METHOD_NAMES = new Set([...Object.keys(HTTP_METHOD_NAMES), 'all']);

/** Route-option / addHook lifecycle keys that run before the handler (auth surface). */
const AUTH_HOOK_KEYS = new Set(['onRequest', 'preHandler', 'preValidation', 'preParsing']);

/** Collect middleware tokens from a hook value: identifier / member / call / array-of-those. */
function hookValueTokens(value: Node | null, source: string): MiddlewareToken[] {
  if (!value) return [];
  if (value.type === 'array') {
    const out: MiddlewareToken[] = [];
    for (let i = 0; i < value.namedChildCount; i++) {
      const t = middlewareToken(value.namedChild(i)!, source);
      if (t) out.push(t);
    }
    return out;
  }
  const t = middlewareToken(value, source);
  return t ? [t] : [];
}

/** Read `{ preHandler: ..., onRequest: ... }` auth-hook tokens from an options object node. */
function optionsHookTokens(opts: Node | null, source: string): MiddlewareToken[] {
  if (!opts || opts.type !== 'object') return [];
  const tokens: MiddlewareToken[] = [];
  for (let i = 0; i < opts.namedChildCount; i++) {
    const prop = opts.namedChild(i)!;
    if (prop.type !== 'pair') continue;
    const key = prop.childForFieldName('key');
    const keyName = key
      ? (key.type === 'string' ? stringLiteralValue(key, source) : textOf(key, source))
      : null;
    if (!keyName || !AUTH_HOOK_KEYS.has(keyName)) continue;
    tokens.push(...hookValueTokens(prop.childForFieldName('value'), source));
  }
  return tokens;
}

/**
 * Scope key for Fastify hook encapsulation: the nearest enclosing function-ish
 * node's startIndex, or -1 for the program top level. A context-wide `addHook`
 * covers only routes registered on the same instance in the SAME scope —
 * fastify plugins encapsulate hooks, and the enclosing function is our cheap
 * same-file approximation of the plugin boundary.
 */
function scopeKeyOf(node: Node): number {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    const t = cur.type;
    if (
      t === 'function_declaration' || t === 'function_expression' || t === 'arrow_function' ||
      t === 'generator_function' || t === 'generator_function_declaration' || t === 'method_definition'
    ) {
      return cur.startIndex;
    }
  }
  return -1;
}

/** True when the call sits under a conditional between itself and its scope (Sem 3). */
function isConditionallyApplied(node: Node): boolean {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    const t = cur.type;
    if (t === 'if_statement' || t === 'else_clause' || t === 'ternary_expression'
      || t === 'conditional_expression' || t === 'switch_statement') {
      return true;
    }
    if (
      t === 'function_declaration' || t === 'function_expression' || t === 'arrow_function'
      || t === 'generator_function' || t === 'generator_function_declaration'
      || t === 'method_definition' || t === 'program'
    ) {
      return false;
    }
  }
  return false;
}

interface ContextHook {
  instance: string;
  scopeKey: number;
  tokens: MiddlewareToken[];
}

export const fastifyDetector: FrameworkDetector = {
  name: 'fastify',
  displayName: 'Fastify',
  language: 'javascript',
  triggerImports: ['fastify'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const root = tree.rootNode;
    const imp = file.imports.find((i) => i.source === 'fastify');
    if (!imp?.localName) return [];

    const instances = findInstancesOfImport(root, source, imp.localName, { includeNew: true });
    // Fastify's idiomatic form is `const fastify = require('fastify')({...})`,
    // which binds the local name directly to an instance (flagged as
    // cjs-require-iife by the extractor).
    if (imp.kind === 'cjs-require-iife') instances.add(imp.localName);
    if (instances.size === 0) return [];

    // Import hint only — classification comes from route/hook evidence.
    const authMechanismHint = detectAuthMechanism(file.imports);

    // Pre-pass: context-wide auth hooks (`addHook('onRequest', authFn)`).
    // Fastify applies a context's hooks to every route in that encapsulation
    // context regardless of registration order, so no before/after check — but
    // the hook must be in the same (function) scope, and not conditionally
    // applied.
    const contextHooks: ContextHook[] = [];
    walkTree(tree, (node) => {
      if (node.type !== 'call_expression') return;
      const fn = node.childForFieldName('function');
      if (fn?.type !== 'member_expression') return;
      const object = fn.childForFieldName('object');
      const property = fn.childForFieldName('property');
      if (object?.type !== 'identifier' || property?.type !== 'property_identifier') return;
      if (textOf(property, source) !== 'addHook') return;
      const instanceName = textOf(object, source);
      if (!instances.has(instanceName)) return;
      if (isConditionallyApplied(node)) return;
      const args = node.childForFieldName('arguments');
      const hookName = stringLiteralValue(args?.namedChild(0) ?? null, source);
      if (!hookName || !AUTH_HOOK_KEYS.has(hookName)) return;
      const tokens: MiddlewareToken[] = [];
      for (let i = 1; i < (args?.namedChildCount ?? 0); i++) {
        const t = middlewareToken(args!.namedChild(i)!, source);
        if (t) tokens.push(t);
      }
      if (tokens.length === 0) return;
      contextHooks.push({ instance: instanceName, scopeKey: scopeKeyOf(node), tokens });
    });

    const entryPoints: EntryPoint[] = [];

    const pushRoute = (opts: {
      node: Node;
      instanceName: string;
      call: string;
      routePattern: string;
      httpMethod: EntryPoint['httpMethod'];
      handlerNode: Node | null;
      routeTokens: MiddlewareToken[];
    }): void => {
      const { node, instanceName, call, routePattern, httpMethod, handlerNode, routeTokens } = opts;

      // Context hooks covering this route: same instance + same scope.
      const routeScope = scopeKeyOf(node);
      const hookTokens: MiddlewareToken[] = [];
      for (const h of contextHooks) {
        if (h.instance === instanceName && h.scopeKey === routeScope) hookTokens.push(...h.tokens);
      }

      const allTokens = [...routeTokens, ...hookTokens];
      const { authTokens, internalTokens, publicOverrides } = categorizeMiddlewareTokens(allTokens);
      const result = classifyRoute({
        authTokens,
        internalTokens,
        publicOverrides,
        routePattern,
        // Route-options hooks are route-local evidence; addHook-only coverage is
        // the centralized idiom the belt guards (Sem 10).
        centralizedOnly: !hasRouteLocalAuth(routeTokens),
      });

      // Span capture (Sem 6): terminal handler only.
      let handlerSpan: HandlerSpan | null = null;
      let demotionEligible = false;
      if (handlerNode) {
        handlerSpan = handlerSpanForArg(handlerNode, root, source);
        if (handlerSpan) {
          demotionEligible = handlerNode.type === 'identifier'
            ? isNamedHandlerDemotionEligible(root, source, textOf(handlerNode, source))
            : true;
        }
      }

      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(node),
        framework: 'fastify',
        handlerName: handlerDescriptor(handlerNode, source),
        httpMethod,
        routePattern,
        entryPointType: 'http_route',
        classification: result.classification,
        authenticated: result.authenticated,
        authMechanism: authMechanismHint,
        middlewareChain: allTokens.length ? allTokens.map((t) => t.display) : null,
        handlerSpan,
        demotionEligible,
        metadata: { instance: instanceName, call },
      });
    };

    walkTree(tree, (node) => {
      if (node.type !== 'call_expression') return;
      const fn = node.childForFieldName('function');
      if (fn?.type !== 'member_expression') return;
      const object = fn.childForFieldName('object');
      const property = fn.childForFieldName('property');
      if (object?.type !== 'identifier' || property?.type !== 'property_identifier') return;
      const instanceName = textOf(object, source);
      const methodName = textOf(property, source);
      if (!instances.has(instanceName)) return;

      const args = node.childForFieldName('arguments');
      if (!args) return;

      if (ROUTE_METHOD_NAMES.has(methodName)) {
        const routeArg = args.namedChild(0);
        const routePattern = stringLiteralValue(routeArg, source);
        if (!routePattern) return;
        const lastArg = args.namedChild(args.namedChildCount - 1);
        // Shorthand with options: get(path, opts, handler) — opts is the middle
        // object arg. get(path, handler) has no opts.
        const optsArg = args.namedChildCount >= 3 && args.namedChild(1)?.type === 'object'
          ? args.namedChild(1)
          : null;
        // Guard the degenerate `get(path, opts)` shape (handler inside opts is
        // not modeled here): if the last arg IS the options object, no handler.
        const handlerNode = lastArg && lastArg !== optsArg ? lastArg : null;
        pushRoute({
          node,
          instanceName,
          call: `${instanceName}.${methodName}`,
          routePattern,
          httpMethod: HTTP_METHOD_NAMES[methodName] ?? null,
          handlerNode,
          routeTokens: optionsHookTokens(optsArg, source),
        });
      } else if (methodName === 'route') {
        // fastify.route({ method: 'GET', url: '/path', preHandler, handler })
        const configArg = args.namedChild(0);
        if (configArg?.type !== 'object') return;
        let methodStr: string | null = null;
        let urlStr: string | null = null;
        let handlerNode: Node | null = null;
        for (let i = 0; i < configArg.namedChildCount; i++) {
          const prop = configArg.namedChild(i)!;
          if (prop.type !== 'pair') continue;
          const key = prop.childForFieldName('key');
          const value = prop.childForFieldName('value');
          const keyName = key?.type === 'property_identifier' || key?.type === 'string'
            ? (key.type === 'string' ? stringLiteralValue(key, source) : textOf(key, source))
            : null;
          if (keyName === 'method') methodStr = stringLiteralValue(value ?? null, source);
          else if (keyName === 'url') urlStr = stringLiteralValue(value ?? null, source);
          else if (keyName === 'handler') handlerNode = value ?? null;
        }
        if (!urlStr) return;
        pushRoute({
          node,
          instanceName,
          call: `${instanceName}.route`,
          routePattern: urlStr,
          httpMethod: (methodStr?.toUpperCase() as EntryPoint['httpMethod']) ?? null,
          handlerNode,
          routeTokens: optionsHookTokens(configArg, source),
        });
      }
    });

    return entryPoints;
  },
};
