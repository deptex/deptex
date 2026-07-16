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
  isTopLevelStatement,
  lineOf,
  middlewareToken,
  stringLiteralValue,
  textOf,
  walkTree,
  type MiddlewareToken,
} from '../util/javascript';
import { classifyRoute } from '../util/auth-evidence';

// Koa shape:
//   const Koa = require('koa'); const app = new Koa();
//   const Router = require('@koa/router'); const router = new Router();
//   router.get('/path', requireAuth, handler);      // middle args = middleware
//   app.use(jwt({ secret }).unless({ path: [...] })); // centralized (carve-out!)
//   app.use(router.routes());                        // mount
const ROUTE_METHOD_NAMES = new Set([...Object.keys(HTTP_METHOD_NAMES), 'all']);

/**
 * koa-jwt's `.unless({...})` makes coverage a carve-out (Sem 3): some paths are
 * deliberately exempt, and we can't resolve which — so the token is NOT auth
 * evidence for any route.
 */
function isUnlessCarveOut(token: MiddlewareToken): boolean {
  return /\.unless\b/.test(token.classify);
}

/** A top-level `app.use(<mw>)` on a Koa app instance. */
interface AppUse {
  app: string;
  line: number;
  tokens: MiddlewareToken[];
}

export const koaDetector: FrameworkDetector = {
  name: 'koa',
  displayName: 'Koa',
  language: 'javascript',
  triggerImports: ['koa', '@koa/router', 'koa-router'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const root = tree.rootNode;

    // Find instances for either Koa itself (app) or a koa-router Router
    // (router). Both are instantiated via `new`.
    const appImport = file.imports.find((i) => i.source === 'koa');
    const routerImport = file.imports.find((i) => i.source === '@koa/router' || i.source === 'koa-router');

    const routerInstances = routerImport?.localName
      ? findInstancesOfImport(root, source, routerImport.localName, { includeNew: true })
      : new Set<string>();

    if (routerInstances.size === 0 && !appImport) return [];

    const appInstances = appImport?.localName
      ? findInstancesOfImport(root, source, appImport.localName, { includeNew: true })
      : new Set<string>();

    // Import hint only — classification comes from route/centralized evidence.
    const authMechanismHint = detectAuthMechanism(file.imports);

    // Pre-pass 1: top-level `app.use(<mw>)` middleware applications, and
    // pre-pass 2: `app.use(router.routes())` mounts (per router, the earliest
    // mount line into any app). A centralized middleware covers a router's
    // routes when it was applied BEFORE the router was mounted — Koa runs
    // middleware in registration order, so `app.use(auth); app.use(r.routes())`
    // authenticates everything the router serves.
    const appUses: AppUse[] = [];
    const mountLineByRouter = new Map<string, number>();
    walkTree(tree, (node) => {
      if (node.type !== 'call_expression') return;
      const fn = node.childForFieldName('function');
      if (fn?.type !== 'member_expression') return;
      const object = fn.childForFieldName('object');
      const property = fn.childForFieldName('property');
      if (object?.type !== 'identifier' || property?.type !== 'property_identifier') return;
      if (textOf(property, source) !== 'use') return;
      const appName = textOf(object, source);
      if (!appInstances.has(appName)) return;
      if (!isTopLevelStatement(node)) return;
      const args = node.childForFieldName('arguments');
      if (!args) return;

      // Mount detection: any arg shaped `<router>.routes()` / `<router>.middleware()`.
      let sawMount = false;
      const tokens: MiddlewareToken[] = [];
      for (let i = 0; i < args.namedChildCount; i++) {
        const arg = args.namedChild(i)!;
        if (arg.type === 'call_expression') {
          const argFn = arg.childForFieldName('function');
          if (argFn?.type === 'member_expression') {
            const argObj = argFn.childForFieldName('object');
            const argProp = argFn.childForFieldName('property');
            const objName = argObj?.type === 'identifier' ? textOf(argObj, source) : null;
            const propName = argProp ? textOf(argProp, source) : '';
            if (objName && routerInstances.has(objName) && (propName === 'routes' || propName === 'middleware')) {
              sawMount = true;
              const prev = mountLineByRouter.get(objName);
              const line = lineOf(node);
              if (prev === undefined || line < prev) mountLineByRouter.set(objName, line);
              continue;
            }
          }
        }
        const t = middlewareToken(arg, source);
        if (t) tokens.push(t);
      }
      if (!sawMount && tokens.length > 0) {
        appUses.push({ app: appName, line: lineOf(node), tokens });
      }
    });

    const entryPoints: EntryPoint[] = [];

    // Route entries — only via a router instance.
    if (routerInstances.size > 0) {
      walkTree(tree, (node) => {
        if (node.type !== 'call_expression') return;
        const fn = node.childForFieldName('function');
        if (fn?.type !== 'member_expression') return;
        const object = fn.childForFieldName('object');
        const property = fn.childForFieldName('property');
        if (object?.type !== 'identifier' || property?.type !== 'property_identifier') return;
        const instanceName = textOf(object, source);
        const methodName = textOf(property, source);
        if (!routerInstances.has(instanceName) || !ROUTE_METHOD_NAMES.has(methodName)) return;

        const args = node.childForFieldName('arguments');
        const routeArg = args?.namedChild(0);
        const routePattern = stringLiteralValue(routeArg ?? null, source);
        if (!routePattern) return;
        const lastArg = args ? args.namedChild(args.namedChildCount - 1) : null;

        // Route-local middleware = the middle args (after the path, before the
        // terminal handler). `.unless(...)`-wrapped tokens are carve-outs and
        // never evidence (Sem 3).
        const routeTokens: MiddlewareToken[] = [];
        if (args) {
          for (let i = 1; i < args.namedChildCount - 1; i++) {
            const t = middlewareToken(args.namedChild(i)!, source);
            if (t && !isUnlessCarveOut(t)) routeTokens.push(t);
          }
        }

        // Centralized coverage: app.use(<auth>) applied before this router's
        // mount into that app. No mount in this file → no centralized coverage.
        const centralTokens: MiddlewareToken[] = [];
        const mountLine = mountLineByRouter.get(instanceName);
        if (mountLine !== undefined) {
          for (const u of appUses) {
            if (u.line >= mountLine) continue;
            centralTokens.push(...u.tokens.filter((t) => !isUnlessCarveOut(t)));
          }
        }

        const allTokens = [...routeTokens, ...centralTokens];
        const { authTokens, internalTokens, publicOverrides } = categorizeMiddlewareTokens(allTokens);
        const result = classifyRoute({
          authTokens,
          internalTokens,
          publicOverrides,
          routePattern,
          centralizedOnly: !hasRouteLocalAuth(routeTokens),
        });

        // Span capture (Sem 6): terminal handler only.
        let handlerSpan: HandlerSpan | null = null;
        let demotionEligible = false;
        if (lastArg) {
          handlerSpan = handlerSpanForArg(lastArg, root, source);
          if (handlerSpan) {
            demotionEligible = lastArg.type === 'identifier'
              ? isNamedHandlerDemotionEligible(root, source, textOf(lastArg, source))
              : true;
          }
        }

        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(node),
          framework: 'koa',
          handlerName: handlerDescriptor(lastArg, source),
          httpMethod: HTTP_METHOD_NAMES[methodName] ?? null,
          routePattern,
          entryPointType: 'http_route',
          classification: result.classification,
          authenticated: result.authenticated,
          authMechanism: authMechanismHint,
          middlewareChain: allTokens.length ? allTokens.map((t) => t.display) : null,
          handlerSpan,
          demotionEligible,
          metadata: { instance: instanceName, call: `${instanceName}.${methodName}` },
        });
      });
    }

    return entryPoints;
  },
};
