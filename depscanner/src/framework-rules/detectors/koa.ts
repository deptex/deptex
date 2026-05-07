import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  HTTP_METHOD_NAMES,
  classifyFromAuth,
  detectAuthMechanism,
  findInstancesOfImport,
  handlerDescriptor,
  lineOf,
  stringLiteralValue,
  textOf,
  walkTree,
} from '../util/javascript';

// Koa shape:
//   const Koa = require('koa'); const app = new Koa();
//   // Routes usually come from koa-router:
//   const Router = require('@koa/router'); const router = new Router();
//   router.get('/path', handler);
//   // Middleware-only mounts via app.use are registered as 'use' entry points
//   // (useful for reachability on things like auth middleware).
const ROUTE_METHOD_NAMES = new Set([...Object.keys(HTTP_METHOD_NAMES), 'all']);

export const koaDetector: FrameworkDetector = {
  name: 'koa',
  displayName: 'Koa',
  language: 'javascript',
  triggerImports: ['koa', '@koa/router', 'koa-router'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;

    // Find instances for either Koa itself (app) or a koa-router Router
    // (router). Both are instantiated via `new`.
    const appImport = file.imports.find((i) => i.source === 'koa');
    const routerImport = file.imports.find((i) => i.source === '@koa/router' || i.source === 'koa-router');

    const routerInstances = routerImport?.localName
      ? findInstancesOfImport(tree.rootNode, source, routerImport.localName, { includeNew: true })
      : new Set<string>();

    if (routerInstances.size === 0 && !appImport) return [];

    const authMechanism = detectAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
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

        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(node),
          framework: 'koa',
          handlerName: handlerDescriptor(lastArg, source),
          httpMethod: HTTP_METHOD_NAMES[methodName] ?? null,
          routePattern,
          entryPointType: 'http_route',
          classification,
          authenticated: !!authMechanism,
          authMechanism,
          middlewareChain: null,
          metadata: { instance: instanceName, call: `${instanceName}.${methodName}` },
        });
      });
    }

    return entryPoints;
  },
};
