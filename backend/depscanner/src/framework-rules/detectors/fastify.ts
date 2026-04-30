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

// Fastify's typical shape:
//   const fastify = require('fastify')({ logger: true });
//   // or: import Fastify from 'fastify'; const app = Fastify();
//   fastify.get('/path', handler);
//   fastify.route({ method: 'GET', url: '/path', handler });
const ROUTE_METHOD_NAMES = new Set([...Object.keys(HTTP_METHOD_NAMES), 'all']);

export const fastifyDetector: FrameworkDetector = {
  name: 'fastify',
  displayName: 'Fastify',
  language: 'javascript',
  triggerImports: ['fastify'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const imp = file.imports.find((i) => i.source === 'fastify');
    if (!imp?.localName) return [];

    const instances = findInstancesOfImport(tree.rootNode, source, imp.localName, { includeNew: true });
    // Fastify's idiomatic form is `const fastify = require('fastify')({...})`,
    // which binds the local name directly to an instance (flagged as
    // cjs-require-iife by the extractor).
    if (imp.kind === 'cjs-require-iife') instances.add(imp.localName);
    if (instances.size === 0) return [];

    const authMechanism = detectAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
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
      if (!instances.has(instanceName)) return;

      const args = node.childForFieldName('arguments');
      if (!args) return;

      if (ROUTE_METHOD_NAMES.has(methodName)) {
        const routeArg = args.namedChild(0);
        const routePattern = stringLiteralValue(routeArg, source);
        if (!routePattern) return;
        const lastArg = args.namedChild(args.namedChildCount - 1);
        const handlerName = handlerDescriptor(lastArg, source);
        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(node),
          framework: 'fastify',
          handlerName,
          httpMethod: HTTP_METHOD_NAMES[methodName] ?? null,
          routePattern,
          entryPointType: 'http_route',
          classification,
          authenticated: !!authMechanism,
          authMechanism,
          middlewareChain: null,
          metadata: { instance: instanceName, call: `${instanceName}.${methodName}` },
        });
      } else if (methodName === 'route') {
        // fastify.route({ method: 'GET', url: '/path', handler })
        const configArg = args.namedChild(0);
        if (configArg?.type !== 'object') return;
        let methodStr: string | null = null;
        let urlStr: string | null = null;
        let handlerNode: ReturnType<typeof configArg.namedChild> = null;
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
        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(node),
          framework: 'fastify',
          handlerName: handlerDescriptor(handlerNode, source),
          httpMethod: (methodStr?.toUpperCase() as EntryPoint['httpMethod']) ?? null,
          routePattern: urlStr,
          entryPointType: 'http_route',
          classification,
          authenticated: !!authMechanism,
          authMechanism,
          middlewareChain: null,
          metadata: { instance: instanceName, call: `${instanceName}.route` },
        });
      }
    });

    return entryPoints;
  },
};
