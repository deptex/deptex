import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  HTTP_METHOD_NAMES,
  classifyFromAuth,
  decoratorsOf,
  detectPyAuthMechanism,
  findClassInstances,
  lineOf,
  parseDecorator,
  pythonStringLiteral,
  textOf,
  walkTree,
} from '../util/python';

// aiohttp routing styles:
//   1. Decorator form:
//        routes = web.RouteTableDef()
//        @routes.get('/path') async def handler(request): ...
//   2. Imperative form:
//        app = web.Application()
//        app.router.add_get('/path', handler)
//        app.router.add_post('/path', handler)
// We implement both.

const ADD_METHOD_TO_VERB: Record<string, keyof typeof HTTP_METHOD_NAMES> = {
  add_get: 'get', add_post: 'post', add_put: 'put', add_patch: 'patch',
  add_delete: 'delete', add_head: 'head', add_options: 'options',
};

export const aiohttpDetector: FrameworkDetector = {
  name: 'aiohttp',
  displayName: 'aiohttp',
  language: 'python',
  triggerImports: ['aiohttp'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectPyAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    // Decorator style: `@routes.get('/path')`. We find any RouteTableDef()
    // instance first.
    const routeTableInstances = findClassInstances(tree.rootNode, source, ['RouteTableDef']);

    if (routeTableInstances.size > 0) {
      walkTree(tree, (node) => {
        if (node.type !== 'function_definition') return;
        const decorators = decoratorsOf(node);
        if (decorators.length === 0) return;
        const funcName = node.childForFieldName('name');
        const handlerName = funcName ? textOf(funcName, source) : null;
        for (const dec of decorators) {
          const parsed = parseDecorator(dec, source);
          if (!parsed.object || !routeTableInstances.has(parsed.object) || !parsed.attr || !parsed.call) continue;
          const verb = HTTP_METHOD_NAMES[parsed.attr];
          if (!verb) continue;
          const args = parsed.call.childForFieldName('arguments');
          const routeArg = args?.namedChild(0);
          const routePattern = pythonStringLiteral(routeArg ?? null, source);
          if (!routePattern) continue;
          entryPoints.push({
            filePath: file.filePath,
            lineNumber: lineOf(node),
            framework: 'aiohttp',
            handlerName,
            httpMethod: verb,
            routePattern,
            entryPointType: 'http_route',
            classification,
            authenticated: !!authMechanism,
            authMechanism,
            middlewareChain: null,
            metadata: { style: 'decorator' },
          });
        }
      });
    }

    // Imperative: `app.router.add_get('/path', handler)`
    walkTree(tree, (node) => {
      if (node.type !== 'call') return;
      const fn = node.childForFieldName('function');
      if (fn?.type !== 'attribute') return;
      const attrName = textOf(fn.childForFieldName('attribute'), source);
      const verbKey = ADD_METHOD_TO_VERB[attrName];
      if (!verbKey) return;
      const verb = HTTP_METHOD_NAMES[verbKey];
      if (!verb) return;

      // Ensure the object is `.router` (heuristic: receiver text ends with
      // '.router' or is named 'router' / 'routes').
      const objectNode = fn.childForFieldName('object');
      const objectText = objectNode ? textOf(objectNode, source) : '';
      if (!/\brouter$|^router$|^routes$/.test(objectText)) return;

      const args = node.childForFieldName('arguments');
      const routeArg = args?.namedChild(0);
      const routePattern = pythonStringLiteral(routeArg ?? null, source);
      if (!routePattern) return;
      const handlerArg = args?.namedChild(1);
      const handlerName = handlerArg ? textOf(handlerArg, source) : null;

      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(node),
        framework: 'aiohttp',
        handlerName,
        httpMethod: verb,
        routePattern,
        entryPointType: 'http_route',
        classification,
        authenticated: !!authMechanism,
        authMechanism,
        middlewareChain: null,
        metadata: { style: 'imperative' },
      });
    });

    return entryPoints;
  },
};
