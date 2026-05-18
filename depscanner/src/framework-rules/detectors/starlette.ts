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

// Starlette routing:
//   app = Starlette(routes=[Route('/', endpoint), Route('/users', users)])
//   Or decorator style with app.route (older):
//     @app.route('/path') async def handler(req): ...
// We cover the decorator case — the routes=[] list is harder to attribute to
// handler code reliably because `endpoint` is often an imported symbol.

export const starletteDetector: FrameworkDetector = {
  name: 'starlette',
  displayName: 'Starlette',
  language: 'python',
  triggerImports: ['starlette'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const instances = findClassInstances(tree.rootNode, source, ['Starlette']);
    if (instances.size === 0) return [];

    const authMechanism = detectPyAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'function_definition') return;
      const decorators = decoratorsOf(node);
      if (decorators.length === 0) return;
      const funcName = node.childForFieldName('name');
      const handlerName = funcName ? textOf(funcName, source) : null;
      for (const dec of decorators) {
        const parsed = parseDecorator(dec, source);
        if (!parsed.object || !instances.has(parsed.object)) continue;
        if (parsed.attr !== 'route' || !parsed.call) continue;
        const args = parsed.call.childForFieldName('arguments');
        const routeArg = args?.namedChild(0);
        const routePattern = pythonStringLiteral(routeArg ?? null, source);
        if (!routePattern) continue;
        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(node),
          framework: 'starlette',
          handlerName,
          httpMethod: null, // Starlette accepts all methods unless `methods=` kwarg
          routePattern,
          entryPointType: 'http_route',
          classification,
          authenticated: !!authMechanism,
          authMechanism,
          middlewareChain: null,
          metadata: { instance: parsed.object },
        });
      }
    });

    return entryPoints;
  },
};
