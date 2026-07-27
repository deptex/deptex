import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  decoratorTokenText,
  decoratorsOf,
  detectPyAuthMechanism,
  findClassInstances,
  lineOf,
  parseDecorator,
  pythonStringLiteral,
  textOf,
  walkTree,
} from '../util/python';
import { classifyRoute, spanOfNode } from '../util/auth-evidence';

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

    // Import hint only — classification comes from @requires evidence.
    const authMechanismHint = detectPyAuthMechanism(file.imports);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'function_definition') return;
      const decorators = decoratorsOf(node);
      if (decorators.length === 0) return;
      const funcName = node.childForFieldName('name');
      const handlerName = funcName ? textOf(funcName, source) : null;

      // starlette.authentication.requires — `@requires('authenticated')` /
      // `@requires(['authenticated', 'admin'])` is a positive auth constraint on
      // the endpoint (Sem 1). Any other co-decorator goes through the shared
      // name patterns.
      const vettedAuthTokens: string[] = [];
      const authTokens: string[] = [];
      for (const dec of decorators) {
        const parsed = parseDecorator(dec, source);
        if (parsed.object && instances.has(parsed.object)) continue; // the route decorator
        const token = decoratorTokenText(dec, source);
        if (!token) continue;
        if (/^requires\s*\(/.test(token)) vettedAuthTokens.push(token);
        else authTokens.push(token);
      }

      for (const dec of decorators) {
        const parsed = parseDecorator(dec, source);
        if (!parsed.object || !instances.has(parsed.object)) continue;
        if (parsed.attr !== 'route' || !parsed.call) continue;
        const args = parsed.call.childForFieldName('arguments');
        const routeArg = args?.namedChild(0);
        const routePattern = pythonStringLiteral(routeArg ?? null, source);
        if (!routePattern) continue;
        const result = classifyRoute({
          vettedAuthTokens,
          authTokens,
          routePattern,
          centralizedOnly: false,
        });
        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(node),
          framework: 'starlette',
          handlerName,
          httpMethod: null, // Starlette accepts all methods unless `methods=` kwarg
          routePattern,
          entryPointType: 'http_route',
          classification: result.classification,
          authenticated: result.authenticated,
          authMechanism: authMechanismHint,
          middlewareChain: vettedAuthTokens.length ? vettedAuthTokens : null,
          // Declaration-bound family — span always demotion-eligible (Sem 6).
          handlerSpan: spanOfNode(node),
          demotionEligible: true,
          metadata: { instance: parsed.object },
        });
      }
    });

    return entryPoints;
  },
};
