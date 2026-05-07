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

// FastAPI routes:
//   app = FastAPI()
//   @app.get('/items/{id}')
//   async def get_item(id: int): ...
//   Sub-routers: router = APIRouter(); @router.post('/foo')

export const fastapiDetector: FrameworkDetector = {
  name: 'fastapi',
  displayName: 'FastAPI',
  language: 'python',
  triggerImports: ['fastapi'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const instances = findClassInstances(tree.rootNode, source, ['FastAPI', 'APIRouter']);
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
        if (!parsed.call || !parsed.attr) continue;

        const verb = HTTP_METHOD_NAMES[parsed.attr];
        if (!verb) continue;

        const args = parsed.call.childForFieldName('arguments');
        const routeArg = args?.namedChild(0);
        const routePattern = pythonStringLiteral(routeArg ?? null, source);
        if (!routePattern) continue;

        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(node),
          framework: 'fastapi',
          handlerName,
          httpMethod: verb,
          routePattern,
          entryPointType: 'http_route',
          classification,
          authenticated: !!authMechanism,
          authMechanism,
          middlewareChain: null,
          metadata: { instance: parsed.object, decorator: parsed.attr },
        });
      }
    });

    return entryPoints;
  },
};
