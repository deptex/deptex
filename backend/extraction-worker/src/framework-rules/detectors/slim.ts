import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  PHP_HTTP_METHODS,
  classifyFromAuth,
  detectPhpAuthMechanism,
  lineOf,
  phpStringLiteral,
  textOf,
  walkTree,
} from '../util/php';

// Slim 4:
//   $app = AppFactory::create();
//   $app->get('/users', function ($req, $res) { ... });
//   $app->post('/users', UserController::class . ':store');

export const slimDetector: FrameworkDetector = {
  name: 'slim',
  displayName: 'Slim',
  language: 'php',
  triggerImports: ['Slim\\App', 'Slim\\Factory\\AppFactory', 'Slim'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectPhpAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'member_call_expression') return;
      const object = node.childForFieldName('object');
      const name = node.childForFieldName('name');
      if (object?.type !== 'variable_name' || !name) return;
      const methodName = textOf(name, source).toLowerCase();
      const httpMethod = PHP_HTTP_METHODS[methodName];
      if (!httpMethod && methodName !== 'any' && methodName !== 'map') return;

      const args = node.childForFieldName('arguments');
      const first = args?.namedChild(0);
      const inner = first?.type === 'argument' ? first.namedChild(0) : first ?? null;
      const routePattern = phpStringLiteral(inner ?? null, source);
      if (!routePattern) return;

      const lastArg = args ? args.namedChild(args.namedChildCount - 1) : null;
      let handlerName: string | null = null;
      if (lastArg) {
        const hInner = lastArg.type === 'argument' ? lastArg.namedChild(0) : lastArg;
        if (hInner) handlerName = textOf(hInner, source);
      }

      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(node),
        framework: 'slim',
        handlerName,
        httpMethod: httpMethod ?? null,
        routePattern,
        entryPointType: 'http_route',
        classification,
        authenticated: !!authMechanism,
        authMechanism,
        middlewareChain: null,
        metadata: { method: methodName },
      });
    });
    return entryPoints;
  },
};
