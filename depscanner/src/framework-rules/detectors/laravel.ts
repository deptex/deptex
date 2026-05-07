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

// Laravel routes/web.php + routes/api.php:
//   Route::get('/users', [UserController::class, 'index']);
//   Route::post('/users', 'UserController@store');
//   Route::resource('users', UserController::class);

export const laravelDetector: FrameworkDetector = {
  name: 'laravel',
  displayName: 'Laravel',
  language: 'php',
  triggerImports: ['Illuminate\\Support\\Facades\\Route', 'Illuminate'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectPhpAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'scoped_call_expression') return;
      const scope = node.childForFieldName('scope');
      const name = node.childForFieldName('name');
      if (scope?.type !== 'name' || !name) return;
      if (textOf(scope, source) !== 'Route') return;
      const methodName = textOf(name, source).toLowerCase();
      const httpMethod = PHP_HTTP_METHODS[methodName] ?? (methodName === 'any' ? null : undefined);
      if (httpMethod === undefined && methodName !== 'any' && methodName !== 'match') return;

      const args = node.childForFieldName('arguments');
      // For Route::match([...], '/path', handler) the first arg is the methods list.
      let routeArgIdx = 0;
      if (methodName === 'match') routeArgIdx = 1;
      const routeArg = args?.namedChild(routeArgIdx);
      const routeInner = routeArg?.type === 'argument' ? routeArg.namedChild(0) : routeArg ?? null;
      const routePattern = phpStringLiteral(routeInner ?? null, source);
      if (!routePattern) return;

      const handlerArg = args ? args.namedChild(routeArgIdx + 1) : null;
      let handlerName: string | null = null;
      if (handlerArg) {
        const hInner = handlerArg.type === 'argument' ? handlerArg.namedChild(0) : handlerArg;
        if (hInner) handlerName = textOf(hInner, source);
      }

      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(node),
        framework: 'laravel',
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
