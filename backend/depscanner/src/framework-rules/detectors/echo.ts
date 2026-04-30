import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  GO_HTTP_METHODS_UPPER,
  classifyFromAuth,
  detectGoAuthMechanism,
  findInstancesFromFactory,
  findRouteCalls,
  lineOf,
} from '../util/go';

// Echo:
//   e := echo.New()
//   e.GET("/users", getUsers)

export const echoDetector: FrameworkDetector = {
  name: 'echo',
  displayName: 'Echo',
  language: 'go',
  triggerImports: ['github.com/labstack/echo'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectGoAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);

    const echoImp = file.imports.find((i) => i.source.startsWith('github.com/labstack/echo'));
    const echoAlias = echoImp?.localName ?? 'echo';
    const instances = findInstancesFromFactory(tree.rootNode, source, [
      { pkgAlias: echoAlias, fn: 'New' },
    ]);
    if (instances.size === 0) return [];

    const entryPoints: EntryPoint[] = [];
    for (const call of findRouteCalls(tree, source, instances, GO_HTTP_METHODS_UPPER)) {
      if (!call.httpMethod) continue;
      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(call.node),
        framework: 'echo',
        handlerName: call.handlerName,
        httpMethod: call.httpMethod,
        routePattern: call.routePattern,
        entryPointType: 'http_route',
        classification,
        authenticated: !!authMechanism,
        authMechanism,
        middlewareChain: null,
        metadata: { method: call.methodName },
      });
    }
    return entryPoints;
  },
};
