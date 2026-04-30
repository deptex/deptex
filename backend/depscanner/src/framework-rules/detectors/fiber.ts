import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  GO_HTTP_METHODS_PASCAL,
  classifyFromAuth,
  detectGoAuthMechanism,
  findInstancesFromFactory,
  findRouteCalls,
  lineOf,
} from '../util/go';

// Fiber:
//   app := fiber.New()
//   app.Get("/path", handler)    (PascalCase methods — distinct from Gin/Echo)

export const fiberDetector: FrameworkDetector = {
  name: 'fiber',
  displayName: 'Fiber',
  language: 'go',
  triggerImports: ['github.com/gofiber/fiber'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectGoAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);

    const fiberImp = file.imports.find((i) => i.source.startsWith('github.com/gofiber/fiber'));
    const fiberAlias = fiberImp?.localName ?? 'fiber';
    const instances = findInstancesFromFactory(tree.rootNode, source, [
      { pkgAlias: fiberAlias, fn: 'New' },
    ]);
    if (instances.size === 0) return [];

    const entryPoints: EntryPoint[] = [];
    for (const call of findRouteCalls(tree, source, instances, GO_HTTP_METHODS_PASCAL, ['All', 'Use'])) {
      if (!call.httpMethod) continue;
      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(call.node),
        framework: 'fiber',
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
