import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  GO_HTTP_METHODS_PASCAL,
  classifyFromAuth,
  detectGoAuthMechanism,
  findInstancesFromFactory,
  findRouteCalls,
  lineOf,
} from '../util/go';

// Chi:
//   r := chi.NewRouter()
//   r.Get("/path", handler)

export const chiDetector: FrameworkDetector = {
  name: 'chi',
  displayName: 'Chi',
  language: 'go',
  triggerImports: ['github.com/go-chi/chi'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectGoAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);

    const chiImp = file.imports.find((i) => i.source.startsWith('github.com/go-chi/chi'));
    const chiAlias = chiImp?.localName ?? 'chi';
    const instances = findInstancesFromFactory(tree.rootNode, source, [
      { pkgAlias: chiAlias, fn: 'NewRouter' },
    ]);
    if (instances.size === 0) return [];

    const entryPoints: EntryPoint[] = [];
    for (const call of findRouteCalls(tree, source, instances, GO_HTTP_METHODS_PASCAL, ['Handle', 'HandleFunc'])) {
      if (!call.httpMethod) continue;
      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(call.node),
        framework: 'chi',
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
