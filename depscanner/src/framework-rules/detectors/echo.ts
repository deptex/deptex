import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  GO_HTTP_METHODS_UPPER,
  buildGoRouteEntryPoint,
  detectGoAuthMechanism,
  findInstancesFromFactory,
  findRouteCalls,
  findUseCalls,
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
    // Import hint only — classification comes from middleware evidence.
    const authMechanismHint = detectGoAuthMechanism(file.imports);

    const echoImp = file.imports.find((i) => i.source.startsWith('github.com/labstack/echo'));
    const echoAlias = echoImp?.localName ?? 'echo';
    const instances = findInstancesFromFactory(tree.rootNode, source, [
      { pkgAlias: echoAlias, fn: 'New' },
    ]);
    if (instances.size === 0) return [];

    const uses = findUseCalls(tree, source, instances);
    const entryPoints: EntryPoint[] = [];
    for (const call of findRouteCalls(tree, source, instances, GO_HTTP_METHODS_UPPER)) {
      if (!call.httpMethod) continue;
      entryPoints.push(buildGoRouteEntryPoint({
        call, tree, source, filePath: file.filePath,
        framework: 'echo', authMechanismHint, uses,
        metadata: { method: call.methodName },
      }));
    }
    return entryPoints;
  },
};
