import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  GO_HTTP_METHODS_PASCAL,
  buildGoRouteEntryPoint,
  detectGoAuthMechanism,
  findInstancesFromFactory,
  findRouteCalls,
  findUseCalls,
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
    // Import hint only — classification comes from middleware evidence.
    const authMechanismHint = detectGoAuthMechanism(file.imports);

    const fiberImp = file.imports.find((i) => i.source.startsWith('github.com/gofiber/fiber'));
    const fiberAlias = fiberImp?.localName ?? 'fiber';
    const instances = findInstancesFromFactory(tree.rootNode, source, [
      { pkgAlias: fiberAlias, fn: 'New' },
    ]);
    if (instances.size === 0) return [];

    const uses = findUseCalls(tree, source, instances);
    const entryPoints: EntryPoint[] = [];
    for (const call of findRouteCalls(tree, source, instances, GO_HTTP_METHODS_PASCAL, ['All', 'Use'])) {
      if (!call.httpMethod) continue;
      entryPoints.push(buildGoRouteEntryPoint({
        call, tree, source, filePath: file.filePath,
        framework: 'fiber', authMechanismHint, uses,
        metadata: { method: call.methodName },
      }));
    }
    return entryPoints;
  },
};
