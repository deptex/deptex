import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  GO_HTTP_METHODS_UPPER,
  buildGoRouteEntryPoint,
  detectGoAuthMechanism,
  findInstancesFromFactory,
  findRouteCalls,
  findUseCalls,
} from '../util/go';

// Gin:
//   r := gin.Default()   (or gin.New())
//   r.GET("/path", handler)
// Group chaining (`r.Group("/api").GET(...)`) is not traced — the API-style
// returns a value but we'd need flow tracking to follow. Captures top-level
// calls on the `r` instance, which is what 95% of real code does.

export const ginDetector: FrameworkDetector = {
  name: 'gin',
  displayName: 'Gin',
  language: 'go',
  triggerImports: ['github.com/gin-gonic/gin'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    // Import hint only — classification comes from middleware evidence.
    const authMechanismHint = detectGoAuthMechanism(file.imports);

    const ginAlias = file.imports.find((i) => i.source === 'github.com/gin-gonic/gin')?.localName ?? 'gin';
    const instances = findInstancesFromFactory(tree.rootNode, source, [
      { pkgAlias: ginAlias, fn: 'Default' },
      { pkgAlias: ginAlias, fn: 'New' },
    ]);
    if (instances.size === 0) return [];

    const uses = findUseCalls(tree, source, instances);
    const entryPoints: EntryPoint[] = [];
    for (const call of findRouteCalls(tree, source, instances, GO_HTTP_METHODS_UPPER, ['Any', 'Handle'])) {
      if (!call.httpMethod) continue;
      entryPoints.push(buildGoRouteEntryPoint({
        call, root: tree.rootNode, source, filePath: file.filePath,
        framework: 'gin', authMechanismHint, uses,
        metadata: { method: call.methodName },
      }));
    }
    return entryPoints;
  },
};
