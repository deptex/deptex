import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  GO_HTTP_METHODS_PASCAL,
  buildGoRouteEntryPoint,
  detectGoAuthMechanism,
  findInstancesFromFactory,
  findRouteCalls,
  findUseCalls,
} from '../util/go';

// Chi:
//   r := chi.NewRouter()
//   r.Use(jwtauth.Verifier(tokenAuth))      ← parse-only, NOT auth evidence
//   r.Use(jwtauth.Authenticator)            ← enforce → auth evidence
//   r.Get("/path", handler)
//   r.With(requireAuth).Get("/admin", h)    ← per-route middleware chain

export const chiDetector: FrameworkDetector = {
  name: 'chi',
  displayName: 'Chi',
  language: 'go',
  triggerImports: ['github.com/go-chi/chi'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    // Import hint only — classification comes from middleware evidence.
    const authMechanismHint = detectGoAuthMechanism(file.imports);

    const chiImp = file.imports.find((i) => i.source.startsWith('github.com/go-chi/chi'));
    const chiAlias = chiImp?.localName ?? 'chi';
    const instances = findInstancesFromFactory(tree.rootNode, source, [
      { pkgAlias: chiAlias, fn: 'NewRouter' },
    ]);
    if (instances.size === 0) return [];

    const uses = findUseCalls(tree, source, instances);
    const entryPoints: EntryPoint[] = [];
    for (const call of findRouteCalls(tree, source, instances, GO_HTTP_METHODS_PASCAL, ['Handle', 'HandleFunc'])) {
      if (!call.httpMethod) continue;
      entryPoints.push(buildGoRouteEntryPoint({
        call, tree, source, filePath: file.filePath,
        framework: 'chi', authMechanismHint, uses,
        metadata: { method: call.methodName },
      }));
    }
    return entryPoints;
  },
};
