import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  FASTAPI_AUTH_DEP_RE,
  HTTP_METHOD_NAMES,
  collectDependencyTargets,
  decoratorsOf,
  detectPyAuthMechanism,
  findClassInstances,
  keywordArgValue,
  lineOf,
  parseDecorator,
  pythonStringLiteral,
  textOf,
  walkTree,
} from '../util/python';
import { classifyRoute, isOptionalVetoed, matchesAuthName, spanOfNode } from '../util/auth-evidence';

// FastAPI routes:
//   app = FastAPI()
//   @app.get('/items/{id}')
//   async def get_item(id: int): ...
//   Auth idioms (Sem 1/4):
//     async def me(user = Depends(get_current_user)): ...       ← param dependency
//     @app.get('/x', dependencies=[Depends(verify_token)])      ← decorator kwarg
//     router = APIRouter(dependencies=[Depends(oauth2_scheme)]) ← router-level
//   `Security(...)` targets are ALWAYS auth requirements; `Depends(...)` targets
//   count only when auth-shaped, and Optional*/anonymous names are vetoed.

/** Is a dependency target auth evidence (post-veto)? */
function depTargetIsAuth(dep: { kind: 'depends' | 'security'; target: string }): boolean {
  if (isOptionalVetoed(dep.target)) return false;
  if (dep.kind === 'security') return true;
  return matchesAuthName(dep.target) || FASTAPI_AUTH_DEP_RE.test(dep.target);
}

export const fastapiDetector: FrameworkDetector = {
  name: 'fastapi',
  displayName: 'FastAPI',
  language: 'python',
  triggerImports: ['fastapi'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const root = tree.rootNode;
    const instances = findClassInstances(root, source, ['FastAPI', 'APIRouter']);
    if (instances.size === 0) return [];

    // Import hint only — classification comes from dependency evidence.
    const authMechanismHint = detectPyAuthMechanism(file.imports);

    // Router-level dependencies: `router = APIRouter(dependencies=[Depends(x)])`
    // cover every route on that instance (centralized — belt applies).
    const instanceAuthTokens = new Map<string, string[]>();
    walkTree(tree, (node) => {
      if (node.type !== 'assignment') return;
      const left = node.childForFieldName('left');
      const right = node.namedChild(1);
      if (left?.type !== 'identifier' || right?.type !== 'call') return;
      const instanceName = textOf(left, source);
      if (!instances.has(instanceName)) return;
      const depsKwarg = keywordArgValue(right, 'dependencies', source);
      const targets = collectDependencyTargets(depsKwarg, source).filter(depTargetIsAuth);
      if (targets.length > 0) {
        instanceAuthTokens.set(instanceName, targets.map((t) => `${t.kind === 'security' ? 'Security' : 'Depends'}(${t.target})`));
      }
    });

    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'function_definition') return;
      const decorators = decoratorsOf(node);
      if (decorators.length === 0) return;
      const funcName = node.childForFieldName('name');
      const handlerName = funcName ? textOf(funcName, source) : null;

      // Param-level dependencies: `def h(user = Depends(get_current_user))`.
      const paramDeps = collectDependencyTargets(node.childForFieldName('parameters'), source)
        .filter(depTargetIsAuth)
        .map((t) => `${t.kind === 'security' ? 'Security' : 'Depends'}(${t.target})`);

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

        // Decorator-level dependencies: `@app.get('/x', dependencies=[...])`.
        const decoDeps = collectDependencyTargets(keywordArgValue(parsed.call, 'dependencies', source), source)
          .filter(depTargetIsAuth)
          .map((t) => `${t.kind === 'security' ? 'Security' : 'Depends'}(${t.target})`);

        const routeLocal = [...paramDeps, ...decoDeps];
        const routerLevel = instanceAuthTokens.get(parsed.object) ?? [];
        const result = classifyRoute({
          vettedAuthTokens: routeLocal.length > 0 ? routeLocal : routerLevel,
          routePattern,
          // Router-level dependencies are the centralized idiom (Sem 10 belt).
          centralizedOnly: routeLocal.length === 0,
        });

        const allTokens = [...routeLocal, ...routerLevel];
        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(node),
          framework: 'fastapi',
          handlerName,
          httpMethod: verb,
          routePattern,
          entryPointType: 'http_route',
          classification: result.classification,
          authenticated: result.authenticated,
          authMechanism: authMechanismHint,
          middlewareChain: allTokens.length ? allTokens : null,
          // Declaration-bound family — span always demotion-eligible (Sem 6).
          handlerSpan: spanOfNode(node),
          demotionEligible: true,
          metadata: { instance: parsed.object, decorator: parsed.attr },
        });
      }
    });

    return entryPoints;
  },
};
