import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  classifyFromAuth,
  detectPyAuthMechanism,
  lineOf,
  pythonStringLiteral,
  textOf,
  walkTree,
} from '../util/python';

// Django URL routing lives in urls.py (or any file) as:
//   urlpatterns = [
//     path('users/', views.user_list, name='user_list'),
//     path('users/<int:id>/', views.user_detail),
//     re_path(r'^legacy/$', old_view),
//   ]
// We walk assignments named `urlpatterns` and extract path()/re_path() calls
// from the list.

const ROUTE_CALL_NAMES = new Set(['path', 're_path', 'url']);

export const djangoDetector: FrameworkDetector = {
  name: 'django',
  displayName: 'Django',
  language: 'python',
  triggerImports: ['django'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;

    const authMechanism = detectPyAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'assignment') return;
      const left = node.childForFieldName('left');
      if (left?.type !== 'identifier' || textOf(left, source) !== 'urlpatterns') return;
      const right = node.namedChild(1);
      if (right?.type !== 'list') return;

      for (let i = 0; i < right.namedChildCount; i++) {
        const elem = right.namedChild(i)!;
        if (elem.type !== 'call') continue;
        const fn = elem.childForFieldName('function');
        if (fn?.type !== 'identifier') continue;
        const fnName = textOf(fn, source);
        if (!ROUTE_CALL_NAMES.has(fnName)) continue;

        const args = elem.childForFieldName('arguments');
        const first = args?.namedChild(0);
        const routePattern = pythonStringLiteral(first ?? null, source);
        if (!routePattern) continue;

        const viewArg = args?.namedChild(1);
        let handlerName: string | null = null;
        if (viewArg) {
          if (viewArg.type === 'identifier') handlerName = textOf(viewArg, source);
          else if (viewArg.type === 'attribute') handlerName = textOf(viewArg, source);
          else if (viewArg.type === 'call') {
            // Class-based: `views.UserList.as_view()` — still informative as-is.
            handlerName = textOf(viewArg, source);
          }
        }

        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(elem),
          framework: 'django',
          handlerName,
          httpMethod: null,
          routePattern: routePattern.startsWith('/') ? routePattern : `/${routePattern}`,
          entryPointType: 'http_route',
          classification,
          authenticated: !!authMechanism,
          authMechanism,
          middlewareChain: null,
          metadata: { call: fnName },
        });
      }
    });

    return entryPoints;
  },
};
