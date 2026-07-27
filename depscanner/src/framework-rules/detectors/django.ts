import type { Node } from 'web-tree-sitter';
import type { CtxOnlyRouteRecord, DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import type { ExtractedFile } from '../../tree-sitter-extractor/languages/types';
import {
  analyzeDjangoViews,
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

    // Bank per-view auth facts from this file's Django views (the cross-file
    // leg, T9). Taint sources fire inside the view, so classifying + re-homing
    // here demotes those flows — no urls.py resolution needed.
    bankDjangoViewFacts(tree.rootNode, source, file);

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
  /**
   * Cross-file pass (T9): re-home every file's banked Django view auth facts
   * into ctx-only route records keyed on the view file. Added to
   * `ctx.entryPointAuth` only — never persisted.
   */
  postProcess(files: readonly ExtractedFile[]): CtxOnlyRouteRecord[] {
    const out: CtxOnlyRouteRecord[] = [];
    for (const file of files) {
      const facts = file.authFacts;
      if (!facts || facts.framework !== 'django') continue;
      for (const action of facts.actions) {
        if (action.classification === 'PUBLIC_UNAUTH' || action.classification === 'UNKNOWN') continue;
        out.push({
          filePath: facts.filePath,
          classification: action.classification,
          handlerSpan: action.handlerSpan,
          demotionEligible: action.demotionEligible,
          routePattern: action.routePattern,
          middlewareChain: action.middlewareChain,
          authMechanism: action.authMechanism,
        });
      }
    }
    return out;
  },
};

/** Bank per-view auth facts from every Django view in the file. */
function bankDjangoViewFacts(root: Node, source: string, file: ExtractedFile): void {
  const views = analyzeDjangoViews(root, source);
  if (views.length === 0) return;
  file.authFacts = {
    framework: 'django',
    filePath: file.filePath,
    actions: views.map((v) => ({
      name: v.name,
      handlerSpan: v.handlerSpan,
      classification: v.classification,
      demotionEligible: v.demotionEligible,
      routePattern: null,
      middlewareChain: v.middlewareChain,
      authMechanism: v.middlewareChain?.[0] ?? null,
    })),
  };
}
