import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import { classifyFromAuth, detectPyAuthMechanism, lineOf, pythonStringLiteral, textOf, walkTree } from '../util/python';

// Tornado routing:
//   tornado.web.Application([
//     (r'/path', HandlerClass),
//     (r'/users/([0-9]+)', UserHandler),
//   ])
// Handlers are class-based (subclasses of RequestHandler).

export const tornadoDetector: FrameworkDetector = {
  name: 'tornado',
  displayName: 'Tornado',
  language: 'python',
  triggerImports: ['tornado'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectPyAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'call') return;
      const fn = node.childForFieldName('function');
      // Match `tornado.web.Application(...)` or `web.Application(...)` or
      // `Application(...)` — but at least be cautious and require the text
      // to contain "Application".
      const fnText = fn ? textOf(fn, source) : '';
      if (!/(^|\.)Application$/.test(fnText)) return;

      const args = node.childForFieldName('arguments');
      const listArg = args?.namedChild(0);
      if (listArg?.type !== 'list') return;

      for (let i = 0; i < listArg.namedChildCount; i++) {
        const elem = listArg.namedChild(i)!;
        if (elem.type !== 'tuple') continue;
        const patternNode = elem.namedChild(0);
        const handlerNode = elem.namedChild(1);
        const routePattern = pythonStringLiteral(patternNode ?? null, source);
        if (!routePattern) continue;
        let handlerName: string | null = null;
        if (handlerNode?.type === 'identifier' || handlerNode?.type === 'attribute') {
          handlerName = textOf(handlerNode, source);
        }
        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(elem),
          framework: 'tornado',
          handlerName,
          httpMethod: null,
          routePattern: routePattern.startsWith('/') ? routePattern : `/${routePattern}`,
          entryPointType: 'http_route',
          classification,
          authenticated: !!authMechanism,
          authMechanism,
          middlewareChain: null,
          metadata: { call: fnText },
        });
      }
    });

    // Silence unused import warning for Node
    void (null as Node | null);

    return entryPoints;
  },
};
