import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  classifyFromAuth,
  detectGoAuthMechanism,
  findInstancesFromFactory,
  goStringLiteral,
  handlerTextOf,
  lineOf,
  textOf,
  walkTree,
} from '../util/go';

// net/http patterns:
//   http.HandleFunc("/p", handler)
//   http.Handle("/p", handlerStruct)
//   mux := http.NewServeMux()
//   mux.HandleFunc("/p", handler)

const HANDLER_METHODS = new Set(['HandleFunc', 'Handle']);

export const nethttpDetector: FrameworkDetector = {
  name: 'nethttp',
  displayName: 'net/http',
  language: 'go',
  triggerImports: ['net/http'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectGoAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    const httpAlias = file.imports.find((i) => i.source === 'net/http')?.localName ?? 'http';
    const muxInstances = findInstancesFromFactory(tree.rootNode, source, [
      { pkgAlias: httpAlias, fn: 'NewServeMux' },
    ]);

    walkTree(tree, (node) => {
      if (node.type !== 'call_expression') return;
      const fn = node.childForFieldName('function');
      if (fn?.type !== 'selector_expression') return;
      const operand = fn.childForFieldName('operand');
      const field = fn.childForFieldName('field');
      if (operand?.type !== 'identifier' || !field) return;
      const op = textOf(operand, source);
      const method = textOf(field, source);
      if (!HANDLER_METHODS.has(method)) return;
      const matchesHttp = op === httpAlias;
      const matchesMux = muxInstances.has(op);
      if (!matchesHttp && !matchesMux) return;

      const args = node.childForFieldName('arguments');
      const firstArg = args?.namedChild(0);
      const routePattern = goStringLiteral(firstArg ?? null, source);
      if (!routePattern) return;
      const handlerArg = args && args.namedChildCount > 1 ? args.namedChild(1) : null;

      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(node),
        framework: 'nethttp',
        handlerName: handlerTextOf(handlerArg, source),
        httpMethod: null,
        routePattern,
        entryPointType: 'http_route',
        classification,
        authenticated: !!authMechanism,
        authMechanism,
        middlewareChain: null,
        metadata: { instance: op, method },
      });
    });
    return entryPoints;
  },
};
