import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import type { MiddlewareToken } from '../util/auth-evidence';
import {
  classifyGoRoute,
  detectGoAuthMechanism,
  findInstancesFromFactory,
  goHandlerSpan,
  goMiddlewareToken,
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
    // Import hint only — classification comes from wrapper evidence.
    const authMechanismHint = detectGoAuthMechanism(file.imports);
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

      // net/http has no middleware chain — the only evidence surface is a
      // wrapped handler (`http.Handle("/x", requireAuth(h))`).
      const routeTokens: MiddlewareToken[] = [];
      if (handlerArg?.type === 'call_expression') {
        const wrapper = goMiddlewareToken(handlerArg, source);
        if (wrapper) routeTokens.push(wrapper);
      }
      const { classification, authenticated } = classifyGoRoute({
        routeTokens, useTokens: [], routePattern,
      });
      const { span, eligible } = goHandlerSpan(tree.rootNode, source, handlerArg);

      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(node),
        framework: 'nethttp',
        handlerName: handlerTextOf(handlerArg, source),
        httpMethod: null,
        routePattern,
        entryPointType: 'http_route',
        classification,
        authenticated,
        authMechanism: authMechanismHint,
        middlewareChain: routeTokens.length ? routeTokens.map((t) => t.display) : null,
        handlerSpan: span,
        demotionEligible: eligible,
        metadata: { instance: op, method },
      });
    });
    return entryPoints;
  },
};
