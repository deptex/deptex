import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HandlerSpan } from '../types';
import {
  PHP_CLOSURE_TYPES,
  PHP_HTTP_METHODS,
  chainedMemberCalls,
  detectPhpAuthMechanism,
  lineOf,
  phpArgValue,
  phpStringLiteral,
  textOf,
  walkTree,
} from '../util/php';
import { classifyRoute, spanOfNode } from '../util/auth-evidence';

// Slim 4:
//   $app = AppFactory::create();
//   $app->get('/users', function ($req, $res) { ... });
//   $app->post('/admin', handler)->add(new AuthMiddleware());
//   $app->group('/admin', function ($group) { $group->get(...); })->add($auth);

/** Middleware token from an ->add(...) argument: new X() / $var / X::class / callable. */
function slimMiddlewareToken(arg: Node | null, source: string): string | null {
  const inner = phpArgValue(arg);
  if (!inner) return null;
  if (inner.type === 'object_creation_expression') {
    // `new AuthMiddleware(...)` — the class name is the token.
    for (let i = 0; i < inner.namedChildCount; i++) {
      const c = inner.namedChild(i)!;
      if (c.type === 'name' || c.type === 'qualified_name') return textOf(c, source).split('\\').pop() ?? null;
    }
    return textOf(inner, source);
  }
  if (PHP_CLOSURE_TYPES.has(inner.type)) return null; // inline closure — no name signal
  const t = textOf(inner, source).trim();
  return t || null;
}

/** All ->add(...) middleware tokens in a fluent chain. */
function chainAddTokens(node: Node, source: string): string[] {
  const out: string[] = [];
  for (const call of chainedMemberCalls(node, source)) {
    if (call.name !== 'add') continue;
    const argsNode = call.argsNode;
    if (!argsNode) continue;
    for (let i = 0; i < argsNode.namedChildCount; i++) {
      const t = slimMiddlewareToken(argsNode.namedChild(i)!, source);
      if (t) out.push(t);
    }
  }
  return out;
}

interface SlimGroup {
  startIndex: number;
  endIndex: number;
  tokens: string[];
}

export const slimDetector: FrameworkDetector = {
  name: 'slim',
  displayName: 'Slim',
  language: 'php',
  triggerImports: ['Slim\\App', 'Slim\\Factory\\AppFactory', 'Slim'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    // Import hint only — classification comes from ->add() middleware evidence.
    const authMechanismHint = detectPhpAuthMechanism(file.imports);
    const entryPoints: EntryPoint[] = [];

    // Pre-pass: `->group('/prefix', closure)->add(mw)` — the added middleware
    // covers every route registered inside the group closure.
    const groups: SlimGroup[] = [];
    walkTree(tree, (node) => {
      if (node.type !== 'member_call_expression') return;
      const name = node.childForFieldName('name');
      if (!name || textOf(name, source) !== 'group') return;
      const args = node.childForFieldName('arguments');
      const closure = phpArgValue(args?.namedChild(args.namedChildCount - 1) ?? null);
      if (!closure || !PHP_CLOSURE_TYPES.has(closure.type)) return;
      const tokens = chainAddTokens(node, source);
      if (tokens.length === 0) return;
      groups.push({ startIndex: closure.startIndex, endIndex: closure.endIndex, tokens });
    });

    walkTree(tree, (node) => {
      if (node.type !== 'member_call_expression') return;
      const object = node.childForFieldName('object');
      const name = node.childForFieldName('name');
      if (object?.type !== 'variable_name' || !name) return;
      const methodName = textOf(name, source).toLowerCase();
      const httpMethod = PHP_HTTP_METHODS[methodName];
      if (!httpMethod && methodName !== 'any' && methodName !== 'map') return;

      const args = node.childForFieldName('arguments');
      const inner = phpArgValue(args?.namedChild(0) ?? null);
      const routePattern = phpStringLiteral(inner ?? null, source);
      if (!routePattern) return;

      const lastArg = args ? args.namedChild(args.namedChildCount - 1) : null;
      const hInner = phpArgValue(lastArg);
      const handlerName = hInner ? textOf(hInner, source) : null;

      // Route-chained ->add(...) middleware + enclosing group middleware.
      const routeTokens = chainAddTokens(node, source);
      const groupTokens: string[] = [];
      for (const g of groups) {
        if (node.startIndex >= g.startIndex && node.endIndex <= g.endIndex) {
          groupTokens.push(...g.tokens);
        }
      }

      // Name-heuristic evidence (AuthMiddleware / JwtAuthentication match the
      // shared patterns; unknown middleware names stay neutral → PUBLIC).
      const result = classifyRoute({
        authTokens: [...routeTokens, ...groupTokens],
        routePattern,
        centralizedOnly: routeTokens.length === 0,
      });

      // Span capture (Sem 6): inline closure handlers only.
      let handlerSpan: HandlerSpan | null = null;
      let demotionEligible = false;
      if (hInner && PHP_CLOSURE_TYPES.has(hInner.type)) {
        handlerSpan = spanOfNode(hInner);
        demotionEligible = true;
      }

      const allTokens = [...routeTokens, ...groupTokens];
      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(node),
        framework: 'slim',
        handlerName,
        httpMethod: httpMethod ?? null,
        routePattern,
        entryPointType: 'http_route',
        classification: result.classification,
        authenticated: result.authenticated,
        authMechanism: authMechanismHint,
        middlewareChain: allTokens.length ? allTokens : null,
        handlerSpan,
        demotionEligible,
        metadata: { method: methodName },
      });
    });
    return entryPoints;
  },
};
