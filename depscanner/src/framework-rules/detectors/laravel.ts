import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HandlerSpan } from '../types';
import {
  PHP_CLOSURE_TYPES,
  PHP_HTTP_METHODS,
  chainedMemberCalls,
  detectPhpAuthMechanism,
  lineOf,
  phpArgStrings,
  phpArgValue,
  phpStringLiteral,
  textOf,
  walkTree,
} from '../util/php';
import { classifyRoute, matchesAuthName, matchesPublicOverride, spanOfNode } from '../util/auth-evidence';

// Laravel routes/web.php + routes/api.php:
//   Route::get('/users', [UserController::class, 'index']);
//   Route::get('/me', ...)->middleware('auth');
//   Route::middleware('auth:sanctum')->group(function () { Route::get(...); });
//   Route::group(['middleware' => 'auth'], function () { ... });
//   Route::get('/hook', ...)->withoutMiddleware('auth');

/**
 * Laravel middleware-string semantics (exact, not name-heuristic): `auth`,
 * `auth:guard`, `auth.basic`, `auth.session` require authentication; `can:*`
 * (authorization) and `verified` imply it. `guest` marks a for-visitors route —
 * not auth evidence. Anything else falls back to the shared name patterns.
 */
function laravelTokenIsAuth(token: string): boolean {
  if (/^auth([:.]|$)/.test(token)) return true;
  if (token === 'verified') return true;
  if (/^can:/.test(token)) return true;
  if (token === 'guest') return false;
  return matchesAuthName(token) && !matchesPublicOverride(token);
}

/** A middleware group whose closure wraps route registrations. */
interface MiddlewareGroup {
  /** Byte span of the group closure body — routes inside inherit the tokens. */
  startIndex: number;
  endIndex: number;
  tokens: string[];
}

/** Middleware strings from the `['middleware' => ...]` key of a legacy group array. */
function middlewareFromGroupArray(arrayNode: Node, source: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < arrayNode.namedChildCount; i++) {
    const el = arrayNode.namedChild(i)!;
    if (el.type !== 'array_element_initializer') continue;
    const key = el.namedChild(0);
    const value = el.namedChildCount > 1 ? el.namedChild(1) : null;
    if (!key || !value) continue;
    const keyStr = phpStringLiteral(key, source);
    if (keyStr !== 'middleware') continue;
    if (value.type === 'string' || value.type === 'encapsed_string') {
      const s = phpStringLiteral(value, source);
      if (s) out.push(s);
    } else {
      out.push(...phpArgStrings(value, source));
    }
  }
  return out;
}

export const laravelDetector: FrameworkDetector = {
  name: 'laravel',
  displayName: 'Laravel',
  language: 'php',
  triggerImports: ['Illuminate\\Support\\Facades\\Route', 'Illuminate'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const root = tree.rootNode;
    // Import hint only — classification comes from middleware evidence.
    const authMechanismHint = detectPhpAuthMechanism(file.imports);
    const entryPoints: EntryPoint[] = [];

    // Pre-pass: middleware groups. Two forms:
    //   Route::middleware('auth')->group(fn)      (fluent)
    //   Route::group(['middleware' => 'auth'], fn) (legacy array)
    const groups: MiddlewareGroup[] = [];
    walkTree(tree, (node) => {
      if (node.type !== 'scoped_call_expression') return;
      const scope = node.childForFieldName('scope');
      const name = node.childForFieldName('name');
      if (scope?.type !== 'name' || !name || textOf(scope, source) !== 'Route') return;
      const methodName = textOf(name, source);

      if (methodName === 'middleware') {
        // Fluent: collect tokens here, find the chained ->group(closure).
        const tokens = phpArgStrings(node.childForFieldName('arguments'), source);
        if (tokens.length === 0) return;
        for (const call of chainedMemberCalls(node, source)) {
          if (call.name !== 'group') continue;
          const closure = phpArgValue(call.argsNode?.namedChild(0) ?? null);
          if (closure && PHP_CLOSURE_TYPES.has(closure.type)) {
            groups.push({ startIndex: closure.startIndex, endIndex: closure.endIndex, tokens });
          }
        }
      } else if (methodName === 'group') {
        // Legacy: Route::group(['middleware' => ...], closure).
        const args = node.childForFieldName('arguments');
        const first = phpArgValue(args?.namedChild(0) ?? null);
        const second = phpArgValue(args?.namedChild(1) ?? null);
        if (first?.type === 'array_creation_expression' && second && PHP_CLOSURE_TYPES.has(second.type)) {
          const tokens = middlewareFromGroupArray(first, source);
          if (tokens.length > 0) {
            groups.push({ startIndex: second.startIndex, endIndex: second.endIndex, tokens });
          }
        }
      }
    });

    walkTree(tree, (node) => {
      if (node.type !== 'scoped_call_expression') return;
      const scope = node.childForFieldName('scope');
      const name = node.childForFieldName('name');
      if (scope?.type !== 'name' || !name) return;
      if (textOf(scope, source) !== 'Route') return;
      const methodName = textOf(name, source).toLowerCase();
      const httpMethod = PHP_HTTP_METHODS[methodName] ?? (methodName === 'any' ? null : undefined);
      if (httpMethod === undefined && methodName !== 'any' && methodName !== 'match') return;

      const args = node.childForFieldName('arguments');
      // For Route::match([...], '/path', handler) the first arg is the methods list.
      let routeArgIdx = 0;
      if (methodName === 'match') routeArgIdx = 1;
      const routeArg = args?.namedChild(routeArgIdx);
      const routeInner = phpArgValue(routeArg ?? null);
      const routePattern = phpStringLiteral(routeInner ?? null, source);
      if (!routePattern) return;

      const handlerArg = args ? args.namedChild(routeArgIdx + 1) : null;
      const hInner = phpArgValue(handlerArg);
      const handlerName = hInner ? textOf(hInner, source) : null;

      // Route-local chained middleware + withoutMiddleware overrides.
      const routeTokens: string[] = [];
      const publicOverrides: string[] = [];
      for (const call of chainedMemberCalls(node, source)) {
        if (call.name === 'middleware') {
          routeTokens.push(...phpArgStrings(call.argsNode, source));
        } else if (call.name === 'withoutMiddleware') {
          // Explicit opt-out (Sem 2) — only when it strips an auth-shaped
          // middleware; withoutMiddleware('throttle') is not a public marker.
          const stripped = phpArgStrings(call.argsNode, source);
          if (stripped.some(laravelTokenIsAuth)) {
            publicOverrides.push(`withoutMiddleware(${stripped.join(',')})`);
          }
        }
      }

      // Group middleware wrapping this registration.
      const groupTokens: string[] = [];
      for (const g of groups) {
        if (node.startIndex >= g.startIndex && node.endIndex <= g.endIndex) {
          groupTokens.push(...g.tokens);
        }
      }

      const routeAuth = routeTokens.filter(laravelTokenIsAuth);
      const groupAuth = groupTokens.filter(laravelTokenIsAuth);
      const result = classifyRoute({
        vettedAuthTokens: routeAuth.length > 0 ? routeAuth : groupAuth,
        publicOverrides,
        routePattern,
        // Group-derived auth is the centralized idiom here — the belt keeps
        // /login-class routes public even inside an auth group (Sem 10).
        centralizedOnly: routeAuth.length === 0,
      });

      // Span capture (Sem 6): only inline closure handlers — controller
      // references ([UserController::class, 'index']) are cross-file → null.
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
        framework: 'laravel',
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
