import type { Node, Tree } from 'web-tree-sitter';
import type { ImportBinding } from '../../tree-sitter-extractor/languages/types';
import type { EntryPointClassification, HttpMethod } from '../types';
import { spanOfNode, type HandlerSpan, type MiddlewareToken } from './auth-evidence';

// Re-exported for the JS detectors (the definitions are language-agnostic and
// live in auth-evidence.ts so the Go/PHP utils share them).
export { categorizeMiddlewareTokens, hasRouteLocalAuth } from './auth-evidence';
export type { MiddlewareToken } from './auth-evidence';

export function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

export function stringLiteralValue(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type !== 'string') return null;
  const frag = node.namedChild(0);
  if (frag && frag.type === 'string_fragment') return textOf(frag, source);
  const raw = textOf(node, source);
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    return raw.slice(1, -1);
  }
  return null;
}

export function handlerDescriptor(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type === 'identifier') return textOf(node, source);
  if (node.type === 'function_expression' || node.type === 'function_declaration') {
    const name = node.childForFieldName('name');
    return name ? textOf(name, source) : '(anonymous)';
  }
  if (node.type === 'arrow_function') return '(anonymous)';
  if (node.type === 'member_expression') return textOf(node, source);
  return null;
}

export const HTTP_METHOD_NAMES: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
};

/**
 * Tracks variables assigned from calling the given imported identifier.
 *
 * For `const app = express()` given localName="express", returns `{"app"}`.
 * Also follows `.Method()` forms when `extraMethods` is provided — e.g. for
 * Express's `const router = express.Router()` pass `extraMethods: ['Router']`.
 */
export function findInstancesOfImport(
  root: Node,
  source: string,
  localName: string,
  opts: { extraMethods?: readonly string[]; includeNew?: boolean } = {}
): Set<string> {
  const instances = new Set<string>();
  const extraMethods = new Set(opts.extraMethods ?? []);
  const includeNew = opts.includeNew ?? false;

  const valueMatches = (value: Node | null): boolean => {
    if (!value) return false;
    if (value.type === 'call_expression') {
      const fn = value.childForFieldName('function');
      if (!fn) return false;
      if (fn.type === 'identifier') return textOf(fn, source) === localName;
      if (fn.type === 'member_expression') {
        const object = fn.childForFieldName('object');
        const property = fn.childForFieldName('property');
        if (object?.type === 'identifier' && property) {
          return textOf(object, source) === localName && extraMethods.has(textOf(property, source));
        }
      }
    }
    if (includeNew && value.type === 'new_expression') {
      const ctor = value.childForFieldName('constructor');
      if (ctor?.type === 'identifier') return textOf(ctor, source) === localName;
    }
    return false;
  };

  const walk = (node: Node): void => {
    if (node.type === 'variable_declarator') {
      const name = node.childForFieldName('name');
      const value = node.childForFieldName('value');
      if (name?.type === 'identifier' && valueMatches(value)) {
        instances.add(textOf(name, source));
      }
    } else if (node.type === 'assignment_expression') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      if (left?.type === 'identifier' && valueMatches(right)) {
        instances.add(textOf(left, source));
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };

  walk(root);
  return instances;
}

/**
 * File-level heuristic: if any of these auth-flavored packages is imported,
 * route classifications flip from PUBLIC_UNAUTH → AUTH_INTERNAL. The
 * returned mechanism string identifies the auth mechanism for UI display.
 */
export const AUTH_MIDDLEWARE: ReadonlyArray<{ pkg: string; mechanism: string }> = [
  { pkg: 'passport', mechanism: 'passport' },
  { pkg: 'express-jwt', mechanism: 'bearer_jwt' },
  { pkg: 'jsonwebtoken', mechanism: 'bearer_jwt' },
  { pkg: '@fastify/jwt', mechanism: 'bearer_jwt' },
  { pkg: 'fastify-jwt', mechanism: 'bearer_jwt' },
  { pkg: 'express-session', mechanism: 'session_cookie' },
  { pkg: 'cookie-session', mechanism: 'session_cookie' },
  { pkg: 'koa-jwt', mechanism: 'bearer_jwt' },
  { pkg: 'koa-passport', mechanism: 'passport' },
  { pkg: 'next-auth', mechanism: 'next_auth' },
  { pkg: 'helmet', mechanism: 'helmet' },
];

export function detectAuthMechanism(imports: readonly ImportBinding[]): string | null {
  for (const imp of imports) {
    const hit = AUTH_MIDDLEWARE.find((m) => imp.source === m.pkg || imp.source.startsWith(`${m.pkg}/`));
    if (hit) return hit.mechanism;
  }
  return null;
}

export function classifyFromAuth(authMechanism: string | null): EntryPointClassification {
  return authMechanism ? 'AUTH_INTERNAL' : 'PUBLIC_UNAUTH';
}

/** 1-based line number — matches how the DB stores it. */
export function lineOf(node: Node): number {
  return node.startPosition.row + 1;
}

/** Convenience — walk the whole tree once, invoking `visit` on every node. */
export function walkTree(tree: Tree, visit: (node: Node) => void): void {
  const walk = (node: Node): void => {
    visit(node);
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(tree.rootNode);
}

// ---------------------------------------------------------------------------
// Handler-span capture + demotion eligibility (entry-point auth join, Sem 6).
//
// A taint flow demotes only when its source line falls inside an authed,
// demotion-eligible handler span. We record the span of the TERMINAL handler
// argument node exclusively — never the registration call node or middleware
// args (those run pre-auth and would mis-demote). A named handler resolves to
// its same-file declaration span only when the reference is a bare identifier
// with exactly one matching function/arrow declaration; wrapped
// (`asyncWrap(h)`), member (`ctrl.method`), array, and cross-file handlers get
// a null span (→ unmatched → PUBLIC, fail-safe).
// ---------------------------------------------------------------------------

function forEachNode(root: Node, visit: (node: Node) => void): void {
  const walk = (node: Node): void => {
    visit(node);
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(root);
}

/**
 * Resolve the span of a same-file named handler. Returns the declaration span
 * only when exactly ONE `function_declaration` named `name` OR one
 * `variable_declarator` named `name` whose value is directly an arrow/function
 * expression exists. Zero or multiple matches → null (ambiguous → fail-safe).
 */
export function resolveSameFileHandlerSpan(root: Node, source: string, name: string): HandlerSpan | null {
  const matches: Node[] = [];
  forEachNode(root, (node) => {
    if (node.type === 'function_declaration') {
      const n = node.childForFieldName('name');
      if (n && textOf(n, source) === name) matches.push(node);
    } else if (node.type === 'variable_declarator') {
      const n = node.childForFieldName('name');
      const v = node.childForFieldName('value');
      if (n?.type === 'identifier' && textOf(n, source) === name
        && (v?.type === 'arrow_function' || v?.type === 'function_expression')) {
        matches.push(v);
      }
    }
  });
  return matches.length === 1 ? spanOfNode(matches[0]) : null;
}

/**
 * Compute a route's `handlerSpan` from its handler argument node.
 * - inline function/arrow → that node's span (always eligible; can't be
 *   referenced elsewhere).
 * - bare identifier → same-file declaration span (subject to the eligibility
 *   guard below).
 * - member / call / array / anything else → null.
 */
export function handlerSpanForArg(handlerArg: Node | null, root: Node, source: string): HandlerSpan | null {
  if (!handlerArg) return null;
  if (handlerArg.type === 'arrow_function' || handlerArg.type === 'function_expression'
    || handlerArg.type === 'function_declaration') {
    return spanOfNode(handlerArg);
  }
  if (handlerArg.type === 'identifier') {
    return resolveSameFileHandlerSpan(root, source, textOf(handlerArg, source));
  }
  return null;
}

/**
 * JS/TS demotion-eligibility guard (Sem 6). A named handler is INELIGIBLE
 * (its route classifies but never demotes a flow) when it could be re-mounted
 * or invoked from code we can't see:
 *   (a) it appears in any export-shaped construct, OR
 *   (b) it is referenced elsewhere in the file (occurrence count > 2 =
 *       one declaration name + one registration reference).
 * Over-approximation: false-ineligible = coverage loss (safe). Inline handlers
 * are always eligible — callers pass `isInline` and skip this.
 */
export function isNamedHandlerDemotionEligible(root: Node, source: string, name: string): boolean {
  let exported = false;
  let identifierRefs = 0;
  forEachNode(root, (node) => {
    if (node.type === 'identifier' && textOf(node, source) === name) identifierRefs++;
    if (exported) return;
    if (node.type === 'export_statement') {
      // Any export_statement that wraps or names this handler.
      if (textOf(node, source).match(new RegExp(`\\b${escapeRe(name)}\\b`))) exported = true;
    } else if (node.type === 'assignment_expression') {
      const left = node.childForFieldName('left');
      if (left && rootsAtExports(left, source)) {
        // exports.x = h / module.exports = { h } / module.exports.h = h
        if (textOf(node, source).match(new RegExp(`\\b${escapeRe(name)}\\b`))) exported = true;
      }
    }
  });
  return !exported && identifierRefs <= 2;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** True when a member-expression LHS chain roots at `exports` or `module.exports`. */
function rootsAtExports(node: Node, source: string): boolean {
  let cur: Node | null = node;
  while (cur && cur.type === 'member_expression') cur = cur.childForFieldName('object');
  if (!cur) return false;
  const root = textOf(cur, source);
  return root === 'exports' || root === 'module';
}

// ---------------------------------------------------------------------------
// Shared JS middleware-evidence helpers (entry-point auth classification).
// Used by the express / fastify / koa detectors so the token → evidence-bucket
// logic can never diverge between them.
// ---------------------------------------------------------------------------

export function middlewareToken(node: Node, source: string): MiddlewareToken | null {
  if (node.type === 'identifier') {
    const t = textOf(node, source);
    return { display: t, classify: t };
  }
  if (node.type === 'member_expression') {
    const t = textOf(node, source);
    return { display: t, classify: t };
  }
  if (node.type === 'call_expression') {
    const fn = node.childForFieldName('function');
    const fnText = fn ? textOf(fn, source) : '';
    // Fold string-literal args into the classify token so `passport.authenticate('anonymous')`
    // and `guard('optional')` are veto-visible without a full arg inspector.
    const argStrings: string[] = [];
    const argsNode = node.childForFieldName('arguments');
    if (argsNode) {
      for (let i = 0; i < argsNode.namedChildCount; i++) {
        const s = stringLiteralValue(argsNode.namedChild(i)!, source);
        if (s) argStrings.push(s);
      }
    }
    if (!fnText) return null;
    return { display: fnText, classify: `${fnText} ${argStrings.join(' ')}`.trim() };
  }
  return null;
}

/** True when `node` is a program-level statement (no enclosing function/method/arrow). */
export function isTopLevelStatement(node: Node): boolean {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    const t = cur.type;
    if (
      t === 'function_declaration' || t === 'function_expression' || t === 'arrow_function' ||
      t === 'generator_function' || t === 'generator_function_declaration' || t === 'method_definition'
    ) {
      return false;
    }
    if (t === 'program') return true;
  }
  return true;
}

/**
 * A same-file inline verifier call is machine evidence (Sem 5): a webhook
 * handler that verifies a signature in its own body (`x.verify(...)`,
 * `stripe.webhooks.constructEvent(...)`). Scanned only inside an inline handler
 * span — cross-file verifier bodies are NOT detectable (documented v1 residual).
 */
export function inlineHandlerHasVerifier(handler: Node | null, source: string): string | null {
  if (!handler) return null;
  if (handler.type !== 'arrow_function' && handler.type !== 'function_expression' && handler.type !== 'function_declaration') {
    return null;
  }
  let hit: string | null = null;
  const walk = (n: Node): void => {
    if (hit) return;
    if (n.type === 'call_expression') {
      const fn = n.childForFieldName('function');
      if (fn?.type === 'member_expression') {
        const prop = fn.childForFieldName('property');
        const propName = prop ? textOf(prop, source) : '';
        if (/^verify$/i.test(propName) || /construct_?event/i.test(propName)) {
          hit = textOf(fn, source);
          return;
        }
      }
    }
    for (let i = 0; i < n.namedChildCount; i++) walk(n.namedChild(i)!);
  };
  walk(handler);
  return hit;
}
