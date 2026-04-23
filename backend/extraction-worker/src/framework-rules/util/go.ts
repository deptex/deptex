import type { Node, Tree } from 'web-tree-sitter';
import type { EntryPointClassification, HttpMethod } from '../types';
import type { ImportBinding } from '../../tree-sitter-extractor/languages/types';

export function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

export function goStringLiteral(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type !== 'interpreted_string_literal' && node.type !== 'raw_string_literal') return null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'interpreted_string_literal_content' || c.type === 'raw_string_literal_content') {
      return textOf(c, source);
    }
  }
  const raw = textOf(node, source);
  const m = raw.match(/^["`](.*)["`]$/s);
  return m ? m[1] : null;
}

export function lineOf(node: Node): number {
  return node.startPosition.row + 1;
}

export function walkTree(tree: Tree, visit: (node: Node) => void): void {
  const walk = (node: Node): void => {
    visit(node);
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(tree.rootNode);
}

/**
 * Find identifiers assigned from calling any of the given package-qualified
 * factory names. For `r := gin.Default()` with `factories = [{pkgAlias:'gin',
 * fn:'Default'}]`, returns `{'r'}`. Handles both `:=` (short_var_declaration)
 * and `=` assignment.
 */
export function findInstancesFromFactory(
  root: Node,
  source: string,
  factories: ReadonlyArray<{ pkgAlias: string; fn: string }>
): Set<string> {
  const out = new Set<string>();

  const matchesFactory = (call: Node): boolean => {
    const fn = call.childForFieldName('function');
    if (fn?.type !== 'selector_expression') return false;
    const operand = fn.childForFieldName('operand');
    const field = fn.childForFieldName('field');
    if (operand?.type !== 'identifier' || !field) return false;
    const op = textOf(operand, source);
    const fname = textOf(field, source);
    return factories.some((f) => f.pkgAlias === op && f.fn === fname);
  };

  const walk = (node: Node): void => {
    if (node.type === 'short_var_declaration' || node.type === 'assignment_statement') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      if (left?.type === 'expression_list' && right?.type === 'expression_list') {
        if (left.namedChildCount === 1 && right.namedChildCount === 1) {
          const l = left.namedChild(0)!;
          const r = right.namedChild(0)!;
          if (l.type === 'identifier' && r.type === 'call_expression' && matchesFactory(r)) {
            out.add(textOf(l, source));
          }
        }
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(root);
  return out;
}

/** Go auth-flavored packages. */
export const GO_AUTH_PACKAGES: ReadonlyArray<{ prefix: string; mechanism: string }> = [
  { prefix: 'github.com/golang-jwt/jwt', mechanism: 'bearer_jwt' },
  { prefix: 'github.com/dgrijalva/jwt-go', mechanism: 'bearer_jwt' },
  { prefix: 'github.com/lestrrat-go/jwx', mechanism: 'bearer_jwt' },
  { prefix: 'github.com/gorilla/sessions', mechanism: 'session_cookie' },
  { prefix: 'github.com/gin-contrib/sessions', mechanism: 'session_cookie' },
];

export function detectGoAuthMechanism(imports: readonly ImportBinding[]): string | null {
  for (const imp of imports) {
    const hit = GO_AUTH_PACKAGES.find((p) => imp.source === p.prefix || imp.source.startsWith(`${p.prefix}/`));
    if (hit) return hit.mechanism;
  }
  return null;
}

export function classifyFromAuth(auth: string | null): EntryPointClassification {
  return auth ? 'AUTH_INTERNAL' : 'PUBLIC_UNAUTH';
}

/** Normalize handler display — returns the selector text or identifier name. */
export function handlerTextOf(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type === 'identifier') return textOf(node, source);
  if (node.type === 'selector_expression') return textOf(node, source);
  if (node.type === 'func_literal') return '(anonymous)';
  return null;
}

export const GO_HTTP_METHODS_UPPER: Record<string, HttpMethod> = {
  GET: 'GET', POST: 'POST', PUT: 'PUT', PATCH: 'PATCH',
  DELETE: 'DELETE', HEAD: 'HEAD', OPTIONS: 'OPTIONS',
};

export const GO_HTTP_METHODS_PASCAL: Record<string, HttpMethod> = {
  Get: 'GET', Post: 'POST', Put: 'PUT', Patch: 'PATCH',
  Delete: 'DELETE', Head: 'HEAD', Options: 'OPTIONS',
};

/**
 * Find `<instanceName>.<Method>(pattern, handler)` call-expressions where
 * Method is in the allowed verb table. Returns matched data ready for
 * entry-point emission.
 */
export interface RouteCall {
  node: Node;
  methodName: string;
  routePattern: string;
  handlerName: string | null;
}

export function findRouteCalls(
  tree: Tree,
  source: string,
  instances: Set<string>,
  verbTable: Record<string, HttpMethod>,
  extraMethods: readonly string[] = []
): Array<RouteCall & { httpMethod: HttpMethod | null }> {
  const out: Array<RouteCall & { httpMethod: HttpMethod | null }> = [];
  const extras = new Set(extraMethods);
  walkTree(tree, (node) => {
    if (node.type !== 'call_expression') return;
    const fn = node.childForFieldName('function');
    if (fn?.type !== 'selector_expression') return;
    const operand = fn.childForFieldName('operand');
    const field = fn.childForFieldName('field');
    if (operand?.type !== 'identifier' || !field) return;
    const op = textOf(operand, source);
    const method = textOf(field, source);
    if (!instances.has(op)) return;
    const isVerb = method in verbTable;
    const isExtra = extras.has(method);
    if (!isVerb && !isExtra) return;
    const args = node.childForFieldName('arguments');
    const firstArg = args?.namedChild(0);
    const routePattern = goStringLiteral(firstArg ?? null, source);
    if (!routePattern) return;
    const handlerArg = args ? args.namedChild(args.namedChildCount - 1) : null;
    out.push({
      node,
      methodName: method,
      routePattern,
      handlerName: handlerTextOf(handlerArg, source),
      httpMethod: isVerb ? verbTable[method] : null,
    });
  });
  return out;
}
