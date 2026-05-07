import type { Node, Tree } from 'web-tree-sitter';
import type { ImportBinding } from '../../tree-sitter-extractor/languages/types';
import type { EntryPointClassification, HttpMethod } from '../types';

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
