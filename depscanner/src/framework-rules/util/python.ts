import type { Node, Tree } from 'web-tree-sitter';
import type { ImportBinding } from '../../tree-sitter-extractor/languages/types';
import type { EntryPointClassification, HttpMethod } from '../types';

export function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

export function pythonStringLiteral(node: Node | null, source: string): string | null {
  if (!node || node.type !== 'string') return null;
  // Python string nodes wrap a string_start, string_content, string_end.
  // Walk named children for string_content; fall back to trimming quotes.
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'string_content') return textOf(c, source);
  }
  const raw = textOf(node, source);
  const matched = raw.match(/^[rRbBuUfF]*(['"]{1,3})([\s\S]*?)\1$/);
  return matched ? matched[2] : null;
}

export const HTTP_METHOD_NAMES: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
};

/** 1-based line number — matches how the DB stores it. */
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
 * Collect local-variable bindings created by calling one of the given
 * class names. Given `callableNames = ['Flask', 'FastAPI']` this matches
 * `app = Flask(__name__)` and `api = FastAPI()`, returning
 * `{'app' → 'Flask', 'api' → 'FastAPI'}`.
 */
export function findClassInstances(
  root: Node,
  source: string,
  callableNames: readonly string[]
): Map<string, string> {
  const result = new Map<string, string>();
  const set = new Set(callableNames);

  const walk = (node: Node): void => {
    if (node.type === 'assignment') {
      const left = node.childForFieldName('left');
      // Second named child is the right-hand value.
      const right = node.namedChild(1);
      if (left?.type === 'identifier' && right?.type === 'call') {
        const fn = right.childForFieldName('function');
        let fnName: string | null = null;
        if (fn?.type === 'identifier') {
          fnName = textOf(fn, source);
        } else if (fn?.type === 'attribute') {
          // `web.RouteTableDef()` / `tornado.web.Application()` — take the
          // attribute (rightmost segment).
          const attr = fn.childForFieldName('attribute');
          if (attr) fnName = textOf(attr, source);
        }
        if (fnName && set.has(fnName)) result.set(textOf(left, source), fnName);
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(root);
  return result;
}

/**
 * Flag Python auth-flavored imports. Flips PUBLIC_UNAUTH → AUTH_INTERNAL.
 */
export const PY_AUTH_MIDDLEWARE: ReadonlyArray<{ pkg: string; mechanism: string }> = [
  { pkg: 'flask_login', mechanism: 'session_cookie' },
  { pkg: 'flask_jwt_extended', mechanism: 'bearer_jwt' },
  { pkg: 'flask_jwt', mechanism: 'bearer_jwt' },
  { pkg: 'fastapi.security', mechanism: 'bearer_jwt' },
  { pkg: 'jwt', mechanism: 'bearer_jwt' },
  { pkg: 'pyjwt', mechanism: 'bearer_jwt' },
  { pkg: 'django.contrib.auth', mechanism: 'session_cookie' },
  { pkg: 'rest_framework.authentication', mechanism: 'bearer_token' },
  { pkg: 'rest_framework.permissions', mechanism: 'rest_framework_permissions' },
  { pkg: 'starlette.authentication', mechanism: 'bearer_token' },
];

export function detectPyAuthMechanism(imports: readonly ImportBinding[]): string | null {
  for (const imp of imports) {
    const hit = PY_AUTH_MIDDLEWARE.find((m) => imp.source === m.pkg || imp.source.startsWith(`${m.pkg}.`));
    if (hit) return hit.mechanism;
  }
  return null;
}

export function classifyFromAuth(authMechanism: string | null): EntryPointClassification {
  return authMechanism ? 'AUTH_INTERNAL' : 'PUBLIC_UNAUTH';
}

/**
 * Return the decorator nodes that precede a `function_definition` inside a
 * `decorated_definition` parent. Returns empty if the function isn't decorated.
 */
export function decoratorsOf(funcDef: Node): Node[] {
  const parent = funcDef.parent;
  if (!parent || parent.type !== 'decorated_definition') return [];
  const out: Node[] = [];
  for (let i = 0; i < parent.namedChildCount; i++) {
    const c = parent.namedChild(i)!;
    if (c.type === 'decorator') out.push(c);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Python route-auth evidence helpers (entry-point auth classification, T7c).
// ---------------------------------------------------------------------------

/**
 * Full text of a decorator's inner expression — `login_required`,
 * `jwt_required(optional=True)`, `auth.login_required` — used as the evidence
 * token so kwarg-shaped vetoes (`optional=True`) are veto-visible.
 */
export function decoratorTokenText(dec: Node, source: string): string {
  const inner = dec.namedChild(0);
  return inner ? textOf(inner, source) : '';
}

/**
 * FastAPI auth-dependency targets beyond the shared auth-name patterns:
 * `Depends(get_current_user)` / `Depends(oauth2_scheme)` — canonical
 * tutorial/idiom names for enforced authentication.
 */
export const FASTAPI_AUTH_DEP_RE = /current_?user|oauth2|api_?key|http_?bearer|security_?scheme/i;

/**
 * Collect `Depends(x)` / `Security(x)` target tokens from a subtree — used on
 * a FastAPI function's parameter list and on a decorator/constructor
 * `dependencies=[...]` kwarg value. `Security(...)` targets are ALWAYS
 * security requirements; `Depends(...)` targets are evidence only when their
 * name is auth-shaped (caller filters).
 */
export function collectDependencyTargets(root: Node | null, source: string): Array<{ kind: 'depends' | 'security'; target: string }> {
  if (!root) return [];
  const out: Array<{ kind: 'depends' | 'security'; target: string }> = [];
  const walk = (n: Node): void => {
    if (n.type === 'call') {
      const fn = n.childForFieldName('function');
      const fnName = fn?.type === 'identifier' ? textOf(fn, source) : null;
      if (fnName === 'Depends' || fnName === 'Security') {
        const args = n.childForFieldName('arguments');
        const first = args?.namedChild(0);
        const target = first ? textOf(first, source) : '';
        out.push({ kind: fnName === 'Security' ? 'security' : 'depends', target });
      }
    }
    for (let i = 0; i < n.namedChildCount; i++) walk(n.namedChild(i)!);
  };
  walk(root);
  return out;
}

/** The `name=` keyword-argument value node of a call's argument list. */
export function keywordArgValue(callNode: Node | null, name: string, source: string): Node | null {
  const args = callNode?.childForFieldName('arguments');
  if (!args) return null;
  for (let i = 0; i < args.namedChildCount; i++) {
    const c = args.namedChild(i)!;
    if (c.type !== 'keyword_argument') continue;
    const key = c.childForFieldName('name');
    if (key && textOf(key, source) === name) return c.childForFieldName('value');
  }
  return null;
}

/** `@obj.attr(...)` → returns `{ object: 'obj', attr: 'attr', call: <Node> }`. */
export function parseDecorator(dec: Node, source: string): {
  object: string | null;
  attr: string | null;
  call: Node | null;
  name: string | null;
} {
  const inner = dec.namedChild(0);
  if (!inner) return { object: null, attr: null, call: null, name: null };
  if (inner.type === 'call') {
    const fn = inner.childForFieldName('function');
    if (fn?.type === 'attribute') {
      const object = fn.childForFieldName('object');
      const attr = fn.childForFieldName('attribute');
      return {
        object: object?.type === 'identifier' ? textOf(object, source) : null,
        attr: attr ? textOf(attr, source) : null,
        call: inner,
        name: null,
      };
    }
    if (fn?.type === 'identifier') {
      return { object: null, attr: null, call: inner, name: textOf(fn, source) };
    }
  }
  if (inner.type === 'attribute') {
    const object = inner.childForFieldName('object');
    const attr = inner.childForFieldName('attribute');
    return {
      object: object?.type === 'identifier' ? textOf(object, source) : null,
      attr: attr ? textOf(attr, source) : null,
      call: null,
      name: null,
    };
  }
  if (inner.type === 'identifier') {
    return { object: null, attr: null, call: null, name: textOf(inner, source) };
  }
  return { object: null, attr: null, call: null, name: null };
}
