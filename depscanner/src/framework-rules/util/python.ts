import type { Node, Tree } from 'web-tree-sitter';
import type { ImportBinding } from '../../tree-sitter-extractor/languages/types';
import type { EntryPointClassification, HandlerSpan, HttpMethod } from '../types';
import { matchesAuthName } from './auth-evidence';

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

// ---------------------------------------------------------------------------
// Django view auth analysis (entry-point auth classification, T9).
//
// The auth evidence (@login_required / LoginRequiredMixin / permission_classes)
// lives in views.py, next to the taint sources (`request.GET[...]`). We classify
// each view here and bank per-view facts; postProcess re-homes them (urls.py is
// not needed).
// ---------------------------------------------------------------------------

/** Django decorator names that enforce auth (beyond the shared name patterns). */
const DJANGO_AUTH_DECORATORS = /login_required|permission_required|staff_member_required|user_passes_test/i;
/** DRF/mixin auth base classes. */
const DJANGO_AUTH_MIXINS = /LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin/;
/** DRF permission classes that ENFORCE auth. */
const DRF_AUTH_PERMISSION = /IsAuthenticated\b|IsAdminUser|DjangoModelPermissions|IsAuthenticatedOrReadOnly/;
/** DRF permission classes / markers that make a view explicitly public. */
const DRF_PUBLIC_PERMISSION = /AllowAny/;
/** DRF conditional coverage (Sem 3): read-open, write-authed — does NOT cover. */
const DRF_CONDITIONAL_PERMISSION = /IsAuthenticatedOrReadOnly/;
/** Django HTTP-verb method names on class-based views. */
const DJANGO_CBV_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options',
  'list', 'create', 'retrieve', 'update', 'partial_update', 'destroy']);

export interface DjangoViewFact {
  name: string;
  handlerSpan: HandlerSpan;
  classification: EntryPointClassification;
  demotionEligible: boolean;
  middlewareChain: string[] | null;
}

/** Classify a decorator list (function views) → auth / public-override / neither. */
function classifyDjangoDecorators(decorators: readonly Node[], source: string): {
  authed: boolean; publicOverride: boolean; mechanism: string | null;
} {
  let authed = false;
  let mechanism: string | null = null;
  for (const dec of decorators) {
    const text = decoratorTokenText(dec, source);
    if (DJANGO_AUTH_DECORATORS.test(text) || (matchesAuthName(text) && !/optional/i.test(text))) {
      authed = true;
      mechanism = text.split('(')[0];
    }
  }
  return { authed, publicOverride: false, mechanism };
}

/** DRF `permission_classes = [...]` (or `.permission_classes`) on a class body. */
function classBodyPermissionEvidence(body: Node, source: string): {
  authed: boolean; publicOverride: boolean; conditional: boolean; mechanism: string | null;
} {
  let authed = false;
  let publicOverride = false;
  let conditional = false;
  let mechanism: string | null = null;
  for (let i = 0; i < body.namedChildCount; i++) {
    const stmt = body.namedChild(i)!;
    if (stmt.type !== 'expression_statement') continue;
    const assign = stmt.namedChild(0);
    if (assign?.type !== 'assignment') continue;
    const left = assign.childForFieldName('left');
    if (!left || textOf(left, source) !== 'permission_classes') continue;
    const right = assign.namedChild(1);
    const text = right ? textOf(right, source) : '';
    if (DRF_CONDITIONAL_PERMISSION.test(text)) { conditional = true; }
    if (DRF_PUBLIC_PERMISSION.test(text) || /^\[\s*\]$/.test(text.trim())) { publicOverride = true; }
    else if (DRF_AUTH_PERMISSION.test(text) && !DRF_CONDITIONAL_PERMISSION.test(text)) { authed = true; mechanism = 'permission_classes'; }
  }
  return { authed, publicOverride, conditional, mechanism };
}

/**
 * Analyze a Python file's Django views → per-view auth classification.
 * Function views: classified from their decorators, span = the def. Class-based
 * views: classified from auth mixins + DRF permission_classes; each HTTP-verb
 * method gets a record with the class classification + the method's span, plus a
 * whole-class record for the class body span.
 */
export function analyzeDjangoViews(root: Node, source: string): DjangoViewFact[] {
  const out: DjangoViewFact[] = [];

  const walk = (node: Node): void => {
    if (node.type === 'decorated_definition') {
      const def = node.namedChild(node.namedChildCount - 1);
      if (def?.type === 'function_definition') {
        const decorators = decoratorsOf(def);
        const { authed, mechanism } = classifyDjangoDecorators(decorators, source);
        if (authed) {
          const nameNode = def.childForFieldName('name');
          out.push({
            name: nameNode ? textOf(nameNode, source) : '(view)',
            handlerSpan: { startLine: def.startPosition.row + 1, endLine: def.endPosition.row + 1 },
            classification: 'AUTH_INTERNAL',
            demotionEligible: true,
            middlewareChain: mechanism ? [mechanism] : null,
          });
        }
      }
    }
    if (node.type === 'class_definition') {
      const superclasses = node.childForFieldName('superclasses');
      const superText = superclasses ? textOf(superclasses, source) : '';
      const body = node.childForFieldName('body');
      const mixinAuthed = DJANGO_AUTH_MIXINS.test(superText);
      const perm = body ? classBodyPermissionEvidence(body, source) : { authed: false, publicOverride: false, conditional: false, mechanism: null };
      const authed = (mixinAuthed || perm.authed) && !perm.publicOverride && !perm.conditional;
      if (authed && body) {
        const mechanism = perm.mechanism ?? (mixinAuthed ? superText.match(DJANGO_AUTH_MIXINS)?.[0] ?? 'auth_mixin' : 'auth_mixin');
        // Each HTTP-verb method → record with the method's span.
        let sawMethod = false;
        for (let i = 0; i < body.namedChildCount; i++) {
          const m = body.namedChild(i)!;
          const fnDef = m.type === 'function_definition' ? m
            : (m.type === 'decorated_definition' && m.namedChild(m.namedChildCount - 1)?.type === 'function_definition'
              ? m.namedChild(m.namedChildCount - 1)! : null);
          if (!fnDef) continue;
          const nm = fnDef.childForFieldName('name');
          const methodName = nm ? textOf(nm, source) : '';
          if (!DJANGO_CBV_METHODS.has(methodName)) continue;
          sawMethod = true;
          out.push({
            name: methodName,
            handlerSpan: { startLine: fnDef.startPosition.row + 1, endLine: fnDef.endPosition.row + 1 },
            classification: 'AUTH_INTERNAL',
            demotionEligible: true,
            middlewareChain: [mechanism],
          });
        }
        // Whole-class fallback span (covers CBVs whose source fires outside a
        // verb method, e.g. get_queryset).
        if (!sawMethod) {
          const nameNode = node.childForFieldName('name');
          out.push({
            name: nameNode ? textOf(nameNode, source) : '(view)',
            handlerSpan: { startLine: node.startPosition.row + 1, endLine: node.endPosition.row + 1 },
            classification: 'AUTH_INTERNAL',
            demotionEligible: true,
            middlewareChain: [mechanism],
          });
        }
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(root);
  return out;
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
