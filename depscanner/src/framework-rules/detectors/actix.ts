import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';
import {
  classifyRoute,
  isOptionalVetoed,
  matchesAuthName,
  spanOfNode,
} from '../util/auth-evidence';

function textOf(n: Node | null, src: string): string {
  return n ? src.slice(n.startIndex, n.endIndex) : '';
}

/**
 * Auth-shaped `.wrap(...)` middleware on a chain rooted at `App::new()` (the
 * whole-app middleware idiom — `HttpAuthentication::bearer(validator)`).
 * Scope-level wraps (`web::scope(...).wrap(...)`) are deliberately ignored:
 * applying them file-wide could wrongly demote routes outside the scope, and
 * resolving scope membership is out of v1 (coverage loss, fail-safe).
 */
function appRootWrapTokens(root: Node, source: string): string[] {
  const out: string[] = [];
  const walk = (n: Node): void => {
    if (n.type === 'call_expression') {
      const fn = n.childForFieldName('function');
      if (fn?.type === 'field_expression' && textOf(fn.childForFieldName('field'), source) === 'wrap') {
        // Walk the receiver chain down to its root call.
        let cur: Node | null = fn.childForFieldName('value') ?? fn.namedChild(0);
        while (cur && cur.type === 'call_expression') {
          const innerFn: Node | null = cur.childForFieldName('function');
          if (innerFn?.type === 'field_expression') {
            cur = innerFn.childForFieldName('value') ?? innerFn.namedChild(0);
          } else if (innerFn?.type === 'scoped_identifier' || innerFn?.type === 'identifier') {
            cur = innerFn;
            break;
          } else {
            cur = null;
          }
        }
        if (cur && /(^|::)App::new$|^App$/.test(textOf(cur, source))) {
          const args = n.childForFieldName('arguments');
          if (args) {
            for (let i = 0; i < args.namedChildCount; i++) {
              const t = textOf(args.namedChild(i)!, source);
              if (t) out.push(t);
            }
          }
        }
      }
    }
    for (let i = 0; i < n.namedChildCount; i++) walk(n.namedChild(i)!);
  };
  walk(root);
  return out;
}

function rustStringLiteral(node: Node | null, source: string): string | null {
  if (!node || node.type !== 'string_literal') return null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'string_content') return textOf(c, source);
  }
  const raw = textOf(node, source);
  const m = raw.match(/^"(.*)"$/s);
  return m ? m[1] : null;
}

// Actix-web attribute macros on async fn:
//   #[get("/users")]
//   async fn list_users() -> impl Responder { ... }
//   #[post("/users")]
//   async fn create_user() -> impl Responder { ... }

const VERB_MACROS: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
};

export const actixDetector: FrameworkDetector = {
  name: 'actix',
  displayName: 'Actix',
  language: 'rust',
  triggerImports: ['actix-web', 'actix_web'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const entryPoints: EntryPoint[] = [];

    // Whole-app `.wrap(...)` middleware on App::new() (centralized — the belt
    // applies to belt routes).
    const wrapTokens = appRootWrapTokens(tree.rootNode, source)
      .filter((t) => matchesAuthName(t) && !isOptionalVetoed(t));

    const walk = (node: Node): void => {
      if (node.type === 'function_item') {
        const attrs = collectPrecedingAttributes(node, source);
        for (const attr of attrs) {
          const verb = VERB_MACROS[attr.name];
          if (!verb) continue;
          if (attr.firstStringArg === null) continue;
          const name = node.childForFieldName('name');
          const result = classifyRoute({
            vettedAuthTokens: wrapTokens,
            routePattern: attr.firstStringArg,
            centralizedOnly: true,
          });
          entryPoints.push({
            filePath: file.filePath,
            lineNumber: node.startPosition.row + 1,
            framework: 'actix',
            handlerName: name ? textOf(name, source) : null,
            httpMethod: verb,
            routePattern: attr.firstStringArg,
            entryPointType: 'http_route',
            classification: result.classification,
            authenticated: result.authenticated,
            authMechanism: null,
            middlewareChain: wrapTokens.length ? wrapTokens : null,
            // Attribute-macro routes are declaration-bound (Sem 6): the macro
            // travels with the fn wherever it's serviced.
            handlerSpan: spanOfNode(node),
            demotionEligible: true,
            metadata: { macro: attr.name },
          });
        }
      }
      for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
    };
    walk(tree.rootNode);
    return entryPoints;
  },
};

export interface RustAttribute {
  name: string;
  firstStringArg: string | null;
  node: Node;
}

export function collectPrecedingAttributes(fnNode: Node, source: string): RustAttribute[] {
  const parent = fnNode.parent;
  if (!parent) return [];
  const out: RustAttribute[] = [];
  const fnStart = fnNode.startIndex;
  for (let i = 0; i < parent.namedChildCount; i++) {
    const c = parent.namedChild(i)!;
    // Compare by startIndex — web-tree-sitter may return a new Node wrapper
    // each call to namedChild, so `===` identity isn't reliable.
    if (c.startIndex === fnStart && c.endIndex === fnNode.endIndex) break;
    if (c.type === 'attribute_item') {
      const attr = c.namedChild(0);
      if (attr?.type !== 'attribute') continue;
      // attribute > path (identifier) + arguments? (delim_token_tree)
      const pathNode = attr.childForFieldName('path') ?? attr.namedChild(0);
      if (!pathNode) continue;
      const name = textOf(pathNode, source);
      const args = attr.childForFieldName('arguments');
      let firstStringArg: string | null = null;
      if (args) {
        // Walk inside the token tree for the first string_literal.
        const findStr = (n: Node): string | null => {
          if (n.type === 'string_literal') return rustStringLiteral(n, source);
          for (let j = 0; j < n.namedChildCount; j++) {
            const r = findStr(n.namedChild(j)!);
            if (r !== null) return r;
          }
          return null;
        };
        firstStringArg = findStr(args);
      }
      out.push({ name, firstStringArg, node: c });
    } else if (c.type === 'function_item') {
      out.length = 0; // reset between functions
    }
  }
  return out;
}
