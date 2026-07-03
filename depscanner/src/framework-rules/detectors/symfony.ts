import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';
import {
  PHP_HTTP_METHODS,
  classifyFromAuth,
  detectPhpAuthMechanism,
  lineOf,
  phpStringLiteral,
  textOf,
  walkTree,
} from '../util/php';

// Symfony route declarations come in two flavours; we detect both:
//
//   PHP 8+ native attributes:
//     class UserController {
//       #[Route('/users', methods: ['GET', 'POST'])]
//       public function index() {}
//     }
//
//   Legacy Doctrine-style docblock annotations (Symfony ≤5 / PHP 7.x — still
//   the majority of real-world apps, e.g. symfony/demo):
//     /** @Route("/blog") */
//     class BlogController {
//       /** @Route("/posts/{slug}", methods={"GET"}, name="blog_post") */
//       public function postShow() {}
//     }
//
// tree-sitter parses docblocks as `comment` nodes, so the docblock path reads
// the method's (and class's) immediately-preceding `comment` sibling. Both
// paths funnel through the same joinRoute / classification / http-method logic
// so they produce identically-shaped EntryPoint rows.

interface RouteSpec {
  path: string | null;
  methods: HttpMethod[];
}

export const symfonyDetector: FrameworkDetector = {
  name: 'symfony',
  displayName: 'Symfony',
  language: 'php',
  triggerImports: ['Symfony\\Component\\Routing\\Annotation\\Route', 'Symfony'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectPhpAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'method_declaration') return;

      // Class-level route prefix: attribute first, then docblock fallback.
      let classRoute: string | null = null;
      const klass = node.parent?.parent; // method → declaration_list → class_declaration
      if (klass?.type === 'class_declaration') {
        const classAttr = findRouteAttribute(klass, source);
        classRoute = classAttr?.path ?? null;
        if (classRoute === null) {
          const classDoc = precedingDocblock(klass, source);
          if (classDoc) {
            const prefixRoute = parseDocblockRoutes(classDoc).find((r) => r.path);
            classRoute = prefixRoute?.path ?? null;
          }
        }
      }

      // Method-level routes. Prefer the native #[Route] attribute; only fall
      // back to the docblock when no attribute route is present, so a method
      // carrying BOTH forms is never double-counted.
      const routeSpecs: RouteSpec[] = [];
      const methodAttr = findRouteAttribute(node, source);
      if (methodAttr?.path) {
        routeSpecs.push({ path: methodAttr.path, methods: methodAttr.methods });
      } else {
        const methodDoc = precedingDocblock(node, source);
        if (methodDoc) {
          for (const spec of parseDocblockRoutes(methodDoc)) {
            if (spec.path) routeSpecs.push(spec);
          }
        }
      }

      if (routeSpecs.length === 0) return;

      const nameNode = node.childForFieldName('name');
      const handlerName = nameNode ? textOf(nameNode, source) : null;

      for (const { path, methods } of routeSpecs) {
        const fullPath = classRoute ? joinRoute(classRoute, path) : path;
        const emitted = methods.length > 0 ? methods : [null as HttpMethod | null];
        for (const m of emitted) {
          entryPoints.push({
            filePath: file.filePath,
            lineNumber: lineOf(node),
            framework: 'symfony',
            handlerName,
            httpMethod: m,
            routePattern: fullPath,
            entryPointType: 'http_route',
            classification,
            authenticated: !!authMechanism,
            authMechanism,
            middlewareChain: null,
            metadata: null,
          });
        }
      }
    });
    return entryPoints;
  },
};

/**
 * The immediately-preceding `comment` sibling of a declaration — the node's
 * docblock. tree-sitter attaches PHPDoc blocks as a `comment` sibling right
 * before the `class_declaration` / `method_declaration` they annotate. Returns
 * the raw comment text, or null when the preceding sibling isn't a comment.
 */
function precedingDocblock(node: Node, source: string): string | null {
  const parent = node.parent;
  if (!parent) return null;
  // Find `node` among the parent's named children and return the one before it.
  // Compare by span, not object identity — web-tree-sitter hands back fresh
  // Node wrappers so `===` is unreliable (see framework-rule-pack-guide.md).
  let prev: Node | null = null;
  for (let i = 0; i < parent.namedChildCount; i++) {
    const child = parent.namedChild(i)!;
    if (child.startIndex === node.startIndex && child.endIndex === node.endIndex) {
      if (prev && prev.type === 'comment') return textOf(prev, source);
      return null;
    }
    prev = child;
  }
  return null;
}

/**
 * Extract every `@Route(...)` annotation from a docblock's raw text. A single
 * docblock can declare multiple routes (symfony/demo's BlogController::index
 * carries three), and may also carry unrelated annotations (`@ParamConverter`,
 * `@IsGranted`, `@param`) which are ignored. Returns [] when no `@Route` is
 * present.
 */
function parseDocblockRoutes(docblock: string): RouteSpec[] {
  const specs: RouteSpec[] = [];
  // `@Route` (not `@RouteFoo`) immediately followed by `(`. The `@` guards the
  // left boundary; matching the literal `(` guards the right.
  const re = /@Route\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(docblock)) !== null) {
    const argsStart = m.index + m[0].length;
    const args = readBalancedParen(docblock, argsStart);
    if (args === null) continue;
    specs.push({ path: extractRoutePath(args), methods: extractRouteMethods(args) });
    re.lastIndex = argsStart + args.length; // resume past this annotation
  }
  return specs;
}

/**
 * Given an index just past an opening `(`, return the substring up to (but not
 * including) the matching close paren, respecting nested parens and quoted
 * strings. Null if unbalanced.
 */
function readBalancedParen(text: string, start: number): string | null {
  let depth = 1;
  let inStr: string | null = null;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (ch === '\\') { i++; continue; }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'") inStr = ch;
    else if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return text.slice(start, i);
    }
  }
  return null;
}

// A single- or double-quoted string literal (with backslash escapes). Fresh
// RegExp instances are built from this source so `lastIndex` is never shared.
const QUOTED_SOURCE = "(['\"])((?:\\\\.|(?!\\1)[^\\\\])*)\\1";

/**
 * The route path from a `@Route(...)` argument list. Honours an explicit named
 * `path=`/`path:` key, otherwise takes the first *positional* string literal
 * (Doctrine puts the positional path first). Scans char-by-char so that braces
 * that belong to a route parameter *inside* the path (`/posts/{slug}`,
 * `/page/{page<[1-9]\d*>}`) are preserved, while the top-level `key={...}`
 * blocks (methods/defaults/requirements) — whose inner strings must NOT be
 * mistaken for the path — are skipped by brace-depth. Returns the raw string
 * content (escapes preserved), matching the attribute path's phpStringLiteral.
 */
function extractRoutePath(args: string): string | null {
  const named = args.match(new RegExp(`\\bpath\\s*[=:]\\s*${QUOTED_SOURCE}`));
  if (named) return named[2];
  let brace = 0;
  let prevSig = '';
  for (let i = 0; i < args.length; i++) {
    const ch = args[i];
    if (ch === '"' || ch === "'") {
      const str = readStringLiteral(args, i, ch);
      if (!str) return null;
      // A positional string at the top level, not the value of a `key=`/`key:`.
      if (brace === 0 && prevSig !== '=' && prevSig !== ':') return str.value;
      i = str.endIndex; // skip the string body
      prevSig = ch;
      continue;
    }
    if (ch === '{') brace++;
    else if (ch === '}') { if (brace > 0) brace--; }
    if (!/\s/.test(ch)) prevSig = ch;
  }
  return null;
}

/**
 * Read a quoted string starting at the opening quote. Returns the raw content
 * between the quotes (backslash escapes left intact, mirroring how the
 * attribute path's phpStringLiteral captures `string_content`) plus the index
 * of the closing quote. Null if the string is unterminated.
 */
function readStringLiteral(text: string, start: number, quote: string): { value: string; endIndex: number } | null {
  for (let i = start + 1; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\\') { i++; continue; } // escaped char can't close the string
    if (ch === quote) return { value: text.slice(start + 1, i), endIndex: i };
  }
  return null;
}

/** HTTP verbs from a `methods={"GET","POST"}` (or `methods="GET"`) key. */
function extractRouteMethods(args: string): HttpMethod[] {
  const methods: HttpMethod[] = [];
  const block = args.match(/\bmethods\s*[=:]\s*(\{[^{}]*\}|['"][^'"]*['"])/);
  if (!block) return methods;
  const re = new RegExp(QUOTED_SOURCE, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(block[1])) !== null) {
    const upper = m[2].toUpperCase();
    if (upper in PHP_HTTP_METHODS || ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(upper)) {
      methods.push(upper as HttpMethod);
    }
  }
  return methods;
}

function findRouteAttribute(decl: Node, source: string): { path: string | null; methods: HttpMethod[] } | null {
  for (let i = 0; i < decl.namedChildCount; i++) {
    const child = decl.namedChild(i)!;
    if (child.type !== 'attribute_list') continue;
    // PHP attribute_list children can be either `attribute` or `attribute_group`
    // (the latter wraps one or more attributes in `#[A, B]` syntax).
    const attrs: Node[] = [];
    for (let j = 0; j < child.namedChildCount; j++) {
      const n = child.namedChild(j)!;
      if (n.type === 'attribute') attrs.push(n);
      else if (n.type === 'attribute_group') {
        for (let k = 0; k < n.namedChildCount; k++) {
          const inner = n.namedChild(k)!;
          if (inner.type === 'attribute') attrs.push(inner);
        }
      }
    }
    for (const attr of attrs) {
      const nameNode = attr.childForFieldName('name') ?? attr.namedChild(0);
      if (!nameNode || textOf(nameNode, source) !== 'Route') continue;
      // The arguments node lives at the [parameters] field name on newer
      // PHP grammars (the node type itself is still `arguments`); fall back
      // to the positional child-1 lookup for older grammars.
      const args = attr.childForFieldName('parameters') ?? attr.namedChild(1);
      if (!args) return { path: null, methods: [] };
      let path: string | null = null;
      const methods: HttpMethod[] = [];
      const collectMethodsFromArray = (arr: Node): void => {
        for (let l = 0; l < arr.namedChildCount; l++) {
          const el = arr.namedChild(l)!;
          const elInner = el.type === 'array_element_initializer' ? el.namedChild(0) : el;
          if (elInner?.type === 'string') {
            const s = phpStringLiteral(elInner, source);
            if (!s) continue;
            const upper = s.toUpperCase();
            if (upper in PHP_HTTP_METHODS || ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(upper)) {
              methods.push(upper as HttpMethod);
            }
          }
        }
      };
      for (let k = 0; k < args.namedChildCount; k++) {
        const arg = args.namedChild(k)!;
        // Two PHP-argument shapes:
        //   (1) positional:       argument > <value>
        //   (2) named (PHP 8):    argument > name + <value>
        // Older grammars also emit `named_argument`/`keyword_argument` wrapper
        // nodes; handle that path as a fallback.
        let namedKey: string | null = null;
        let inner: Node | null = null;
        if (arg.type === 'argument') {
          const first = arg.namedChild(0);
          const second = arg.namedChild(1);
          if (first?.type === 'name' && second) {
            namedKey = textOf(first, source);
            inner = second;
          } else {
            inner = first;
          }
        } else if (arg.type === 'named_argument' || arg.type === 'keyword_argument') {
          namedKey = textOf(arg.namedChild(0), source) || null;
          inner = arg.namedChild(1);
        } else {
          inner = arg;
        }
        if (!inner) continue;
        if (!namedKey && inner.type === 'string' && path === null) {
          path = phpStringLiteral(inner, source);
        } else if (namedKey === 'methods' && inner.type === 'array_creation_expression') {
          collectMethodsFromArray(inner);
        }
      }
      return { path, methods };
    }
  }
  return null;
}

function joinRoute(prefix: string | null, sub: string | null): string | null {
  if (!prefix && !sub) return null;
  const p = prefix ? (prefix.startsWith('/') ? prefix : `/${prefix}`).replace(/\/$/, '') : '';
  const s = sub ? (sub.startsWith('/') ? sub : `/${sub}`) : '';
  return (`${p}${s}` || '/').replace(/\/+/g, '/');
}
