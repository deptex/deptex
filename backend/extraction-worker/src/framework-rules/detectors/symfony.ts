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

// Symfony (PHP 8+ attributes):
//   class UserController {
//     #[Route('/users', methods: ['GET', 'POST'])]
//     public function index() {}
//   }
// Also older annotation form in docblocks is possible but we only cover the
// native attribute syntax — easier to detect and what new projects use.

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
      // Symfony attributes sit as `attribute_list` siblings — iterate preceding
      // attribute_list children on the method's parent that belong to this
      // method. Simpler: method_declaration's first named children include
      // attribute_list entries before `name`.
      let classRoute: string | null = null;
      // Walk up to class and find a class-level #[Route(...)]
      const klass = node.parent?.parent; // method → declaration_list → class_declaration
      if (klass?.type === 'class_declaration') {
        const classAttr = findRouteAttribute(klass, source);
        classRoute = classAttr?.path ?? null;
      }

      // Method-level Route attribute
      const methodRoute = findRouteAttribute(node, source);
      if (!methodRoute && !classRoute) return;

      const { path, methods } = methodRoute ?? { path: null, methods: [] };
      if (!path) return;

      const fullPath = classRoute ? joinRoute(classRoute, path) : path;
      const nameNode = node.childForFieldName('name');
      const handlerName = nameNode ? textOf(nameNode, source) : null;
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
    });
    return entryPoints;
  },
};

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
