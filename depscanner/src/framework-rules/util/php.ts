import type { Node, Tree } from 'web-tree-sitter';
import type { ImportBinding } from '../../tree-sitter-extractor/languages/types';
import type { EntryPointClassification, HttpMethod } from '../types';

export function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

export function phpStringLiteral(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type !== 'string' && node.type !== 'encapsed_string') return null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'string_content' || c.type === 'string_value') return textOf(c, source);
  }
  const raw = textOf(node, source);
  const m = raw.match(/^['"](.*)['"]$/s);
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

export const PHP_HTTP_METHODS: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
};

export const PHP_AUTH_PACKAGES: ReadonlyArray<{ prefix: string; mechanism: string }> = [
  { prefix: 'Illuminate\\Auth', mechanism: 'laravel_auth' },
  { prefix: 'Symfony\\Component\\Security', mechanism: 'symfony_security' },
  { prefix: 'Firebase\\JWT', mechanism: 'bearer_jwt' },
  { prefix: 'Lcobucci\\JWT', mechanism: 'bearer_jwt' },
];

export function detectPhpAuthMechanism(imports: readonly ImportBinding[]): string | null {
  for (const imp of imports) {
    const hit = PHP_AUTH_PACKAGES.find((a) => imp.source === a.prefix || imp.source.startsWith(`${a.prefix}\\`));
    if (hit) return hit.mechanism;
  }
  return null;
}

export function classifyFromAuth(auth: string | null): EntryPointClassification {
  return auth ? 'AUTH_INTERNAL' : 'PUBLIC_UNAUTH';
}

// ---------------------------------------------------------------------------
// Shared PHP route-auth helpers (entry-point auth classification, T7b).
// ---------------------------------------------------------------------------

export interface PhpAttribute {
  name: string;
  firstStringArg: string | null;
  /** Raw argument-list text (for expression-shaped attributes like Security). */
  argsText: string;
}

/** PHP 8 `#[...]` attributes on a class/method declaration. */
export function phpAttributesOn(decl: Node, source: string): PhpAttribute[] {
  const out: PhpAttribute[] = [];
  for (let i = 0; i < decl.namedChildCount; i++) {
    const child = decl.namedChild(i)!;
    if (child.type !== 'attribute_list') continue;
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
      if (!nameNode) continue;
      // Fully-qualified attribute names keep only the terminal segment.
      const name = textOf(nameNode, source).split('\\').pop() ?? '';
      const args = attr.childForFieldName('parameters') ?? attr.namedChild(1);
      let firstStringArg: string | null = null;
      let argsText = '';
      if (args) {
        argsText = textOf(args, source).replace(/^\(|\)$/g, '');
        for (let k = 0; k < args.namedChildCount; k++) {
          const arg = args.namedChild(k)!;
          const inner = arg.type === 'argument' ? (arg.namedChildCount > 1 ? arg.namedChild(1) : arg.namedChild(0)) : arg;
          if (inner && (inner.type === 'string' || inner.type === 'encapsed_string')) {
            firstStringArg = phpStringLiteral(inner, source);
            break;
          }
        }
      }
      out.push({ name, firstStringArg, argsText });
    }
  }
  return out;
}

export interface ChainedCall {
  name: string;
  argsNode: Node | null;
  callNode: Node;
}

/**
 * The fluent-call chain applied ON a call node: for
 * `Route::get(...)->middleware('auth')->name('x')` called on the
 * `Route::get(...)` node, returns [{middleware}, {name}] in order. Spans are
 * compared (not object identity — web-tree-sitter wrappers are fresh).
 */
export function chainedMemberCalls(node: Node, source: string): ChainedCall[] {
  const out: ChainedCall[] = [];
  let cur: Node = node;
  for (;;) {
    const p = cur.parent;
    if (!p || p.type !== 'member_call_expression') break;
    const obj = p.childForFieldName('object');
    if (!obj || obj.startIndex !== cur.startIndex || obj.endIndex !== cur.endIndex) break;
    const nameNode = p.childForFieldName('name');
    out.push({
      name: nameNode ? textOf(nameNode, source) : '',
      argsNode: p.childForFieldName('arguments'),
      callNode: p,
    });
    cur = p;
  }
  return out;
}

/** PHP closure node types across grammar versions. */
export const PHP_CLOSURE_TYPES = new Set([
  'anonymous_function_creation_expression',
  'anonymous_function',
  'arrow_function',
]);

/** Unwrap `argument` wrapper nodes to the value node. */
export function phpArgValue(arg: Node | null): Node | null {
  if (!arg) return null;
  return arg.type === 'argument' ? (arg.namedChild(0) ?? null) : arg;
}

/**
 * All string values in an argument list: plain strings plus array elements
 * (`middleware(['auth', 'verified'])`).
 */
export function phpArgStrings(argsNode: Node | null, source: string): string[] {
  if (!argsNode) return [];
  const out: string[] = [];
  const collect = (n: Node): void => {
    if (n.type === 'string' || n.type === 'encapsed_string') {
      const s = phpStringLiteral(n, source);
      if (s) out.push(s);
      return;
    }
    for (let i = 0; i < n.namedChildCount; i++) collect(n.namedChild(i)!);
  };
  collect(argsNode);
  return out;
}
