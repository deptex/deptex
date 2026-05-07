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
