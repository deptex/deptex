import type { Node, Tree } from 'web-tree-sitter';
import type { ImportBinding } from '../../tree-sitter-extractor/languages/types';
import type { EntryPointClassification, HttpMethod } from '../types';

export function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

export function rubyStringLiteral(node: Node | null, source: string): string | null {
  if (!node || node.type !== 'string') return null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'string_content') return textOf(c, source);
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

export const RUBY_HTTP_METHODS: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
};

export const RUBY_AUTH_GEMS: ReadonlyArray<{ gem: string; mechanism: string }> = [
  { gem: 'devise', mechanism: 'devise' },
  { gem: 'pundit', mechanism: 'pundit' },
  { gem: 'cancancan', mechanism: 'cancan' },
  { gem: 'warden', mechanism: 'warden' },
  { gem: 'jwt', mechanism: 'bearer_jwt' },
];

export function detectRubyAuthMechanism(imports: readonly ImportBinding[]): string | null {
  for (const imp of imports) {
    const head = imp.source.split('/')[0];
    const hit = RUBY_AUTH_GEMS.find((a) => a.gem === head);
    if (hit) return hit.mechanism;
  }
  return null;
}

export function classifyFromAuth(auth: string | null): EntryPointClassification {
  return auth ? 'AUTH_INTERNAL' : 'PUBLIC_UNAUTH';
}
