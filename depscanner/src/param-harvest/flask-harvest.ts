// Deterministic request-param harvest for Flask view functions.
//
// Flask reads request data off the module-global `request` proxy:
//   request.args.get('q')      → query
//   request.args['q']          → query
//   request.headers.get('X')   → header
//   request.cookies.get('sid') → cookie
// `request.form` / `request.values` / `request.json` (body) are a fast-follow.
//
// Scoped to the view function node we're handed.

import type { Node } from 'web-tree-sitter';
import type { RequestParam, RequestParamIn } from './types';
import { canonicalizeParams, isPlausibleParamName } from './types';

const PY_RECEIVER_TO_IN: Record<string, RequestParamIn> = {
  args: 'query',
  headers: 'header',
  cookies: 'cookie',
};

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

// Python string literal: a `string` node wrapping `string_start`/`string_content`/`string_end`.
function pyStringValue(node: Node | null, source: string): string | null {
  if (!node || node.type !== 'string') return null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'string_content') return textOf(c, source);
  }
  const raw = textOf(node, source).replace(/^[a-zA-Z]*/, ''); // strip prefixes (r, b, f)
  if (raw.length >= 2) return raw.slice(1, -1);
  return null;
}

/** `request.args` / `request.headers` / `request.cookies` attribute → `in`. */
function receiverIn(attr: Node, source: string): RequestParamIn | null {
  if (attr.type !== 'attribute') return null;
  const base = attr.childForFieldName('object');
  const name = attr.childForFieldName('attribute');
  if (base?.type !== 'identifier' || textOf(base, source) !== 'request') return null;
  if (name?.type !== 'identifier') return null;
  return PY_RECEIVER_TO_IN[textOf(name, source)] ?? null;
}

export function harvestFlaskParams(funcNode: Node, source: string): RequestParam[] | null {
  const found: RequestParam[] = [];
  const push = (name: string | null, paramIn: RequestParamIn): void => {
    if (name && isPlausibleParamName(name)) {
      found.push({ name, in: paramIn, required: false, schema: { type: 'string' }, provenance: 'ast' });
    }
  };

  const visit = (node: Node): void => {
    if (node.type === 'call') {
      // request.args.get('q')
      const fn = node.childForFieldName('function');
      if (fn?.type === 'attribute') {
        const method = fn.childForFieldName('attribute');
        const recv = fn.childForFieldName('object');
        if (method?.type === 'identifier' && textOf(method, source) === 'get' && recv) {
          const paramIn = receiverIn(recv, source);
          if (paramIn) {
            const args = node.childForFieldName('arguments');
            const first = args?.namedChild(0) ?? null;
            if (first?.type === 'string') push(pyStringValue(first, source), paramIn);
          }
        }
      }
    } else if (node.type === 'subscript') {
      // request.args['q']
      const obj = node.childForFieldName('value');
      const index = node.childForFieldName('subscript');
      if (obj) {
        const paramIn = receiverIn(obj, source);
        if (paramIn && index?.type === 'string') push(pyStringValue(index, source), paramIn);
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) visit(node.namedChild(i)!);
  };

  visit(funcNode);
  return canonicalizeParams(found);
}
