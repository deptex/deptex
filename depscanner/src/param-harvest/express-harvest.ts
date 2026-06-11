// Deterministic request-param harvest for Express/Connect-style handlers.
//
// Given an inline route handler node (arrow / function), enumerate the
// query/header/cookie parameters the handler reads — `req.query.id`,
// `req.query['id']`, `const { id } = req.query`, `req.get('X')`,
// `req.cookies.sid`. Path params (`req.params.*`) and body (`req.body.*`) are
// intentionally NOT harvested here: path params come from the route string
// (dast/openapi-path-translate.ts); body fields are a fast-follow.
//
// Scoped strictly to the handler subtree we're handed, so params never leak
// across routes declared in the same file. Named-function handlers (an
// identifier referencing a function defined elsewhere) yield nothing — their
// body isn't in this node.

import type { Node } from 'web-tree-sitter';
import type { RequestParam, RequestParamIn } from './types';
import { canonicalizeParams, isPlausibleParamName } from './types';

const RECEIVER_TO_IN: Record<string, RequestParamIn> = {
  query: 'query',
  headers: 'header',
  cookies: 'cookie',
};
// `req.get('X')` / `req.header('X')` read a request header.
const HEADER_GETTER_METHODS = new Set(['get', 'header']);

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

function stringLiteralValue(node: Node | null, source: string): string | null {
  if (!node || node.type !== 'string') return null;
  const frag = node.namedChild(0);
  if (frag && frag.type === 'string_fragment') return textOf(frag, source);
  const raw = textOf(node, source);
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    return raw.slice(1, -1);
  }
  return null;
}

/** First formal parameter name of an inline handler, or null if it isn't a
 * plain identifier (destructured / absent). */
function requestParamName(handler: Node, source: string): string | null {
  const single = handler.childForFieldName('parameter'); // `req => ...`
  if (single?.type === 'identifier') return textOf(single, source);
  const params = handler.childForFieldName('parameters');
  if (!params) return null;
  const first = params.namedChild(0);
  if (!first) return null;
  if (first.type === 'identifier') return textOf(first, source);
  return null;
}

/** `req.query` / `req.headers` / `req.cookies` member → its OpenAPI `in`, when
 * the base identifier is one of the recognized request receivers. */
function receiverIn(member: Node, source: string, receivers: ReadonlySet<string>): RequestParamIn | null {
  if (member.type !== 'member_expression') return null;
  const base = member.childForFieldName('object');
  const prop = member.childForFieldName('property');
  if (base?.type !== 'identifier' || prop?.type !== 'property_identifier') return null;
  if (!receivers.has(textOf(base, source))) return null;
  return RECEIVER_TO_IN[textOf(prop, source)] ?? null;
}

export function harvestExpressParams(
  handler: Node | null,
  source: string,
): RequestParam[] | null {
  if (
    !handler ||
    (handler.type !== 'arrow_function' &&
      handler.type !== 'function_expression' &&
      handler.type !== 'function_declaration')
  ) {
    return null;
  }

  const named = requestParamName(handler, source);
  // When the first param isn't a plain identifier (destructured / missing),
  // fall back to the conventional express receiver names so we still catch the
  // common case.
  const receivers: ReadonlySet<string> = named ? new Set([named]) : new Set(['req', 'request']);

  const found: RequestParam[] = [];
  const push = (name: string | null, paramIn: RequestParamIn): void => {
    if (name && isPlausibleParamName(name)) {
      found.push({ name, in: paramIn, required: false, schema: { type: 'string' }, provenance: 'ast' });
    }
  };

  const visit = (node: Node): void => {
    if (node.type === 'member_expression') {
      // req.query.id
      const obj = node.childForFieldName('object');
      const prop = node.childForFieldName('property');
      if (obj?.type === 'member_expression' && prop?.type === 'property_identifier') {
        const paramIn = receiverIn(obj, source, receivers);
        if (paramIn) push(textOf(prop, source), paramIn);
      }
    } else if (node.type === 'subscript_expression') {
      // req.query['id']
      const obj = node.childForFieldName('object');
      const index = node.childForFieldName('index');
      if (obj?.type === 'member_expression' && index?.type === 'string') {
        const paramIn = receiverIn(obj, source, receivers);
        if (paramIn) push(stringLiteralValue(index, source), paramIn);
      }
    } else if (node.type === 'call_expression') {
      // req.get('X') / req.header('X')
      const fn = node.childForFieldName('function');
      if (fn?.type === 'member_expression') {
        const base = fn.childForFieldName('object');
        const method = fn.childForFieldName('property');
        if (
          base?.type === 'identifier' &&
          receivers.has(textOf(base, source)) &&
          method?.type === 'property_identifier' &&
          HEADER_GETTER_METHODS.has(textOf(method, source))
        ) {
          const args = node.childForFieldName('arguments');
          const first = args?.namedChild(0) ?? null;
          if (first?.type === 'string') push(stringLiteralValue(first, source), 'header');
        }
      }
    } else if (node.type === 'variable_declarator') {
      // const { id, q } = req.query
      const value = node.childForFieldName('value');
      const name = node.childForFieldName('name');
      if (value?.type === 'member_expression' && name?.type === 'object_pattern') {
        const paramIn = receiverIn(value, source, receivers);
        if (paramIn) {
          for (let i = 0; i < name.namedChildCount; i++) {
            const el = name.namedChild(i)!;
            if (el.type === 'shorthand_property_identifier_pattern') {
              push(textOf(el, source), paramIn);
            } else if (el.type === 'pair_pattern') {
              const key = el.childForFieldName('key');
              if (key) push(textOf(key, source), paramIn);
            }
          }
        }
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) visit(node.namedChild(i)!);
  };

  visit(handler);
  return canonicalizeParams(found);
}
