/**
 * Extract / wrap helpers for code stored in body-only form.
 *
 * Background: legacy policy editors stored full `function name(...) { body }`
 * declarations. The flow-code editor stores body-only (cleaner UX, no risk of
 * users renaming the function). This module bridges the two formats so flows
 * saved in either shape load the same way.
 *
 * Implementation note: an earlier regex-based version misextracted bodies that
 * contained the substring `function name(` inside string literals or comments.
 * acorn parses real JavaScript, so it sees through that.
 */

import { Parser } from 'acorn';

interface PositionedNode {
  type: string;
  start: number;
  end: number;
  id?: { name?: string };
  body?: { start: number; end: number };
  declarations?: Array<{ id?: { name?: string }; init?: { type: string; body?: { start: number; end: number } } }>;
}

/**
 * Find the body of a top-level `function <fnName>(...) { ... }` declaration
 * in `code`. Returns null if not found or if the code has a syntax error.
 *
 * Also matches `const fnName = function(...) { ... }` and the `async` variants
 * — covers what users actually write.
 */
export function extractFunctionBody(code: string, fnName: string): string | null {
  if (!code || !fnName) return null;
  let ast: { body: PositionedNode[] };
  try {
    ast = Parser.parse(code, { ecmaVersion: 'latest', sourceType: 'script' }) as unknown as {
      body: PositionedNode[];
    };
  } catch {
    return null;
  }

  for (const node of ast.body) {
    if (node.type === 'FunctionDeclaration' && node.id?.name === fnName && node.body) {
      // node.body is a BlockStatement with curly braces — strip them.
      const blockSrc = code.slice(node.body.start, node.body.end);
      return stripBraces(blockSrc).trim();
    }
    if (node.type === 'VariableDeclaration' && node.declarations) {
      for (const d of node.declarations) {
        if (d.id?.name === fnName && d.init?.body) {
          const blockSrc = code.slice(d.init.body.start, d.init.body.end);
          return stripBraces(blockSrc).trim();
        }
      }
    }
  }
  return null;
}

function stripBraces(blockSrc: string): string {
  // Block statement source includes outer `{ ... }`. Slice them off.
  const trimmed = blockSrc.trim();
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

/**
 * Wrap a body string as `function <fnName>(<paramName>) { <body> }` with
 * 2-space indentation on body lines.
 */
export function wrapBody(body: string, fnName: string, paramName: string): string {
  const indented = body.trim().split('\n').map((l) => (l.length > 0 ? `  ${l}` : '')).join('\n');
  return `function ${fnName}(${paramName}) {\n${indented}\n}`;
}

/**
 * Normalize stored code into body-only form. Accepts either form:
 *   - body-only `return true;`
 *   - full declaration `function evaluate(context) { return true; }`
 * Returns the body. If parsing fails, returns the original string unchanged
 * (the user keeps editing what they typed, even if invalid).
 */
export function toBody(stored: string, fnName: string): string {
  if (!stored) return '';
  const extracted = extractFunctionBody(stored, fnName);
  return extracted !== null ? extracted : stored;
}
