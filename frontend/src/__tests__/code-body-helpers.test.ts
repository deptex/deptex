/**
 * AST-based body extraction must survive adversarial inputs (function markers
 * inside string literals, regex literals, comments) that the older regex
 * version mishandled.
 */

import { describe, test, expect } from 'vitest';
import { extractFunctionBody, wrapBody, toBody } from '../lib/code-body-helpers';

describe('extractFunctionBody', () => {
  test('extracts a simple function body', () => {
    const code = `function evaluate(context) { return true; }`;
    expect(extractFunctionBody(code, 'evaluate')).toBe('return true;');
  });

  test('preserves multi-line body and inner indentation', () => {
    const code = `function evaluate(context) {
  const sev = context.vulnerability.severity;
  return sev === 'high';
}`;
    const body = extractFunctionBody(code, 'evaluate');
    expect(body).toContain("const sev");
    expect(body).toContain("return sev === 'high';");
  });

  test('returns null for missing function', () => {
    expect(extractFunctionBody('function other() {}', 'evaluate')).toBeNull();
  });

  test('returns null on syntax error', () => {
    expect(extractFunctionBody('function evaluate(', 'evaluate')).toBeNull();
  });

  test('does not misextract when body contains "function" inside a string literal', () => {
    const code = `function evaluate(context) {
  return 'function nested() { return true; }';
}`;
    const body = extractFunctionBody(code, 'evaluate');
    // The string containing the fake function declaration must round-trip intact.
    expect(body).toContain(`'function nested() { return true; }'`);
  });

  test('does not misextract when body contains regex literal with curly braces', () => {
    const code = `function evaluate(context) {
  return /\\{[^}]*\\}/.test(context.dependency.name);
}`;
    const body = extractFunctionBody(code, 'evaluate');
    expect(body).toContain('/\\{[^}]*\\}/');
  });

  test('does not misextract when body contains comment with "function" marker', () => {
    const code = `function evaluate(context) {
  // function fakeOther() { return false; }
  return true;
}`;
    const body = extractFunctionBody(code, 'evaluate');
    expect(body).toContain('// function fakeOther()');
    expect(body).toContain('return true;');
  });

  test('handles const fnName = function(...) { ... }', () => {
    const code = `const evaluate = function(context) { return false; };`;
    expect(extractFunctionBody(code, 'evaluate')).toBe('return false;');
  });
});

describe('wrapBody', () => {
  test('wraps body with 2-space indent', () => {
    const wrapped = wrapBody('return true;', 'evaluate', 'context');
    expect(wrapped).toBe(`function evaluate(context) {\n  return true;\n}`);
  });

  test('preserves blank lines as empty', () => {
    const body = 'return\n\n  true;';
    const wrapped = wrapBody(body, 'evaluate', 'context');
    expect(wrapped).toContain('\n\n');
  });
});

describe('toBody round-trip', () => {
  test('body-only stored value comes through unchanged', () => {
    expect(toBody('return true;', 'evaluate')).toBe('return true;');
  });

  test('full declaration is unwrapped to body', () => {
    expect(toBody('function evaluate(c) { return true; }', 'evaluate')).toBe('return true;');
  });

  test('empty input → empty body', () => {
    expect(toBody('', 'evaluate')).toBe('');
  });
});
