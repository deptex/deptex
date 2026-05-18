/**
 * Pre-flight pattern-syntax validator for FrameworkSpec sources/sinks/sanitizers.
 *
 * Background: Phase 5's Semgrep grammar gate (`semgrep --validate`) was retired
 * in M2b when the engine moved to a hand-rolled string DSL. The replacement
 * engine compile-validation never landed, so a malformed pattern like
 * `_.template((*` (unbalanced parens) passed zod (string + min(1)) and the
 * engine's hand-rolled validateSpec (also string-only) but silently no-op'd
 * inside `matchesCallPattern` at flow-walk time -- every CVE candidate with a
 * busted pattern reported `schema_pass:true` while emitting zero flows.
 *
 * Goal of this validator: catch the obviously-malformed patterns the audit
 * called out (unbalanced parens, control chars, embedded newlines, untrimmed
 * whitespace, missing callee text) WITHOUT rejecting any of the 1,000+
 * patterns shipped in `framework-models/*.yaml` -- those use richer shapes
 * (`req.uri().path()`, `new ProcessBuilder`, `params[*]`, `[FromBody]`,
 * `node-fetch(*)`, `Query.0.*`, `Kernel.\`(*)`) that the engine matchers
 * tolerate or rely on through other code paths. We deliberately stay
 * structural rather than grammatical -- the engine's true grammar is fluid
 * across language modules, and tightening it here would regress bundled specs.
 *
 * The audit's worst case (`_.template((*` -> two open parens, zero close)
 * is what this gate catches; Gate 2 (fixture round-trip) catches the rest.
 */

export interface PatternSyntaxOk { ok: true; }
export interface PatternSyntaxFail { ok: false; reason: string; }
export type PatternSyntaxResult = PatternSyntaxOk | PatternSyntaxFail;

/**
 * Returns ok=true if the pattern is structurally well-formed (no junk
 * characters, balanced delimiters, has a callee identifier somewhere).
 * On failure returns a short reason string suitable for `validation_log.errors`.
 */
export function validatePatternSyntax(pattern: string): PatternSyntaxResult {
  if (typeof pattern !== 'string') return { ok: false, reason: 'not a string' };
  if (pattern.length === 0) return { ok: false, reason: 'empty pattern' };

  // Whole-line whitespace handling. Trim mismatch -> human typo. Embedded
  // newline / tab / CR are uniformly rejected -- tree-sitter callee text never
  // contains them, so a pattern that does silently no-ops.
  if (pattern !== pattern.trim()) return { ok: false, reason: 'leading or trailing whitespace' };
  if (/[\n\r\t]/.test(pattern)) return { ok: false, reason: 'embedded newline or tab in pattern' };

  // Reject ASCII control characters (codepoints 0x00-0x1F + 0x7F).
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(pattern)) {
    return { ok: false, reason: 'control characters in pattern' };
  }

  // Balanced delimiters. The audit's flagship example `_.template((*` is two
  // open parens, zero close -- exactly the case this catches. We treat each
  // bracket family as independent: `(` paired with `)`, `[` with `]`,
  // `{` with `}`. A pattern that closes more than it opens at any prefix
  // is also rejected (e.g. `pkg.foo)(*)` -> running depth -1 at offset 7).
  const balance = checkBalancedDelimiters(pattern);
  if (!balance.ok) return balance;

  // Must contain at least one identifier-ish character so a pattern of pure
  // punctuation (`*`, `(*)`, `..`, `**`) is rejected. Backtick is allowed
  // because Ruby specs use a literal `` ` `` as Kernel's backtick-shell-out
  // method name. The engine and the schema's broad-pattern guard each catch
  // some of these, but cheap to belt-and-brace here.
  if (!/[A-Za-z_`]/.test(pattern)) {
    return { ok: false, reason: 'pattern has no identifier characters' };
  }

  return { ok: true };
}

interface DelimResult { ok: true; }
interface DelimFail { ok: false; reason: string; }

function checkBalancedDelimiters(s: string): DelimResult | DelimFail {
  const stack: string[] = [];
  const closeFor: Record<string, string> = { '(': ')', '[': ']', '{': '}' };
  const openSet = new Set(['(', '[', '{']);
  const closeSet = new Set([')', ']', '}']);
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (openSet.has(c)) {
      stack.push(closeFor[c]);
    } else if (closeSet.has(c)) {
      const expected = stack.pop();
      if (expected === undefined) {
        return { ok: false, reason: `unmatched closing "${c}" at offset ${i}` };
      }
      if (expected !== c) {
        return { ok: false, reason: `mismatched delimiter -- expected "${expected}" but found "${c}" at offset ${i}` };
      }
    }
  }
  if (stack.length > 0) {
    return { ok: false, reason: `unbalanced delimiters -- ${stack.length} opener(s) never closed` };
  }
  return { ok: true };
}
