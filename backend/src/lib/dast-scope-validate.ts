// Validates `scope_config` payloads sent to PUT /dast/config.
//
// Rules (per plan §"Scope_config validation"):
//   - Header names matching `/^(Authorization|Cookie|X-Api-Key|X-Auth-Token|X-CSRF-Token)$/i`
//     OR `/(token|secret|password|key)/i` are rejected with
//     `error_code='sensitive_header_rejected'` (use credential panel instead).
//   - Each regex pattern length capped at 256 chars.
//   - Static check rejects nested unbounded quantifiers ((.+)+, (a*)*, etc.).
//   - Each pattern compile + 100ms-timeout match against synthetic 1000-char URL;
//     timeout → 422 'regex_pattern_too_expensive'.

import type { DastScopeConfig, DastScopeHeaderRule } from '../types/dast';

export type ScopeValidateError =
  | { error_code: 'invalid_scope_shape'; detail: string }
  | { error_code: 'sensitive_header_rejected'; detail: string; header_name?: string }
  | { error_code: 'regex_pattern_too_long'; detail: string; pattern?: string }
  | { error_code: 'regex_pattern_unsafe'; detail: string; pattern?: string }
  | { error_code: 'regex_pattern_too_expensive'; detail: string; pattern?: string };

export type ScopeValidateResult =
  | { ok: true; value: DastScopeConfig }
  | { ok: false; error: ScopeValidateError };

const SENSITIVE_HEADER_NAMES = /^(Authorization|Cookie|X-Api-Key|X-Auth-Token|X-CSRF-Token)$/i;
const SENSITIVE_HEADER_TOKENS = /(token|secret|password|key)/i;

const MAX_PATTERN_LEN = 256;
const COMPILE_TEST_INPUT = 'https://app.example.com/' + 'a'.repeat(1000);
const COMPILE_TEST_TIMEOUT_MS = 100;

// Heuristic: nested unbounded quantifiers are the canonical ReDoS source.
// Catches (a+)+, (.+)*, (\\w*)+, etc. Not exhaustive — `safe-regex2` would be
// stronger, but we don't want a runtime dep just for this. The runtime
// timeout test below provides the real safety net.
const RE_NESTED_QUANTIFIER = /\([^)]*[+*][^)]*\)[+*]/;

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

function validatePattern(pattern: string): ScopeValidateError | null {
  if (pattern.length > MAX_PATTERN_LEN) {
    return {
      error_code: 'regex_pattern_too_long',
      detail: `Pattern exceeds ${MAX_PATTERN_LEN} characters.`,
      pattern,
    };
  }
  if (RE_NESTED_QUANTIFIER.test(pattern)) {
    return {
      error_code: 'regex_pattern_unsafe',
      detail: 'Nested unbounded quantifiers (e.g. (.+)+) cause exponential backtracking.',
      pattern,
    };
  }
  let re: RegExp;
  try {
    re = new RegExp(pattern);
  } catch (e: any) {
    return {
      error_code: 'regex_pattern_unsafe',
      detail: `Pattern failed to compile: ${e?.message ?? 'unknown'}`,
      pattern,
    };
  }
  // Best-effort timeout test — Node has no native regex timeout, so we wrap
  // a single match call with `Date.now()` deadline checks. A truly malicious
  // pattern can blow past this on the first .test() call, but in practice
  // most ReDoS inputs require many backtracking steps that we can interrupt
  // by checking elapsed time — except we can't, because regex execution is
  // single-shot. So this is more of a "did the call return quickly under
  // benign input" smoke check than a hard guarantee.
  const t0 = Date.now();
  try {
    re.test(COMPILE_TEST_INPUT);
  } catch {
    // shouldn't happen — compile already validated
  }
  const elapsed = Date.now() - t0;
  if (elapsed > COMPILE_TEST_TIMEOUT_MS) {
    return {
      error_code: 'regex_pattern_too_expensive',
      detail: `Pattern took ${elapsed}ms on a 1000-char synthetic input (cap: ${COMPILE_TEST_TIMEOUT_MS}ms).`,
      pattern,
    };
  }
  return null;
}

export function validateScopeConfig(input: unknown): ScopeValidateResult {
  if (input == null || typeof input !== 'object' || Array.isArray(input)) {
    return {
      ok: false,
      error: { error_code: 'invalid_scope_shape', detail: 'scope_config must be an object.' },
    };
  }
  const raw = input as Record<string, unknown>;
  const out: DastScopeConfig = {};

  if ('include_patterns' in raw) {
    if (!isStringArray(raw.include_patterns)) {
      return {
        ok: false,
        error: { error_code: 'invalid_scope_shape', detail: 'include_patterns must be string[]' },
      };
    }
    for (const p of raw.include_patterns) {
      const err = validatePattern(p);
      if (err) return { ok: false, error: err };
    }
    out.include_patterns = raw.include_patterns;
  }

  if ('exclude_patterns' in raw) {
    if (!isStringArray(raw.exclude_patterns)) {
      return {
        ok: false,
        error: { error_code: 'invalid_scope_shape', detail: 'exclude_patterns must be string[]' },
      };
    }
    for (const p of raw.exclude_patterns) {
      const err = validatePattern(p);
      if (err) return { ok: false, error: err };
    }
    out.exclude_patterns = raw.exclude_patterns;
  }

  if ('header_rules' in raw) {
    if (!Array.isArray(raw.header_rules)) {
      return {
        ok: false,
        error: { error_code: 'invalid_scope_shape', detail: 'header_rules must be an array' },
      };
    }
    const rules: DastScopeHeaderRule[] = [];
    for (const r of raw.header_rules) {
      if (
        r == null ||
        typeof r !== 'object' ||
        typeof (r as any).name !== 'string' ||
        typeof (r as any).value !== 'string'
      ) {
        return {
          ok: false,
          error: {
            error_code: 'invalid_scope_shape',
            detail: 'each header_rule needs { name: string, value: string, scope: "all"|"requests"|"responses" }',
          },
        };
      }
      const name = (r as any).name as string;
      const value = (r as any).value as string;
      const scope = ((r as any).scope as string) || 'all';
      if (scope !== 'all' && scope !== 'requests' && scope !== 'responses') {
        return {
          ok: false,
          error: {
            error_code: 'invalid_scope_shape',
            detail: `header_rule.scope must be "all"|"requests"|"responses", got "${scope}"`,
          },
        };
      }
      if (SENSITIVE_HEADER_NAMES.test(name) || SENSITIVE_HEADER_TOKENS.test(name)) {
        return {
          ok: false,
          error: {
            error_code: 'sensitive_header_rejected',
            detail: 'Use the credential panel to manage Authorization/Cookie/secret headers.',
            header_name: name,
          },
        };
      }
      rules.push({ name, value, scope: scope as DastScopeHeaderRule['scope'] });
    }
    out.header_rules = rules;
  }

  return { ok: true, value: out };
}
