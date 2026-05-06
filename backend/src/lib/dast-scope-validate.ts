// Validates `scope_config` payloads sent to PUT /dast/config.
//
// Rules (per plan §"Scope_config validation"):
//   - Header names matching `/^(Authorization|Cookie|X-Api-Key|X-Auth-Token|X-CSRF-Token)$/i`
//     OR `/(token|secret|password|key)/i` are rejected with
//     `error_code='sensitive_header_rejected'` (use credential panel instead).
//   - Each regex pattern length capped at 256 chars.
//   - safe-regex2 rejects ReDoS-prone patterns ((a+)+, (.+a){50}b, polynomial
//     backtracking, alternation overlap). Replaces the pre-2.1a heuristic that
//     only caught `(\\w+[+*])` shapes.
//   - Array caps: 32 include / 32 exclude / 16 header_rules. Bounds the
//     iterative-validation cost even if individual patterns are benign.

import safeRegex from 'safe-regex2';

import type { DastScopeConfig, DastScopeHeaderRule } from '../types/dast';

export type ScopeValidateError =
  | { error_code: 'invalid_scope_shape'; detail: string }
  | { error_code: 'sensitive_header_rejected'; detail: string; header_name?: string }
  | { error_code: 'regex_pattern_too_long'; detail: string; pattern?: string }
  | { error_code: 'regex_pattern_unsafe'; detail: string; pattern?: string };

export type ScopeValidateResult =
  | { ok: true; value: DastScopeConfig }
  | { ok: false; error: ScopeValidateError };

const SENSITIVE_HEADER_NAMES = /^(Authorization|Cookie|X-Api-Key|X-Auth-Token|X-CSRF-Token)$/i;
const SENSITIVE_HEADER_TOKENS = /(token|secret|password|key)/i;

const MAX_PATTERN_LEN = 256;
const MAX_INCLUDE_PATTERNS = 32;
const MAX_EXCLUDE_PATTERNS = 32;
const MAX_HEADER_RULES = 16;

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
  try {
    new RegExp(pattern);
  } catch (e: any) {
    // eslint-disable-next-line no-console
    console.error('[dast-scope-validate] regex compile failed:', e?.message ?? e);
    return {
      error_code: 'regex_pattern_unsafe',
      detail: 'Pattern failed to compile.',
      pattern,
    };
  }
  // safe-regex2 rejects every ReDoS shape we care about: nested unbounded
  // quantifiers, repeated-group backtracking ((.+a){50}b), polynomial cases
  // (a*a*a*...b), alternation-overlap ((a|a)*b). The pre-2.1a heuristic only
  // matched `(\\w*[+*])` shapes and let real attack patterns through (caught
  // by the v2.1a critical review).
  if (!safeRegex(pattern)) {
    return {
      error_code: 'regex_pattern_unsafe',
      detail: 'Pattern is unsafe — potential catastrophic backtracking (ReDoS).',
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
    if (raw.include_patterns.length > MAX_INCLUDE_PATTERNS) {
      return {
        ok: false,
        error: {
          error_code: 'invalid_scope_shape',
          detail: `include_patterns exceeds ${MAX_INCLUDE_PATTERNS} entries`,
        },
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
    if (raw.exclude_patterns.length > MAX_EXCLUDE_PATTERNS) {
      return {
        ok: false,
        error: {
          error_code: 'invalid_scope_shape',
          detail: `exclude_patterns exceeds ${MAX_EXCLUDE_PATTERNS} entries`,
        },
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
    if (raw.header_rules.length > MAX_HEADER_RULES) {
      return {
        ok: false,
        error: {
          error_code: 'invalid_scope_shape',
          detail: `header_rules exceeds ${MAX_HEADER_RULES} entries`,
        },
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
