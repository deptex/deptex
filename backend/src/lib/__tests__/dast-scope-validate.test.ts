// Regression gates for backend/src/lib/dast-scope-validate.ts.
//
// Pre-2.1a-hardening, only `regex_pattern_unsafe` and `sensitive_header_rejected`
// were exercised through dast-routes.test.ts happy-path assertions. The
// branches below were all silently uncovered (per the v2.1a critical review):
//   * include/exclude_patterns array caps
//   * header_rules array cap
//   * invalid_scope_shape on every malformed-input branch
//   * header_rules.scope enum check (drift from "all"/"requests"/"responses")
//   * regex_pattern_too_long
//   * safe-regex2 catches the canonical ReDoS shapes that the old static
//     heuristic let through

import { validateScopeConfig } from '../dast-scope-validate';

// ---------------------------------------------------------------------------
// Shape errors
// ---------------------------------------------------------------------------

describe('validateScopeConfig — shape errors', () => {
  it('rejects null / undefined', () => {
    const r = validateScopeConfig(null);
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('invalid_scope_shape');
  });

  it('rejects arrays at the top level', () => {
    const r = validateScopeConfig([]);
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('invalid_scope_shape');
  });

  it('rejects include_patterns when not a string array', () => {
    const r = validateScopeConfig({ include_patterns: [1, 2, 3] });
    expect(r.ok).toBe(false);
    if (r.ok === false) {
      expect(r.error.error_code).toBe('invalid_scope_shape');
      expect(r.error.detail).toMatch(/include_patterns must be string/);
    }
  });

  it('rejects exclude_patterns when not a string array', () => {
    const r = validateScopeConfig({ exclude_patterns: 'not-an-array' });
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('invalid_scope_shape');
  });

  it('rejects header_rules when not an array', () => {
    const r = validateScopeConfig({ header_rules: { name: 'X', value: 'y' } });
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('invalid_scope_shape');
  });

  it('rejects a header_rule entry with missing name/value', () => {
    const r = validateScopeConfig({ header_rules: [{ name: 'X' }] });
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('invalid_scope_shape');
  });

  it('rejects a header_rule with an unknown scope value', () => {
    const r = validateScopeConfig({
      header_rules: [{ name: 'X-Trace', value: 'abc', scope: 'all-of-it' }],
    });
    expect(r.ok).toBe(false);
    if (r.ok === false) {
      expect(r.error.error_code).toBe('invalid_scope_shape');
      expect(r.error.detail).toMatch(/scope/);
    }
  });
});

// ---------------------------------------------------------------------------
// Array element caps
// ---------------------------------------------------------------------------

describe('validateScopeConfig — element-count caps', () => {
  it('rejects include_patterns > 32 entries', () => {
    const r = validateScopeConfig({
      include_patterns: Array.from({ length: 33 }, (_, i) => `^/path-${i}.*$`),
    });
    expect(r.ok).toBe(false);
    if (r.ok === false) {
      expect(r.error.error_code).toBe('invalid_scope_shape');
      expect(r.error.detail).toMatch(/include_patterns exceeds 32/);
    }
  });

  it('accepts exactly 32 include_patterns', () => {
    const r = validateScopeConfig({
      include_patterns: Array.from({ length: 32 }, (_, i) => `^/path-${i}.*$`),
    });
    expect(r.ok).toBe(true);
  });

  it('rejects exclude_patterns > 32 entries', () => {
    const r = validateScopeConfig({
      exclude_patterns: Array.from({ length: 33 }, (_, i) => `^/x-${i}$`),
    });
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.detail).toMatch(/exclude_patterns exceeds 32/);
  });

  it('rejects header_rules > 16 entries', () => {
    const r = validateScopeConfig({
      header_rules: Array.from({ length: 17 }, (_, i) => ({
        name: `X-Header-${i}`,
        value: `v${i}`,
      })),
    });
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.detail).toMatch(/header_rules exceeds 16/);
  });
});

// ---------------------------------------------------------------------------
// Pattern length cap
// ---------------------------------------------------------------------------

describe('validateScopeConfig — pattern length cap', () => {
  it('rejects a pattern longer than 256 chars', () => {
    const r = validateScopeConfig({ include_patterns: ['a'.repeat(257)] });
    expect(r.ok).toBe(false);
    if (r.ok === false) {
      expect(r.error.error_code).toBe('regex_pattern_too_long');
      expect(r.error.detail).toMatch(/256/);
    }
  });

  it('accepts a pattern exactly at the 256-char cap', () => {
    const r = validateScopeConfig({ include_patterns: ['a'.repeat(256)] });
    expect(r.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// safe-regex2 catches the ReDoS shapes the old heuristic missed
// ---------------------------------------------------------------------------

describe('validateScopeConfig — safe-regex2 catches ReDoS shapes', () => {
  it("rejects (a+)+ (canonical nested-quantifier)", () => {
    const r = validateScopeConfig({ include_patterns: ['(a+)+b'] });
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('regex_pattern_unsafe');
  });

  it('rejects (.+a){50}b (repeated-group; the old heuristic let this through)', () => {
    const r = validateScopeConfig({ include_patterns: ['(.+a){50}b'] });
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('regex_pattern_unsafe');
  });

  it('rejects (a*)+b (nested-quantifier; the old heuristic let *-then-+ through)', () => {
    const r = validateScopeConfig({ include_patterns: ['(a*)+b'] });
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('regex_pattern_unsafe');
  });

  it('rejects an invalid regex (compile failure)', () => {
    const r = validateScopeConfig({ include_patterns: ['[unclosed'] });
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('regex_pattern_unsafe');
  });

  it('accepts a benign pattern', () => {
    const r = validateScopeConfig({
      include_patterns: ['^https://app\\.example\\.com/.*$'],
    });
    expect(r.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// header_rules — sensitive name list
// ---------------------------------------------------------------------------

describe('validateScopeConfig — sensitive header rejection', () => {
  it.each(['Authorization', 'authorization', 'Cookie', 'X-Api-Key', 'X-Auth-Token', 'X-CSRF-Token'])(
    'rejects sensitive header name %s',
    (name) => {
      const r = validateScopeConfig({ header_rules: [{ name, value: 'x' }] });
      expect(r.ok).toBe(false);
      if (r.ok === false) {
        expect(r.error.error_code).toBe('sensitive_header_rejected');
        if ('header_name' in r.error) {
          expect(r.error.header_name).toBe(name);
        }
      }
    },
  );

  it.each(['X-Tenant-Token', 'X-Refresh-Secret', 'My-Password-Header', 'X-API-Key-Custom'])(
    'rejects header name containing token/secret/password/key: %s',
    (name) => {
      const r = validateScopeConfig({ header_rules: [{ name, value: 'x' }] });
      expect(r.ok).toBe(false);
      if (r.ok === false) expect(r.error.error_code).toBe('sensitive_header_rejected');
    },
  );

  it('accepts non-sensitive headers (X-Trace-Id, X-Request-Id)', () => {
    const r = validateScopeConfig({
      header_rules: [
        { name: 'X-Trace-Id', value: 'trace-1' },
        { name: 'X-Request-Id', value: 'req-1', scope: 'requests' },
      ],
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.header_rules).toHaveLength(2);
      expect(r.value.header_rules?.[0].scope).toBe('all'); // default
      expect(r.value.header_rules?.[1].scope).toBe('requests');
    }
  });
});

// ---------------------------------------------------------------------------
// Happy path — empty + populated config round-trips cleanly
// ---------------------------------------------------------------------------

describe('validateScopeConfig — happy path', () => {
  it('accepts an empty object', () => {
    const r = validateScopeConfig({});
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value).toEqual({});
  });

  it('preserves all three sections for a fully populated config', () => {
    const cfg = {
      include_patterns: ['^/api/.*'],
      exclude_patterns: ['^/api/internal/.*'],
      header_rules: [{ name: 'X-Tenant', value: 'org-42', scope: 'all' }],
    };
    const r = validateScopeConfig(cfg);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.include_patterns).toEqual(cfg.include_patterns);
      expect(r.value.exclude_patterns).toEqual(cfg.exclude_patterns);
      expect(r.value.header_rules).toEqual(cfg.header_rules);
    }
  });
});
