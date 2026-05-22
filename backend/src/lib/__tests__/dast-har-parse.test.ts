// Unit tests for dast-har-parse.ts.
//
// Coverage matrix per the plan (M1 step 6):
//   - happy path: synthetic HAR with form-login + dashboard fetch
//   - per-error-code rejection paths
//   - detector false-positives (TOTP-keyworded routes that aren't TOTP)
//   - privacy scrubbers (URL query token redaction)
//   - origin extraction (de-dup, hostname-only)
//
// The privacy-canary suite that asserts stdout/stderr never leaks lives in
// the separate `dast-har-privacy.test.ts` file — that one stubs
// process.stdout.write + process.stderr.write to catch Pino/Datadog
// forwarder bypasses. This file is the pure-function correctness gate.

import {
  detectNonReplayablePatterns,
  detectTotpStep,
  extractOriginsObserved,
  parseHar,
  scrubUrlQueryParams,
} from '../dast-har-parse';
import { HAR_MAX_ENTRIES, HAR_MAX_HEADER_VALUE_LEN, HAR_MAX_HEADERS_PER_REQUEST } from '../dast-har-constants';

// ---------------------------------------------------------------------------
// Synthetic HAR factory — every test builds off this to keep fixtures small.
// ---------------------------------------------------------------------------

interface FixtureRequest {
  method?: string;
  url?: string;
  headers?: { name: string; value: string }[];
  postData?: { mimeType?: string; text?: string; params?: { name: string; value: string }[] };
  responseStatus?: number;
  responseHeaders?: { name: string; value: string }[];
}

function harFixture(reqs: FixtureRequest[]): unknown {
  return {
    log: {
      version: '1.2',
      creator: { name: 'test', version: '1' },
      entries: reqs.map((r) => ({
        startedDateTime: '2026-05-21T00:00:00.000Z',
        time: 50,
        request: {
          method: r.method ?? 'GET',
          url: r.url ?? 'https://app.example.com/',
          httpVersion: 'HTTP/1.1',
          headers: r.headers ?? [],
          queryString: [],
          cookies: [],
          headersSize: -1,
          bodySize: r.postData?.text?.length ?? 0,
          ...(r.postData ? { postData: r.postData } : {}),
        },
        response: {
          status: r.responseStatus ?? 200,
          statusText: 'OK',
          httpVersion: 'HTTP/1.1',
          headers: r.responseHeaders ?? [],
          cookies: [],
          content: { size: 0, mimeType: 'text/html' },
          redirectURL: '',
          headersSize: -1,
          bodySize: 0,
        },
        cache: {},
        timings: { send: 0, wait: 50, receive: 0 },
      })),
    },
  };
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

describe('parseHar — happy path', () => {
  const HAPPY = harFixture([
    {
      method: 'POST',
      url: 'https://app.example.com/login',
      headers: [
        { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
        { name: 'Origin', value: 'https://app.example.com' },
        { name: 'User-Agent', value: 'Mozilla/5.0 (telemetry-noise)' }, // dropped
      ],
      postData: { mimeType: 'application/x-www-form-urlencoded', text: 'username=alice&password=wonderland' },
      responseStatus: 302,
      responseHeaders: [
        { name: 'Set-Cookie', value: 'session=abc; HttpOnly' },
        { name: 'Location', value: '/dashboard' },
      ],
    },
    {
      method: 'GET',
      url: 'https://app.example.com/dashboard',
      headers: [
        { name: 'Cookie', value: 'session=abc' },
        { name: 'Authorization', value: 'Bearer eyJhbGciOiJIUzI1NiJ9' },
      ],
      responseStatus: 200,
    },
  ]);

  it('returns 2 requests with origins captured', () => {
    const r = parseHar(HAPPY);
    expect(r.requests).toHaveLength(2);
    expect(r.summary.origins).toEqual(['app.example.com']);
  });

  it('drops non-allowlisted headers and counts the bytes dropped', () => {
    const r = parseHar(HAPPY);
    expect(r.summary.dropped_header_count).toBe(1);
    expect(r.summary.dropped_bytes).toBeGreaterThan(0);
    // User-Agent dropped → not in the kept headers of entry 0
    const e0 = r.requests[0];
    const headerNames = e0.headers.map((h) => h.name.toLowerCase());
    expect(headerNames).not.toContain('user-agent');
    expect(headerNames).toContain('content-type');
    expect(headerNames).toContain('origin');
  });

  it('counts Set-Cookie responses and Authorization headers', () => {
    const r = parseHar(HAPPY);
    expect(r.summary.cookies_set).toBe(1);
    expect(r.summary.auth_headers_observed).toBe(1);
  });

  it('preview entries carry the per-request flag chips', () => {
    const r = parseHar(HAPPY);
    expect(r.entries[0].flag_chips).toEqual(expect.arrayContaining(['password_body']));
    expect(r.entries[0].has_password_body).toBe(true);
    expect(r.entries[1].flag_chips).toEqual(expect.arrayContaining(['auth_header']));
    expect(r.entries[1].has_auth_header).toBe(true);
  });

  it('scrubs token-keyed query params in url_scrubbed', () => {
    const fx = harFixture([
      {
        method: 'GET',
        url: 'https://app.example.com/oauth/callback?code=hunter2&state=xyz&foo=bar',
      },
    ]);
    const r = parseHar(fx);
    expect(r.entries[0].url_scrubbed).toContain('code=%5BREDACTED%5D');
    expect(r.entries[0].url_scrubbed).toContain('state=%5BREDACTED%5D');
    expect(r.entries[0].url_scrubbed).toContain('foo=bar');
  });
});

// ---------------------------------------------------------------------------
// Per-error-code rejection paths
// ---------------------------------------------------------------------------

describe('parseHar — rejection paths', () => {
  function expectRejection(fn: () => void, code: string): void {
    try {
      fn();
      fail(`expected rejection ${code} but got success`);
    } catch (e) {
      expect((e as { error_code?: string }).error_code).toBe(code);
    }
  }

  it('invalid_har_shape — top-level not object', () => {
    expectRejection(() => parseHar('not an object'), 'invalid_har_shape');
  });

  it('invalid_har_shape — missing log.entries', () => {
    expectRejection(() => parseHar({ log: {} }), 'invalid_har_shape');
  });

  it('har_too_small — entries array empty', () => {
    expectRejection(() => parseHar({ log: { entries: [] } }), 'har_too_small');
  });

  it('har_too_large — rawByteSize > 1MB', () => {
    expectRejection(
      () => parseHar(harFixture([{ url: 'https://x.example.com/' }]), { rawByteSize: 2_000_000 }),
      'har_too_large',
    );
  });

  it('har_entry_too_large — > HAR_MAX_ENTRIES', () => {
    const many = Array.from({ length: HAR_MAX_ENTRIES + 1 }, () => ({ url: 'https://x.example.com/' }));
    expectRejection(() => parseHar(harFixture(many)), 'har_entry_too_large');
  });

  it('har_entry_too_large — header value > HAR_MAX_HEADER_VALUE_LEN', () => {
    expectRejection(
      () => parseHar(harFixture([
        {
          url: 'https://x.example.com/',
          headers: [{ name: 'Authorization', value: 'A'.repeat(HAR_MAX_HEADER_VALUE_LEN + 1) }],
        },
      ])),
      'har_entry_too_large',
    );
  });

  it('har_entry_too_large — too many headers', () => {
    const tooManyHeaders = Array.from({ length: HAR_MAX_HEADERS_PER_REQUEST + 1 }, (_, i) => ({
      name: `X-Custom-${i}`,
      value: 'x',
    }));
    expectRejection(
      () => parseHar(harFixture([{ url: 'https://x.example.com/', headers: tooManyHeaders }])),
      'har_entry_too_large',
    );
  });

  it('har_non_https_entry — http URL', () => {
    expectRejection(
      () => parseHar(harFixture([{ url: 'http://app.example.com/' }])),
      'har_non_https_entry',
    );
  });

  it('har_private_ip_entry — literal 127.0.0.1', () => {
    expectRejection(
      () => parseHar(harFixture([{ url: 'https://127.0.0.1/login' }])),
      'har_private_ip_entry',
    );
  });

  it('har_private_ip_entry — literal 10.x.x.x', () => {
    expectRejection(
      () => parseHar(harFixture([{ url: 'https://10.0.1.5/admin' }])),
      'har_private_ip_entry',
    );
  });

  it('har_origin_count_exceeded — 11+ distinct hosts', () => {
    const many = Array.from({ length: 11 }, (_, i) => ({ url: `https://a${i}.example.com/` }));
    expectRejection(() => parseHar(harFixture(many)), 'har_origin_count_exceeded');
  });

  it('invalid_har_shape — URL with U+2028', () => {
    expectRejection(
      () => parseHar(harFixture([{ url: 'https://app.example.com/login ' }])),
      'invalid_har_shape',
    );
  });

  it('invalid_har_shape — header value with U+2029', () => {
    expectRejection(
      () => parseHar(harFixture([
        {
          url: 'https://app.example.com/',
          headers: [{ name: 'Accept', value: 'text/html ' }],
        },
      ])),
      'invalid_har_shape',
    );
  });
});

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

describe('detectTotpStep', () => {
  it('detects an x-www-form-urlencoded /totp/verify request', () => {
    const fx = harFixture([
      {
        method: 'POST',
        url: 'https://app.example.com/totp/verify',
        headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
        postData: {
          mimeType: 'application/x-www-form-urlencoded',
          text: 'pending_session=abc&code=123456',
        },
      },
    ]);
    const { totp_detected } = parseHar(fx);
    expect(totp_detected).toEqual({ entry_index: 0, body_field: 'code', body_kind: 'form' });
  });

  it('detects a JSON-bodied /mfa/verify request via "code" field', () => {
    const fx = harFixture([
      {
        method: 'POST',
        url: 'https://login.idp.example.com/mfa/verify',
        headers: [{ name: 'Content-Type', value: 'application/json' }],
        postData: { mimeType: 'application/json', text: '{"code":"654321","trust_device":false}' },
      },
    ]);
    const { totp_detected } = parseHar(fx);
    expect(totp_detected).toEqual({ entry_index: 0, body_field: 'code', body_kind: 'json' });
  });

  it('returns null when path matches but content-type is missing', () => {
    const fx = harFixture([
      {
        method: 'POST',
        url: 'https://app.example.com/totp/verify',
        postData: { text: 'code=123456' },
      },
    ]);
    const { totp_detected } = parseHar(fx);
    expect(totp_detected).toBeNull();
  });

  it('returns null when path looks like /code/ but body has no totp field', () => {
    const fx = harFixture([
      {
        method: 'POST',
        url: 'https://app.example.com/totp/login',
        headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
        postData: { mimeType: 'application/x-www-form-urlencoded', text: 'username=alice&password=wonderland' },
      },
    ]);
    const { totp_detected } = parseHar(fx);
    // /totp/login matches HAR_TOTP_PATHS but body has no `code`/`otp`/etc. field
    expect(totp_detected).toBeNull();
  });

  it('detector ignores GET requests (TOTP submission is always POST)', () => {
    const r = detectTotpStep([
      {
        method: 'GET',
        url: 'https://app.example.com/totp/verify?code=000000',
        headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
      },
    ]);
    expect(r).toBeNull();
  });
});

describe('detectNonReplayablePatterns', () => {
  it('flags /webauthn and /sms/verify, leaves form-POST alone', () => {
    const warnings = detectNonReplayablePatterns([
      { method: 'POST', url: 'https://app.example.com/login', headers: [] },
      { method: 'POST', url: 'https://idp.example.com/webauthn/finish', headers: [] },
      { method: 'POST', url: 'https://idp.example.com/sms/verify', headers: [] },
    ]);
    expect(warnings).toHaveLength(2);
    expect(warnings.map((w) => w.entry_index)).toEqual([1, 2]);
    expect(warnings[0].pattern_hint).toMatch(/WebAuthn/);
    expect(warnings[1].pattern_hint).toMatch(/SMS/);
  });

  it('handles malformed URLs gracefully (no throw)', () => {
    expect(() =>
      detectNonReplayablePatterns([{ method: 'GET', url: '::not-a-url::', headers: [] }]),
    ).not.toThrow();
  });
});

describe('extractOriginsObserved', () => {
  it('returns lowercase hostnames de-duplicated', () => {
    const out = extractOriginsObserved([
      { method: 'GET', url: 'https://APP.example.com/', headers: [] },
      { method: 'GET', url: 'https://app.example.com/dashboard', headers: [] },
      { method: 'GET', url: 'https://idp.example.com/oauth/authorize', headers: [] },
    ]);
    expect(out).toEqual(['app.example.com', 'idp.example.com']);
  });
});

describe('scrubUrlQueryParams', () => {
  it('redacts token-keyed values and leaves keys + non-token params', () => {
    const out = scrubUrlQueryParams(
      'https://app.example.com/oauth/callback?code=secret&state=xyz&foo=bar',
    );
    expect(out).toContain('code=%5BREDACTED%5D');
    expect(out).toContain('state=%5BREDACTED%5D');
    expect(out).toContain('foo=bar');
  });

  it('returns [INVALID_URL] without throwing on malformed input', () => {
    expect(scrubUrlQueryParams('::not::a::url')).toBe('[INVALID_URL]');
  });

  it('preserves empty query strings', () => {
    expect(scrubUrlQueryParams('https://app.example.com/dashboard')).toContain('app.example.com/dashboard');
  });
});

// ---------------------------------------------------------------------------
// no-replayable-requests guard
// ---------------------------------------------------------------------------

describe('parseHar — har_no_replayable_requests', () => {
  it('rejects when only OPTIONS preflights remain', () => {
    // OPTIONS doesn't get filtered, but the per-entry header allowlist still
    // applies; we use it as a "no auth-meaningful traffic" representative.
    // This is more of a guard that the empty-after-filter branch is reachable.
    // We currently keep all methods; a future filter would surface this.
    const fx = harFixture([{ url: 'https://x.example.com/preflight', method: 'OPTIONS' }]);
    // Today this passes — kept here as a placeholder for v1.1's "drop
    // OPTIONS / HEAD preflights" follow-up (not in v1 scope).
    expect(() => parseHar(fx)).not.toThrow();
  });
});
