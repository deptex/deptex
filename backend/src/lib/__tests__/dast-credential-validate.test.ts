// Regression gates for backend/src/lib/dast-credential-validate.ts.
//
// Most of the surface is exercised end-to-end via dast-routes.test.ts but
// those tests only walk happy paths. The cases here lock the
// security-relevant boundaries the v2.1a critical review flagged as
// untested — silent-anonymous-fallback regressions, JWT prefix length,
// indicator-collision logic, ReDoS pre-check on user-supplied indicators,
// and the opaque-error contract on the login probe.

import {
  jwtExpiresInMinutes,
  probeFormLogin,
  validateAndPrepareCredential,
  summarizePayload,
} from '../dast-credential-validate';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function buildJwt(claim: object): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(claim)).toString('base64url');
  return `${header}.${body}.fakesignature1234567890fakesignature`;
}

function jwtExpFromNow(seconds: number): string {
  return buildJwt({ sub: '1', exp: Math.floor(Date.now() / 1000) + seconds });
}

function fakeFetch(
  responses: Array<{ status: number; headers?: Record<string, string>; body: string }>,
): typeof fetch {
  let i = 0;
  return (async () => {
    const r = responses[Math.min(i, responses.length - 1)];
    i++;
    return {
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      headers: {
        get: (name: string) => r.headers?.[name.toLowerCase()] ?? null,
      },
      // eslint-disable-next-line @typescript-eslint/require-await
      text: async () => r.body,
      body: null,
    } as any;
  }) as typeof fetch;
}

// Stub the SSRF guard so tests don't perform real DNS. Returns valid for
// any non-private URL; private/IMDS literals still fail because of the
// inner ipaddr.js check we do here too.
const validateUrl: typeof import('../url-guard').validateExternalUrl = async (raw) => {
  let parsed: URL;
  try { parsed = new URL(raw); } catch {
    return { valid: false, reason: 'invalid' };
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  // Quick reject for the cases we care about in tests (loopback / IMDS).
  const blocked = ['127.0.0.1', '::1', '169.254.169.254', '10.0.0.1', '192.168.1.1'];
  if (blocked.includes(host)) {
    return { valid: false, reason: `blocked literal ${host}` };
  }
  return { valid: true, resolved: { host, addresses: [host] } };
};

const FORM_PAYLOAD = {
  kind: 'form' as const,
  login_url: 'https://app.example.com/login',
  username_field: 'email',
  password_field: 'password',
  username: 'admin@example.com',
  password: 's3cr3t-fixture',
};

// ---------------------------------------------------------------------------
// summarizePayload — never echoes secrets back to the client
// ---------------------------------------------------------------------------

describe('summarizePayload', () => {
  it('form: emails are masked to first-char + ***@domain', () => {
    const s = summarizePayload({ ...FORM_PAYLOAD });
    expect(s).toEqual({ kind: 'form', username_masked: 'a***@example.com' });
    if (s.kind === 'form') expect(s.username_masked).not.toContain('admin');
  });

  it('form: bare usernames (no @) emit only first char + ***', () => {
    const s = summarizePayload({ ...FORM_PAYLOAD, username: 'admin' });
    if (s.kind !== 'form') throw new Error('expected form');
    expect(s.username_masked).toBe('a***');
    expect(s.username_masked).not.toContain('dmin');
  });

  it('form: empty username does not crash and does not leak', () => {
    const s = summarizePayload({ ...FORM_PAYLOAD, username: '' });
    if (s.kind !== 'form') throw new Error('expected form');
    expect(s.username_masked).toBe('');
  });

  it('jwt: token_prefix capped at 8 chars (does not expose JWT alg)', () => {
    // Real JWT prefix `eyJhbGciOi` is 10 chars and reveals alg=HS256/RS256.
    // The summary MUST stop at 8 to keep the algorithm choice opaque.
    const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepart';
    const s = summarizePayload({ kind: 'jwt', token });
    if (s.kind !== 'jwt') throw new Error('expected jwt');
    expect(s.token_prefix).toBe('eyJhbGci…');
    expect(s.token_prefix.length).toBe(9); // 8 chars + ellipsis
    // Critically: the prefix must NOT contain the full alg-revealing run.
    expect(s.token_prefix).not.toContain('eyJhbGciOi');
  });

  it('cookie: cookie_names are capped at 10 entries × 32 chars each', () => {
    const cookies = Array.from({ length: 15 }, (_, i) => ({
      name: `c${i}_${'x'.repeat(40)}`,
      value: `secret-value-${i}`,
    }));
    const s = summarizePayload({ kind: 'cookie', cookies });
    if (s.kind !== 'cookie') throw new Error('expected cookie');
    expect(s.cookie_count).toBe(15);
    expect(s.cookie_names).toHaveLength(10);
    expect(s.cookie_names[0].length).toBeLessThanOrEqual(32);
    // Values must NEVER appear in the summary.
    expect(JSON.stringify(s)).not.toContain('secret-value');
  });
});

// ---------------------------------------------------------------------------
// jwtExpiresInMinutes
// ---------------------------------------------------------------------------

describe('jwtExpiresInMinutes', () => {
  it('returns minutes-until-expiry for a well-formed token', () => {
    const m = jwtExpiresInMinutes(jwtExpFromNow(3600));
    expect(m).toBeGreaterThan(58);
    expect(m).toBeLessThan(62);
  });

  it('returns null on a non-3-segment token', () => {
    expect(jwtExpiresInMinutes('not.a.jwt.shape')).toBeNull();
    expect(jwtExpiresInMinutes('only-one-segment')).toBeNull();
  });

  it('returns null on a token without an exp claim', () => {
    const noExp = buildJwt({ sub: '1' });
    expect(jwtExpiresInMinutes(noExp)).toBeNull();
  });

  it('returns null on a token whose payload is not valid JSON', () => {
    const garbage = 'eyJhbGciOiJIUzI1NiJ9.aGVsbG8td29ybGQ.fakesignature';
    expect(jwtExpiresInMinutes(garbage)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// validateAndPrepareCredential — JWT exp threshold formula
// ---------------------------------------------------------------------------

describe('validateAndPrepareCredential — jwt threshold (1.5 × scanTimeoutMinutes)', () => {
  it('rejects a JWT that expires before 1.5 × scan_timeout', async () => {
    // scan_timeout=30, threshold=45 min. exp=20 min must fail.
    const r = await validateAndPrepareCredential(
      { auth_strategy: 'jwt', payload: { kind: 'jwt', token: jwtExpFromNow(20 * 60) } },
      { scanTimeoutMinutes: 30, runFormProbe: false },
    );
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('jwt_expired_too_soon');
  });

  it('accepts a JWT that comfortably exceeds 1.5 × scan_timeout', async () => {
    const r = await validateAndPrepareCredential(
      { auth_strategy: 'jwt', payload: { kind: 'jwt', token: jwtExpFromNow(2 * 60 * 60) } },
      { scanTimeoutMinutes: 30, runFormProbe: false },
    );
    expect(r.ok).toBe(true);
  });

  it('uses opaque generic detail on malformed JWT (does NOT echo pasted token)', async () => {
    const r = await validateAndPrepareCredential(
      // Middle segment decodes to a non-JSON 'hello-world-this-is-not-json'.
      { auth_strategy: 'jwt', payload: { kind: 'jwt', token: 'eyJhbGciOiJIUzI1NiJ9.aGVsbG8td29ybGQtdGhpcy1pcy1ub3QtanNvbg.x' } },
      { scanTimeoutMinutes: 30, runFormProbe: false },
    );
    expect(r.ok).toBe(false);
    if (r.ok === false) {
      expect(r.error.error_code).toBe('jwt_decode_failed');
      // Critically: the detail must NOT contain a substring of the user's
      // pasted token content. Pre-fix this leaked ~11 chars of input.
      expect(r.error.detail).not.toContain('hello-world');
      expect(r.error.detail).not.toContain('Unexpected token');
    }
  });
});

// ---------------------------------------------------------------------------
// probeFormLogin — indicator pre-check (ReDoS safety + length cap)
// ---------------------------------------------------------------------------

describe('probeFormLogin — indicator regex pre-check', () => {
  it('rejects an unsafe logged_in_indicator (catastrophic backtracking shape)', async () => {
    const r = await probeFormLogin(FORM_PAYLOAD, {
      validateUrl, fetchImpl: fakeFetch([{ status: 200, body: '<html>...</html>' }]),
      loggedInIndicator: '(.+a){50}b',
    });
    expect(r?.error_code).toBe('login_probe_failed');
    expect(r?.detail).toMatch(/unsafe|backtracking|ReDoS/i);
  });

  it('rejects an unsafe logged_out_indicator', async () => {
    const r = await probeFormLogin(FORM_PAYLOAD, {
      validateUrl, fetchImpl: fakeFetch([{ status: 200, body: '<html>...</html>' }]),
      loggedOutIndicator: '(a+)+b',
    });
    expect(r?.error_code).toBe('login_probe_failed');
    expect(r?.detail).toMatch(/unsafe|backtracking|ReDoS/i);
  });

  it('rejects an indicator longer than the per-pattern cap', async () => {
    const r = await probeFormLogin(FORM_PAYLOAD, {
      validateUrl, fetchImpl: fakeFetch([{ status: 200, body: '' }]),
      loggedInIndicator: 'a'.repeat(257),
    });
    expect(r?.error_code).toBe('login_probe_failed');
    expect(r?.detail).toMatch(/exceeds|256/);
  });

  it('rejects an invalid regex (compile failure)', async () => {
    const r = await probeFormLogin(FORM_PAYLOAD, {
      validateUrl, fetchImpl: fakeFetch([{ status: 200, body: '' }]),
      loggedInIndicator: '[unclosed-class',
    });
    expect(r?.error_code).toBe('login_probe_failed');
    expect(r?.detail).toMatch(/not a valid regex/i);
  });

  it('accepts a safe indicator and a matching response', async () => {
    const r = await probeFormLogin(FORM_PAYLOAD, {
      validateUrl, fetchImpl: fakeFetch([{ status: 200, body: '<a href=logout>Sign out</a>' }]),
      loggedInIndicator: 'Sign out',
    });
    expect(r).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// probeFormLogin — opaque error contract
// ---------------------------------------------------------------------------

describe('probeFormLogin — opaque error mapping', () => {
  it('maps a fetch network failure to a generic detail (no IP/port leak)', async () => {
    const failing: typeof fetch = (async () => {
      throw new Error('connect ECONNREFUSED 169.254.169.254:80');
    }) as typeof fetch;

    const r = await probeFormLogin(FORM_PAYLOAD, { validateUrl, fetchImpl: failing });
    expect(r?.error_code).toBe('login_probe_failed');
    // The raw Node fetch message embeds the resolved IP + port. We MUST
    // strip that before returning to the client.
    expect(r?.detail).not.toContain('169.254.169.254');
    expect(r?.detail).not.toContain('ECONNREFUSED');
    expect(r?.detail).toBe('login endpoint did not respond');
  });
});

// ---------------------------------------------------------------------------
// probeFormLogin — redirect re-validation
// ---------------------------------------------------------------------------

describe('probeFormLogin — redirect re-validation', () => {
  it('rejects a 302 to a private IP (SSRF guard fires on each hop)', async () => {
    const fakeImpl = fakeFetch([
      { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data/' }, body: '' },
    ]);
    const r = await probeFormLogin(FORM_PAYLOAD, { validateUrl, fetchImpl: fakeImpl });
    expect(r?.error_code).toBe('login_url_invalid');
    expect(r?.detail).toMatch(/redirect destination|SSRF/i);
  });

  it('follows a 302 to a public host and continues the probe', async () => {
    const fakeImpl = fakeFetch([
      { status: 302, headers: { location: 'https://app.example.com/loggedin' }, body: '' },
      { status: 200, body: '<html>welcome admin</html>' },
    ]);
    const r = await probeFormLogin(FORM_PAYLOAD, {
      validateUrl,
      fetchImpl: fakeImpl,
      loggedInIndicator: 'welcome',
    });
    expect(r).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// validateAndPrepareCredential — shape gate
// ---------------------------------------------------------------------------

describe('validateAndPrepareCredential — shape errors', () => {
  it('rejects body=null', async () => {
    const r = await validateAndPrepareCredential(null, { scanTimeoutMinutes: 30, runFormProbe: false });
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('invalid_credential_shape');
  });

  it('rejects mismatched payload.kind vs auth_strategy', async () => {
    const r = await validateAndPrepareCredential(
      { auth_strategy: 'jwt', payload: { kind: 'cookie', cookies: [{ name: 'a', value: 'b' }] } },
      { scanTimeoutMinutes: 30, runFormProbe: false },
    );
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('invalid_credential_shape');
  });

  it('rejects cookie payload with empty cookies array', async () => {
    const r = await validateAndPrepareCredential(
      { auth_strategy: 'cookie', payload: { kind: 'cookie', cookies: [] } },
      { scanTimeoutMinutes: 30, runFormProbe: false },
    );
    expect(r.ok).toBe(false);
    if (r.ok === false) expect(r.error.error_code).toBe('invalid_credential_shape');
  });

  it('accepts a valid cookie payload (no probe required)', async () => {
    const r = await validateAndPrepareCredential(
      {
        auth_strategy: 'cookie',
        payload: { kind: 'cookie', cookies: [{ name: 'sess', value: 'fixture' }] },
      },
      { scanTimeoutMinutes: 30, runFormProbe: false },
    );
    expect(r.ok).toBe(true);
  });
});
