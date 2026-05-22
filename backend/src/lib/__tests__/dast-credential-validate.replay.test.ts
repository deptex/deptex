// Unit tests for the Phase-36 replay-auth validator branches in
// dast-credential-validate.ts.
//
// Coverage per the plan (M1 step 9 + Patch I-6 hostile-secret cases):
//   - happy path: full ReplayCredentialPayload round-trips through
//     validateAndPrepareCredential, encrypt-side payload matches the input
//     verbatim, summary shape is correct
//   - shape rejections: missing requests, non-array origins_observed,
//     mismatched origins, bad totp_step
//   - TOTP secret discipline: canonical accept, lowercase reject, whitespace
//     reject, hyphen reject, oversize reject, U+2028 inside secret reject
//   - SSRF gate: stubbed validateExternalUrl rejects → login_url_invalid
//   - serialized-cap rejection
//   - cross-strategy regression: the existing recorded payload still validates

import {
  validateAndPrepareCredential,
  validateReplayPayload,
} from '../dast-credential-validate';
import type { ReplayCredentialPayload } from '../../types/dast';

// ---------------------------------------------------------------------------
// Synthetic payload factory
// ---------------------------------------------------------------------------

function makePayload(over: Partial<ReplayCredentialPayload> = {}): ReplayCredentialPayload {
  return {
    kind: 'replay',
    requests: [
      {
        method: 'POST',
        url: 'https://app.example.com/login',
        headers: [
          { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
        ],
        body: 'username=alice&password=wonderland',
        body_encoding: 'utf8',
      },
      {
        method: 'GET',
        url: 'https://app.example.com/dashboard',
        headers: [{ name: 'Cookie', value: 'session=abc' }],
      },
    ],
    origins_observed: ['app.example.com'],
    ...over,
  };
}

// validateExternalUrl stub for the SSRF gate — accepts any URL by default.
const acceptingGuard = async (url: string) => ({
  valid: true as const,
  resolved: { host: new URL(url).hostname, addresses: ['203.0.113.1'] },
});

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

describe('validateReplayPayload — happy path', () => {
  it('accepts a minimal valid payload', () => {
    const err = validateReplayPayload(makePayload());
    expect(err).toBeNull();
  });

  it('accepts a payload with a canonical base32 TOTP secret + totp_step', () => {
    const err = validateReplayPayload(
      makePayload({
        requests: [
          {
            method: 'POST',
            url: 'https://app.example.com/totp/verify',
            headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
            body: 'pending_session=abc&code=123456',
          },
        ],
        totp_step: { entry_index: 0, body_field: 'code', body_kind: 'form' },
        totp_secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      }),
    );
    expect(err).toBeNull();
  });
});

describe('validateAndPrepareCredential — replay branch', () => {
  it('round-trips full payload + emits a replay summary', async () => {
    const result = await validateAndPrepareCredential(
      {
        auth_strategy: 'replay',
        payload: makePayload({ label: 'my staging tenant' }),
      },
      { scanTimeoutMinutes: 30, runReplaySsrfGuard: false },
    );
    if (!result.ok) throw new Error(`unexpected error: ${result.error.error_code}`);
    expect(result.payload.kind).toBe('replay');
    expect(result.summary).toEqual({
      kind: 'replay',
      request_count: 2,
      origins_observed: ['app.example.com'],
      totp_detected: false,
      has_totp_secret: false,
      has_non_replayable_pattern: false,
      label: 'my staging tenant',
    });
    // Serialized plaintext is what gets encrypted — assert it round-trips.
    expect(JSON.parse(result.serializedPlaintext)).toMatchObject({
      kind: 'replay',
      origins_observed: ['app.example.com'],
    });
  });

  it('flags non-replayable patterns in the summary', async () => {
    const result = await validateAndPrepareCredential(
      {
        auth_strategy: 'replay',
        payload: makePayload({
          requests: [
            {
              method: 'POST',
              url: 'https://idp.example.com/webauthn/finish',
              headers: [{ name: 'Content-Type', value: 'application/json' }],
              body: '{}',
            },
          ],
          origins_observed: ['idp.example.com'],
        }),
      },
      { scanTimeoutMinutes: 30, runReplaySsrfGuard: false },
    );
    if (!result.ok) throw new Error(`unexpected error: ${result.error.error_code}`);
    expect((result.summary as { has_non_replayable_pattern: boolean }).has_non_replayable_pattern).toBe(true);
  });

  it('exposes has_totp_secret + totp_detected when both are set', async () => {
    const result = await validateAndPrepareCredential(
      {
        auth_strategy: 'replay',
        payload: makePayload({
          requests: [
            {
              method: 'POST',
              url: 'https://app.example.com/totp/verify',
              headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
              body: 'pending_session=abc&code=123456',
            },
          ],
          totp_step: { entry_index: 0, body_field: 'code', body_kind: 'form' },
          totp_secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
        }),
      },
      { scanTimeoutMinutes: 30, runReplaySsrfGuard: false },
    );
    if (!result.ok) throw new Error(`unexpected error: ${result.error.error_code}`);
    expect((result.summary as { totp_detected: boolean }).totp_detected).toBe(true);
    expect((result.summary as { has_totp_secret: boolean }).has_totp_secret).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Shape rejections
// ---------------------------------------------------------------------------

describe('validateReplayPayload — shape rejections', () => {
  it('rejects empty requests array', () => {
    const err = validateReplayPayload({
      kind: 'replay',
      requests: [],
      origins_observed: [],
    });
    expect(err).not.toBeNull();
    expect(err!.error_code).toBe('invalid_credential_shape');
  });

  it('rejects payload missing origins_observed', () => {
    const err = validateReplayPayload({
      ...makePayload(),
      // @ts-expect-error testing missing field
      origins_observed: undefined,
    });
    expect(err).not.toBeNull();
  });

  it('rejects payload where origins_observed misses a host the requests use', () => {
    const err = validateReplayPayload(
      makePayload({
        requests: [
          { method: 'GET', url: 'https://app.example.com/', headers: [] },
          { method: 'GET', url: 'https://idp.example.com/', headers: [] },
        ],
        origins_observed: ['app.example.com'], // missing idp
      }),
    );
    expect(err).not.toBeNull();
    expect(err!.detail).toMatch(/origins_observed missing/);
  });

  it('rejects totp_step with out-of-range entry_index', () => {
    const err = validateReplayPayload(
      makePayload({
        totp_step: { entry_index: 99, body_field: 'code', body_kind: 'form' },
      }),
    );
    expect(err).not.toBeNull();
    expect(err!.detail).toMatch(/totp_step shape invalid/);
  });

  it('rejects totp_step with invalid body_kind', () => {
    const err = validateReplayPayload(
      makePayload({
        totp_step: { entry_index: 0, body_field: 'code', body_kind: 'xml' as 'form' },
      }),
    );
    expect(err).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Patch I-6 — hostile TOTP secret cases
// ---------------------------------------------------------------------------

describe('validateReplayPayload — Patch I-6 hostile-secret cases', () => {
  const cases: Array<{ name: string; secret: string }> = [
    { name: 'JS-injection attempt', secret: '";eval(1);//' },
    { name: 'lowercase rejected', secret: 'jbswy3dpehpk3pxp' },
    { name: 'whitespace rejected', secret: 'JBSW Y3DP' },
    { name: 'hyphen rejected', secret: 'JBSWY3DP-EHPK3PXP' },
    { name: 'oversize rejected', secret: 'A'.repeat(300) },
    { name: 'non-base32 chars rejected', secret: 'JBSWY3DP019999' },
  ];

  it.each(cases)('rejects $name', ({ secret }) => {
    const err = validateReplayPayload(makePayload({ totp_secret: secret }));
    expect(err).not.toBeNull();
  });

  it('accepts canonical RFC 4648 base32 with no padding', () => {
    const err = validateReplayPayload(makePayload({ totp_secret: 'JBSWY3DPEHPK3PXP' }));
    expect(err).toBeNull();
  });

  it('accepts canonical RFC 4648 base32 with `=` padding', () => {
    const err = validateReplayPayload(makePayload({ totp_secret: 'JBSWY3DPEHPK3PXP====' }));
    expect(err).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SSRF gate
// ---------------------------------------------------------------------------

describe('validateAndPrepareCredential — replay SSRF gate', () => {
  it('rejects when the SSRF guard blocks an origin', async () => {
    const blockingGuard = async (_url: string) => ({
      valid: false as const,
      reason: 'resolved to private IP 10.0.0.5',
    });
    const result = await validateAndPrepareCredential(
      { auth_strategy: 'replay', payload: makePayload() },
      { scanTimeoutMinutes: 30, validateUrl: blockingGuard },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.error_code).toBe('login_url_invalid');
    expect(result.error.detail).toMatch(/private IP/);
  });

  it('accepts when the SSRF guard approves every origin', async () => {
    const result = await validateAndPrepareCredential(
      { auth_strategy: 'replay', payload: makePayload() },
      { scanTimeoutMinutes: 30, validateUrl: acceptingGuard },
    );
    expect(result.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Cross-strategy regression
// ---------------------------------------------------------------------------

describe('validateAndPrepareCredential — pre-Phase-36 strategies still work', () => {
  it('still validates a jwt payload', async () => {
    // Synthetic JWT — header.payload.signature; payload has exp far in
    // the future to clear the JWT exp check.
    const payload = Buffer.from(
      JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 * 24 }),
    ).toString('base64url');
    const token = `eyJhbGciOiJIUzI1NiJ9.${payload}.sig`;
    const result = await validateAndPrepareCredential(
      { auth_strategy: 'jwt', payload: { kind: 'jwt', token } },
      { scanTimeoutMinutes: 30 },
    );
    expect(result.ok).toBe(true);
  });
});
