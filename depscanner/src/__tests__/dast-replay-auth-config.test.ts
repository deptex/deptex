// Phase 36 (v1.1) — full-shape round-trip tests for the replay branch of
// buildAuthForStrategy + buildReplayAuthForZap. Pins the contract between
// the hand-mirrored ReplayCredentialPayload type (depscanner-side) and the
// shape that yaml-builder emits.
//
// Covers:
//   - method='script' + correct engine identifier
//   - scriptInline contains all captured requests in order
//   - TOTP block: secret + RFC 6238 helper string-inlined under the
//     __DEPTEX_TOTP_SECRET identifier
//   - shape-coverage: every optional field round-trips encrypt→decrypt
//     unchanged (defends the hand mirror against backend type drift)
//   - Nuclei rejection: buildNucleiAuthHeaders throws on replay

import {
  buildAuthForStrategy,
  buildReplayAuthForZap,
  buildNucleiAuthHeaders,
  UnsupportedAuthStrategyError,
  type ReplayCredentialPayload,
} from '../dast/auth-config';
import { ZAP_SCRIPT_ENGINE } from '../dast/replay-zap-auth';

function makePayload(over: Partial<ReplayCredentialPayload> = {}): ReplayCredentialPayload {
  return {
    kind: 'replay',
    requests: [
      {
        method: 'POST',
        url: 'https://app.example.com/login',
        headers: [
          { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
          { name: 'Origin', value: 'https://app.example.com' },
        ],
        body: 'username=alice&password=wonderland',
        body_encoding: 'utf8',
      },
      {
        method: 'GET',
        url: 'https://app.example.com/dashboard',
        headers: [{ name: 'Cookie', value: 'session=harvested-by-zap' }],
      },
    ],
    origins_observed: ['app.example.com'],
    ...over,
  };
}

describe('buildReplayAuthForZap — base shape', () => {
  it('emits method=script + correct scriptEngine identifier', () => {
    const r = buildReplayAuthForZap(makePayload());
    expect((r.contextAuthentication as any).method).toBe('script');
    expect((r.contextAuthentication as any).parameters.scriptEngine).toBe(
      'ECMAScript : Graal.js',
    );
    expect(ZAP_SCRIPT_ENGINE).toBe('ECMAScript : Graal.js');
  });

  it('emits a non-empty scriptInline that contains both request URLs in order', () => {
    const r = buildReplayAuthForZap(makePayload());
    const body = (r.contextAuthentication as any).parameters.scriptInline as string;
    expect(body).toContain('https://app.example.com/login');
    expect(body).toContain('https://app.example.com/dashboard');
    // Request order is index-stable — login comes before dashboard.
    expect(body.indexOf('app.example.com/login')).toBeLessThan(
      body.indexOf('app.example.com/dashboard'),
    );
  });

  it('emits the deptex-dast-user binding even though credentials map is empty', () => {
    const r = buildReplayAuthForZap(makePayload());
    expect(r.contextUsers).toHaveLength(1);
    expect(r.contextUsers[0].name).toBe('deptex-dast-user');
    expect(r.contextUsers[0].credentials).toEqual({});
  });

  it('plumbs the loggedIn / loggedOut indicators into context.authentication.verification', () => {
    const r = buildReplayAuthForZap(makePayload(), 'WELCOME, ALICE', 'You are not logged in');
    const v = (r.contextAuthentication as any).verification;
    expect(v.method).toBe('response');
    expect(v.loggedInRegex).toBe('WELCOME, ALICE');
    expect(v.loggedOutRegex).toBe('You are not logged in');
  });

  it('omits verification regexes when neither indicator is provided', () => {
    const r = buildReplayAuthForZap(makePayload());
    const v = (r.contextAuthentication as any).verification;
    expect(v.method).toBe('response');
    expect(v.loggedInRegex).toBeUndefined();
    expect(v.loggedOutRegex).toBeUndefined();
  });
});

describe('buildReplayAuthForZap — TOTP shape', () => {
  it('inlines the RFC 6238 helper + base32 secret under __DEPTEX_TOTP_SECRET', () => {
    const r = buildReplayAuthForZap(
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
    const body = (r.contextAuthentication as any).parameters.scriptInline as string;
    expect(body).toContain('__deptexGenerateTotpCode');
    expect(body).toContain('__DEPTEX_TOTP_SECRET');
    expect(body).toContain('"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"');
    // The TOTP code substitution call site at the totp_step entry index.
    expect(body).toMatch(/_fresh0\s*=\s*__deptexGenerateTotpCode/);
  });

  it('does NOT inline the helper when totp_step is absent', () => {
    const r = buildReplayAuthForZap(makePayload()); // no totp_step
    const body = (r.contextAuthentication as any).parameters.scriptInline as string;
    expect(body).not.toContain('__deptexGenerateTotpCode');
    expect(body).not.toContain('__DEPTEX_TOTP_SECRET');
  });
});

describe('buildReplayAuthForZap — shape coverage (hand-mirror drift guard)', () => {
  it('round-trips every optional field through buildAuthForStrategy', () => {
    const full: ReplayCredentialPayload = {
      kind: 'replay',
      requests: [
        {
          method: 'POST',
          url: 'https://app.example.com/login',
          headers: [
            { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
            { name: 'X-CSRF-Token', value: 'csrf123' },
            { name: 'Sec-Fetch-Site', value: 'same-origin' },
          ],
          body: 'username=alice&password=wonderland',
          body_encoding: 'utf8',
        },
        {
          method: 'POST',
          url: 'https://app.example.com/mfa/verify',
          headers: [{ name: 'Content-Type', value: 'application/json' }],
          body: '{"code":"000000","trust":false}',
        },
      ],
      totp_step: { entry_index: 1, body_field: 'code', body_kind: 'json' },
      totp_secret: 'JBSWY3DPEHPK3PXP',
      origins_observed: ['app.example.com'],
      label: 'staging Auth0',
    };

    const r = buildAuthForStrategy('replay', full, 'WELCOME', 'LOGIN');
    expect((r.contextAuthentication as any).method).toBe('script');
    const body = (r.contextAuthentication as any).parameters.scriptInline as string;
    // Every captured artifact present in the emitted JS. Note JSON.stringify
    // round-trips the body: `"trust":false` becomes `\"trust\":false` in
    // the emitted source string.
    expect(body).toContain('username=alice&password=wonderland');
    expect(body).toContain('\\"trust\\":false');
    expect(body).toContain('JBSWY3DPEHPK3PXP');
    expect(body).toContain('csrf123');
    // The JSON-bodied TOTP step uses JSON.parse + mutate + JSON.stringify.
    expect(body).toMatch(/_bobj1\s*=\s*JSON\.parse/);
    expect(body).toMatch(/JSON\.stringify\(_bobj1\)/);
  });
});

describe('buildNucleiAuthHeaders — replay rejection', () => {
  it('throws UnsupportedAuthStrategyError with strategy name (no payload bytes)', () => {
    let thrown: Error | null = null;
    try {
      buildNucleiAuthHeaders('replay', makePayload());
    } catch (e) {
      thrown = e as Error;
    }
    expect(thrown).toBeInstanceOf(UnsupportedAuthStrategyError);
    // Error message contains the strategy name but no URL / header bytes.
    expect(thrown!.message).toContain('replay');
    expect(thrown!.message).not.toContain('app.example.com');
    expect(thrown!.message).not.toContain('wonderland');
  });
});

describe('buildAuthForStrategy — strategy/payload-kind mismatch guard', () => {
  it('throws when payload.kind does not match the strategy arg', () => {
    expect(() =>
      buildAuthForStrategy('replay', { kind: 'jwt', token: 'eyJ.aa.bb' }),
    ).toThrow(/mismatches strategy='replay'/);
  });
});
