// v2.1d /criticalreview ssrf-1 (P0) regression test for the recorded-strategy
// SSRF guard. The structural validator (validateRecordedSteps) only checks
// URL.parse + protocol==='https:'; without validateRecordedSsrf, a tenant
// member with manage_integrations can set login_page_url / goto.value /
// sso_origins to a hostname that resolves to IMDS / RFC1918 / Fly's
// internal 6PN mesh — Firefox in the worker fetches it from the container.
//
// We stub validateExternalUrl so the test stays hermetic (no DNS); the
// real-world hostname → IP guard is covered by the url-guard.ts unit
// tests. Here we just pin the wiring: every URL the worker will fetch
// gets routed through the guard.

import {
  validateRecordedSsrf,
  type ValidateAndPrepareOptions,
  validateAndPrepareCredential,
} from '../dast-credential-validate';
import type { RecordedCredentialPayload } from '../../types/dast';

type UrlGuardResult =
  | { valid: true; resolved: { host: string; addresses: string[] } }
  | { valid: false; reason: string };

function stubGuard(
  decisions: Record<string, UrlGuardResult>,
  fallback: UrlGuardResult = { valid: true, resolved: { host: '', addresses: [] } },
) {
  return async (rawUrl: string): Promise<UrlGuardResult> => {
    const host = (() => {
      try {
        return new URL(rawUrl).hostname;
      } catch {
        return rawUrl;
      }
    })();
    return decisions[host] ?? fallback;
  };
}

function basePayload(overrides: Partial<RecordedCredentialPayload> = {}): RecordedCredentialPayload {
  return {
    kind: 'recorded',
    login_page_url: 'https://app.example.com/login',
    steps: [
      { action: 'goto', value: 'https://app.example.com/login' },
      { action: 'type_username', selector: '#email' },
      { action: 'type_password', selector: '#pass' },
      { action: 'click', selector: 'button[type=submit]' },
    ],
    username: 'a@example.com',
    password: 'hunter2hunter2',
    ...overrides,
  };
}

describe('validateRecordedSsrf', () => {
  it('accepts a public login_page_url', async () => {
    const guard = stubGuard({ 'app.example.com': { valid: true, resolved: { host: 'app.example.com', addresses: ['93.184.216.34'] } } });
    const err = await validateRecordedSsrf(basePayload(), guard);
    expect(err).toBeNull();
  });

  it('rejects login_page_url resolving to AWS IMDS', async () => {
    const guard = stubGuard({
      'imds.attacker.example.com': { valid: false, reason: 'host imds.attacker.example.com resolved to blocked IP 169.254.169.254 (link-local)' },
    });
    const err = await validateRecordedSsrf(
      basePayload({ login_page_url: 'https://imds.attacker.example.com/' }),
      guard,
    );
    expect(err?.error_code).toBe('login_url_invalid');
    expect(err?.detail).toMatch(/login_page_url/);
    expect(err?.detail).toMatch(/169\.254\.169\.254/);
  });

  it('rejects login_page_url with literal RFC1918 host', async () => {
    const guard = stubGuard({
      '10.0.0.1': { valid: false, reason: 'literal IP 10.0.0.1 rejected (RFC1918)' },
    });
    const err = await validateRecordedSsrf(
      basePayload({ login_page_url: 'https://10.0.0.1/' }),
      guard,
    );
    expect(err?.error_code).toBe('login_url_invalid');
  });

  it('rejects login_page_url pointing at localhost', async () => {
    const guard = stubGuard({
      localhost: { valid: false, reason: 'host localhost is a reserved alias' },
    });
    const err = await validateRecordedSsrf(
      basePayload({ login_page_url: 'https://localhost/' }),
      guard,
    );
    expect(err?.error_code).toBe('login_url_invalid');
  });

  it('rejects login_page_url pointing at Fly internal 6PN', async () => {
    const guard = stubGuard({
      'app.internal': { valid: false, reason: 'host app.internal matches blocked pattern /\\.internal$/i' },
    });
    const err = await validateRecordedSsrf(
      basePayload({ login_page_url: 'https://app.internal/' }),
      guard,
    );
    expect(err?.error_code).toBe('login_url_invalid');
  });

  it('rejects a goto step value pointing at a private host', async () => {
    const guard = stubGuard({
      'app.example.com': { valid: true, resolved: { host: 'app.example.com', addresses: ['1.2.3.4'] } },
      'internal.attacker.example.com': { valid: false, reason: 'host resolved to 169.254.169.254' },
    });
    const err = await validateRecordedSsrf(
      basePayload({
        login_page_url: 'https://app.example.com/login',
        steps: [
          { action: 'goto', value: 'https://internal.attacker.example.com/' },
          { action: 'type_username', selector: '#email' },
        ],
      }),
      guard,
    );
    expect(err?.error_code).toBe('login_url_invalid');
    expect(err?.detail).toMatch(/step 0 goto/);
  });

  it('rejects an sso_origin pointing at a private host', async () => {
    const guard = stubGuard({
      'app.example.com': { valid: true, resolved: { host: 'app.example.com', addresses: ['1.2.3.4'] } },
      'attacker.example.com': { valid: false, reason: 'resolved to fdaa::1' },
    });
    const err = await validateRecordedSsrf(
      basePayload({ sso_origins: ['https://attacker.example.com'] }),
      guard,
    );
    expect(err?.error_code).toBe('login_url_invalid');
    expect(err?.detail).toMatch(/sso_origins/);
  });

  it('accepts payloads with no goto step (login_page_url drives entry)', async () => {
    const guard = stubGuard({
      'app.example.com': { valid: true, resolved: { host: 'app.example.com', addresses: ['1.2.3.4'] } },
    });
    const err = await validateRecordedSsrf(
      basePayload({
        steps: [
          { action: 'type_username', selector: '#email' },
          { action: 'type_password', selector: '#pass' },
        ],
      }),
      guard,
    );
    expect(err).toBeNull();
  });
});

describe('validateAndPrepareCredential — recorded SSRF wiring', () => {
  function recordedOpts(
    guard: (rawUrl: string) => Promise<UrlGuardResult>,
  ): ValidateAndPrepareOptions {
    return {
      scanTimeoutMinutes: 30,
      runFormProbe: false,
      runRecordedSsrfGuard: true,
      validateUrl: guard,
    };
  }

  it('passes a recorded payload through validateRecordedSsrf', async () => {
    const guard = stubGuard({
      'app.example.com': { valid: true, resolved: { host: 'app.example.com', addresses: ['1.2.3.4'] } },
    });
    const result = await validateAndPrepareCredential(
      { auth_strategy: 'recorded', payload: basePayload() },
      recordedOpts(guard),
    );
    expect(result.ok).toBe(true);
  });

  it('rejects when validateRecordedSsrf flags a private host', async () => {
    const guard = stubGuard({
      'app.example.com': { valid: false, reason: 'resolved to 127.0.0.1' },
    });
    const result = await validateAndPrepareCredential(
      { auth_strategy: 'recorded', payload: basePayload() },
      recordedOpts(guard),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.error_code).toBe('login_url_invalid');
  });

  it('skips SSRF guard when runRecordedSsrfGuard=false', async () => {
    // Hermetic — never resolves any DNS. If the guard ran, the default
    // validateExternalUrl import would try real DNS and fail in CI.
    const result = await validateAndPrepareCredential(
      { auth_strategy: 'recorded', payload: basePayload() },
      { scanTimeoutMinutes: 30, runFormProbe: false, runRecordedSsrfGuard: false },
    );
    expect(result.ok).toBe(true);
  });
});
