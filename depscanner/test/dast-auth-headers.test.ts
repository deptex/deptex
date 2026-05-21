/**
 * buildNucleiAuthHeaders tests — the credential → static-header reduction the
 * Nuclei engine uses (`-H @file`).
 *
 * This function is security-load-bearing: it enforces the never-scan-anonymous
 * invariant. jwt/cookie reduce to headers; form/recorded MUST throw so the
 * pipeline aborts the run rather than silently scanning an auth-required app
 * without credentials.
 *
 * Run: npx tsx test/dast-auth-headers.test.ts
 */

import {
  buildNucleiAuthHeaders,
  UnsupportedAuthStrategyError,
  type CredentialPayload,
} from '../src/dast/auth-config';

let failures = 0;
let passed = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
    passed++;
  }
}

/** Run `fn`, return the thrown error (or null if it did not throw). */
function caught(fn: () => unknown): unknown {
  try {
    fn();
    return null;
  } catch (e) {
    return e;
  }
}

function main(): void {
  const t0 = Date.now();
  console.log('buildNucleiAuthHeaders tests\n');

  console.log('[1] jwt → Authorization: Bearer <token>');
  {
    const headers = buildNucleiAuthHeaders('jwt', { kind: 'jwt', token: 'abc.def.ghi' });
    assert(
      JSON.stringify(headers) === JSON.stringify({ Authorization: 'Bearer abc.def.ghi' }),
      `jwt maps to a single Authorization header (got ${JSON.stringify(headers)})`,
    );
  }

  console.log('\n[2] cookie → Cookie: name=value; name=value');
  {
    const headers = buildNucleiAuthHeaders('cookie', {
      kind: 'cookie',
      cookies: [
        { name: 'session', value: 'abc' },
        { name: 'csrf', value: 'xyz' },
      ],
    });
    assert(
      headers.Cookie === 'session=abc; csrf=xyz',
      `cookie pairs joined with '; ' (got ${JSON.stringify(headers)})`,
    );
    assert(Object.keys(headers).length === 1, `cookie maps to exactly one header`);
  }

  console.log('\n[3] cookie with an empty cookies array → throws (never scan anonymous)');
  {
    const err = caught(() => buildNucleiAuthHeaders('cookie', { kind: 'cookie', cookies: [] }));
    assert(err instanceof Error, `empty-cookie payload throws`);
  }

  console.log('\n[4] form → throws UnsupportedAuthStrategyError');
  {
    const formPayload: CredentialPayload = {
      kind: 'form',
      login_url: 'https://app/login',
      username_field: 'u',
      password_field: 'p',
      username: 'user',
      password: 'pass',
    };
    const err = caught(() => buildNucleiAuthHeaders('form', formPayload));
    assert(
      err instanceof UnsupportedAuthStrategyError,
      `form auth throws UnsupportedAuthStrategyError (got ${err?.constructor?.name})`,
    );
  }

  console.log('\n[5] recorded → throws UnsupportedAuthStrategyError');
  {
    // 'recorded' has no CredentialPayload variant; a recorded-kind payload is
    // cast so the strategy/kind match check passes and the function reaches
    // its form/recorded throw.
    const recordedPayload = { kind: 'recorded' } as unknown as CredentialPayload;
    const err = caught(() => buildNucleiAuthHeaders('recorded', recordedPayload));
    assert(
      err instanceof UnsupportedAuthStrategyError,
      `recorded auth throws UnsupportedAuthStrategyError (got ${err?.constructor?.name})`,
    );
  }

  console.log('\n[6] strategy/payload-kind mismatch → throws');
  {
    const err = caught(() =>
      buildNucleiAuthHeaders('jwt', { kind: 'cookie', cookies: [{ name: 's', value: '1' }] }),
    );
    assert(err instanceof Error, `kind!=strategy throws`);
    assert(
      err instanceof Error && /mismatch/i.test(err.message),
      `mismatch error message names the mismatch (got ${(err as Error)?.message})`,
    );
  }

  console.log(
    `\nbuildNucleiAuthHeaders tests ${failures === 0 ? 'PASSED' : 'FAILED'} in ${Date.now() - t0}ms ` +
      `(${passed} passed, ${failures} failure${failures === 1 ? '' : 's'})`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main();
