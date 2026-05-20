/**
 * buildRecordedAuthForZap tests — translates the v2.1d recorded payload into
 * ZAP's browser-based AF auth method block. These tests pin the step-action
 * mapping (per the §Data Model table in the plan), the
 * internalIndexToZapIndex[] off-by-one when steps[0] is `goto`, and the
 * defense-in-depth rejection of mid-flow goto (the backend validator already
 * rejects it; we re-check here so a misbehaving caller can't slip it past).
 *
 * Run: npx tsx test/dast-recorded-auth.test.ts
 */

import {
  buildRecordedAuthForZap,
  type RecordedCredentialPayload,
  type RecordedStep,
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

function caught(fn: () => unknown): unknown {
  try {
    fn();
    return null;
  } catch (e) {
    return e;
  }
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
    username: 'alice@example.com',
    password: 'hunter2hunter2',
    ...overrides,
  };
}

function main(): void {
  const t0 = Date.now();
  console.log('buildRecordedAuthForZap tests\n');

  console.log('[1] base payload — 4-step username/password login');
  {
    const r = buildRecordedAuthForZap(basePayload());
    const auth = r.contextAuthentication;
    assert(auth.method === 'browser', `method=browser (got ${String(auth.method)})`);
    const params = auth.parameters as Record<string, unknown>;
    assert(
      params.loginPageUrl === 'https://app.example.com/login',
      `loginPageUrl pulled from steps[0].goto.value (got ${String(params.loginPageUrl)})`,
    );
    assert(params.browserId === 'firefox-headless', `browserId=firefox-headless`);
    // `diagnostics: true` was emitted on the assumption it would produce
    // per-step log events. The v2.1d empirical spike confirmed it's a
    // no-op in authhelper v0.39.0; the field is intentionally omitted.
    assert(
      params.diagnostics === undefined,
      `diagnostics field omitted (no-op in authhelper v0.39.0)`,
    );
    const steps = params.steps as Array<Record<string, unknown>>;
    assert(steps.length === 3, `goto collapsed; remaining 3 steps in ZAP list (got ${steps.length})`);
    assert(steps[0].type === 'USERNAME', `step 0 USERNAME`);
    assert(steps[1].type === 'PASSWORD', `step 1 PASSWORD`);
    assert(steps[2].type === 'CLICK', `step 2 CLICK`);
    assert(
      (steps[0] as Record<string, unknown>).cssSelector === '#email',
      `step 0 cssSelector=#email`,
    );
    // v2.1d empirical: ZAP silently drops the steps[] array unless
    // USERNAME/PASSWORD steps carry an explicit `value:` field.
    assert(
      (steps[0] as Record<string, unknown>).value === 'alice@example.com',
      `step 0 (USERNAME) carries payload.username as value:`,
    );
    assert(
      (steps[1] as Record<string, unknown>).value === 'hunter2hunter2',
      `step 1 (PASSWORD) carries payload.password as value:`,
    );
    assert(
      (steps[2] as Record<string, unknown>).value === undefined,
      `step 2 (CLICK) does NOT carry value (no field to type into)`,
    );
    // v2.1d empirical: ZAP's authhelper step-schema validator requires a
    // `description:` on every step or it silently drops the array.
    for (const [idx, s] of steps.entries()) {
      const sObj = s as Record<string, unknown>;
      assert(
        typeof sObj.description === 'string' && (sObj.description as string).length > 0,
        `step ${idx} carries a non-empty description: (got ${JSON.stringify(sObj.description)})`,
      );
    }
    assert(
      r.internalIndexToZapIndex.length === 4,
      `mapping length matches steps.length (got ${r.internalIndexToZapIndex.length})`,
    );
    assert(
      r.internalIndexToZapIndex[0] === -1,
      `UI step 0 (goto) → ZAP -1 (collapsed)`,
    );
    assert(
      r.internalIndexToZapIndex[1] === 0 &&
        r.internalIndexToZapIndex[2] === 1 &&
        r.internalIndexToZapIndex[3] === 2,
      `UI 1..3 → ZAP 0..2`,
    );
    assert(r.contextUsers.length === 1, `one user`);
    const creds = (r.contextUsers[0] as Record<string, unknown>).credentials as Record<string, unknown>;
    assert(creds.username === 'alice@example.com', `username pass-through`);
    assert(creds.password === 'hunter2hunter2', `password pass-through`);
    assert(creds.totp === undefined, `totp absent when secret not set`);
  }

  console.log('\n[2] action mapping table — every action emits the expected ZAP step type');
  {
    const variants: Array<{ payload: RecordedCredentialPayload; expected: string }> = [
      {
        payload: basePayload({ steps: [{ action: 'click', selector: '#x' }] }),
        expected: 'CLICK',
      },
      {
        payload: basePayload({ steps: [{ action: 'type_username', selector: '#u' }] }),
        expected: 'USERNAME',
      },
      {
        payload: basePayload({ steps: [{ action: 'type_password', selector: '#p' }] }),
        expected: 'PASSWORD',
      },
      {
        payload: basePayload({
          totp_secret: 'JBSWY3DPEHPK3PXP',
          steps: [{ action: 'type_totp', selector: '#otp' }],
        }),
        expected: 'TOTP_FIELD',
      },
      {
        payload: basePayload({
          steps: [{ action: 'type_custom', selector: '#x', value: 'org-deptex' }],
        }),
        expected: 'CUSTOM_FIELD',
      },
      {
        payload: basePayload({ steps: [{ action: 'wait', wait_ms: 250 }] }),
        expected: 'WAIT',
      },
      {
        payload: basePayload({ steps: [{ action: 'return' }] }),
        expected: 'RETURN',
      },
      {
        payload: basePayload({ steps: [{ action: 'escape' }] }),
        expected: 'ESCAPE',
      },
    ];
    for (const { payload, expected } of variants) {
      const r = buildRecordedAuthForZap(payload);
      const steps = (r.contextAuthentication.parameters as Record<string, unknown>).steps as Array<
        Record<string, unknown>
      >;
      assert(steps[0].type === expected, `${payload.steps[0].action} → ${expected} (got ${String(steps[0].type)})`);
    }
  }

  console.log('\n[3] xpath selector_kind emits `xpath`, not `cssSelector`');
  {
    const r = buildRecordedAuthForZap(
      basePayload({
        steps: [
          { action: 'click', selector: '//button[@type="submit"]', selector_kind: 'xpath' },
        ],
      }),
    );
    const step = ((r.contextAuthentication.parameters as Record<string, unknown>).steps as Array<
      Record<string, unknown>
    >)[0];
    assert(step.xpath === '//button[@type="submit"]', `step.xpath set`);
    assert(step.cssSelector === undefined, `step.cssSelector NOT set when xpath`);
  }

  console.log('\n[4] totp_secret threads to credentials.totp');
  {
    const r = buildRecordedAuthForZap(
      basePayload({
        totp_secret: 'JBSWY3DPEHPK3PXP',
        steps: [
          ...basePayload().steps,
          { action: 'type_totp', selector: '#otp' },
        ],
      }),
    );
    const creds = (r.contextUsers[0] as Record<string, unknown>).credentials as Record<string, unknown>;
    assert(creds.totp === 'JBSWY3DPEHPK3PXP', `credentials.totp == secret`);
  }

  console.log('\n[5] verification block carries loggedInRegex / loggedOutRegex when provided');
  {
    const r = buildRecordedAuthForZap(basePayload(), 'Sign out', 'Login');
    const verification = r.contextAuthentication.verification as Record<string, unknown>;
    assert(verification.loggedInRegex === 'Sign out', `loggedInRegex passed through`);
    assert(verification.loggedOutRegex === 'Login', `loggedOutRegex passed through`);
  }

  console.log('\n[6] mid-flow goto rejected (defense-in-depth on top of backend validator)');
  {
    const err = caught(() =>
      buildRecordedAuthForZap(
        basePayload({
          steps: [
            { action: 'click', selector: '#enter' },
            { action: 'goto', value: 'https://app.example.com/page2' },
          ],
        }),
      ),
    ) as Error | null;
    assert(err !== null, `threw on mid-flow goto`);
    assert(
      err !== null && /'goto' only valid as steps\[0\]/.test(err.message),
      `error message identifies the rule (got: ${err?.message})`,
    );
  }

  console.log('\n[7] determinism — same input produces same internalIndexToZapIndex[]');
  {
    const p = basePayload({
      steps: [
        { action: 'goto', value: 'https://app.example.com/login' },
        { action: 'type_username', selector: '#email' },
        { action: 'wait', wait_ms: 500 },
        { action: 'type_password', selector: '#pass' },
        { action: 'click', selector: 'button[type=submit]' },
      ],
    });
    const r1 = buildRecordedAuthForZap(p);
    const r2 = buildRecordedAuthForZap(p);
    assert(
      JSON.stringify(r1.internalIndexToZapIndex) === JSON.stringify(r2.internalIndexToZapIndex),
      `mapping deterministic across calls`,
    );
    assert(
      JSON.stringify(r1.internalIndexToZapIndex) === '[-1,0,1,2,3]',
      `expected [-1,0,1,2,3] (got ${JSON.stringify(r1.internalIndexToZapIndex)})`,
    );
  }

  console.log('\n[8] login_page_wait_ms / step_delay_ms → seconds (rounded)');
  {
    const r = buildRecordedAuthForZap(
      basePayload({
        login_page_wait_ms: 7500, // -> round to 8s
        step_delay_ms: 1500, // -> round to 2s
      }),
    );
    const params = r.contextAuthentication.parameters as Record<string, unknown>;
    assert(params.loginPageWait === 8, `7500ms → 8s (got ${String(params.loginPageWait)})`);
    assert(params.stepDelay === 2, `1500ms → 2s (got ${String(params.stepDelay)})`);
  }

  console.log('\n[9] missing selector on type_username throws');
  {
    const err = caught(() =>
      buildRecordedAuthForZap(
        basePayload({
          steps: [{ action: 'type_username' } as RecordedStep],
        }),
      ),
    ) as Error | null;
    assert(err !== null && /requires a selector/.test(err.message), `threw requires a selector`);
  }

  console.log('\n[10] zero non-goto steps throws (no meaningful login)');
  {
    const err = caught(() =>
      buildRecordedAuthForZap(
        basePayload({
          steps: [{ action: 'goto', value: 'https://app.example.com/login' }],
        }),
      ),
    ) as Error | null;
    assert(
      err !== null && /at least one non-goto step/.test(err.message),
      `threw at-least-one-non-goto`,
    );
  }

  const t1 = Date.now();
  console.log(`\n${passed} passed, ${failures} failed (${t1 - t0}ms)`);
  if (failures > 0) {
    process.exit(1);
  }
}

main();
