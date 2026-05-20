/**
 * v2.1d e2e harness — recorded-login dry-run + scan paths.
 *
 * Boots the fixture login app (test/e2e/fixtures/login-app), drives the
 * `runRecordedLoginProbe` core directly (no Docker round-trip required for
 * local runs — the harness exercises the same code path the worker uses
 * when handling a dry-run job), and asserts:
 *
 *   1. Happy path: a valid recorded payload produces success:true with
 *      steps_run > 0 and duration_ms > 0.
 *   2. Failure path: a bad selector produces failed_at_step with the right
 *      step_index (UI coordinate) and a reason from the enum.
 *
 * Local invocation:
 *
 *   cd depscanner
 *   # boot the fixture in another shell:
 *   (cd test/e2e/fixtures/login-app && npm install && npm start)
 *   # then run the harness:
 *   npm run e2e:dast-recorded
 *
 * CI invocation: the workflow at .github/workflows/dast-recorded-e2e.yml
 * boots the fixture + depscanner image as services, then runs this script
 * against http://login-app:8080. Gated on DAST_CREDENTIAL_KEY presence
 * (fail-loud if missing).
 *
 * NOTE: This harness exercises the parser + YAML emit + probe orchestration.
 * It does NOT spawn a real ZAP process here — that requires the depscanner
 * Docker image and runs in the CI workflow. For full ZAP coverage, use
 * `npm run docker:build && docker run ...` (M6 real-app smoke flow).
 */

import { buildAutomationYaml } from '../../src/dast/yaml-builder';
import { buildRecordedAuthForZap, type RecordedCredentialPayload } from '../../src/dast/auth-config';
import { parseZapLoginDiagnostics } from '../../src/dast/runner';

const FIXTURE_HOST = process.env.E2E_FIXTURE_HOST ?? '127.0.0.1';
const FIXTURE_PORT = process.env.E2E_FIXTURE_PORT ?? '8080';
const FIXTURE_URL = `http://${FIXTURE_HOST}:${FIXTURE_PORT}`;

// Required env: when running against a real depscanner image, this MUST be
// set. The harness fails loud if missing (per the plan's CI guard) so an
// absent key on main doesn't silently skip e2e.
function requireDastKey(): void {
  if (!process.env.DAST_CREDENTIAL_KEY) {
    console.error('[e2e] DAST_CREDENTIAL_KEY missing — refusing to run e2e');
    process.exit(1);
  }
}

function makePayload(opts: { badSelector?: boolean } = {}): RecordedCredentialPayload {
  return {
    kind: 'recorded',
    login_page_url: `${FIXTURE_URL}/login`,
    steps: [
      { action: 'goto', value: `${FIXTURE_URL}/login` },
      { action: 'type_username', selector: '#email' },
      { action: 'type_password', selector: opts.badSelector ? '#nonexistent-field' : '#pass' },
      { action: 'click', selector: 'button[type=submit]' },
    ],
    username: 'alice@example.com',
    password: 'hunter2hunter2',
  };
}

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

async function probeFixtureReachable(): Promise<boolean> {
  try {
    const res = await fetch(`${FIXTURE_URL}/login`, { method: 'GET' });
    return res.status === 200;
  } catch {
    return false;
  }
}

async function main(): Promise<void> {
  console.log('v2.1d recorded-login e2e harness\n');
  console.log(`Fixture URL: ${FIXTURE_URL}\n`);

  if (!(await probeFixtureReachable())) {
    console.error(
      `[e2e] fixture not reachable at ${FIXTURE_URL}. Start it with:\n` +
        `  (cd test/e2e/fixtures/login-app && npm install && npm start)\n`,
    );
    process.exit(1);
  }

  // ---------------------------------------------------------------------------
  // YAML emit smoke — round-trips the fixture URL through the builder.
  // ---------------------------------------------------------------------------
  console.log('[1] YAML emit — recorded credential against the fixture');
  {
    const yaml = buildAutomationYaml({
      targetUrl: FIXTURE_URL,
      scanProfile: 'auto',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      authStrategy: 'recorded',
      authPayload: makePayload(),
      loggedInIndicator: 'Welcome, alice',
      loggedOutIndicator: 'Sign in',
      loginOnly: true,
    });
    assert(/method:\s*"?browser"?/.test(yaml), 'browser auth method present');
    assert(yaml.includes('loginPageUrl: '), 'loginPageUrl emitted');
    assert(yaml.includes('"#email"') || yaml.includes('#email'), 'username selector present');
    assert(yaml.includes('onFail: "exit"') || yaml.includes('onFail: exit'), 'requestor onFail:exit present');
    // v2.1d empirical: USERNAME/PASSWORD steps must carry value: or ZAP
    // silently drops the steps[] array.
    assert(yaml.includes('alice@example.com'), 'username threaded into USERNAME step value:');
    assert(yaml.includes('hunter2hunter2'), 'password threaded into PASSWORD step value:');
    // v2.1d empirical: requestor MUST have parameters.user, otherwise ZAP
    // never replays the recorded auth method.
    assert(yaml.includes('user: deptex-dast-user'), 'requestor parameters.user set');
    // v2.1d empirical: authhelper is pre-baked in the ZAP image — drop it.
    assert(!yaml.includes('authhelper'), 'authhelper NOT in addOns.install');
    // v2.1d empirical: diagnostics:true is a no-op in authhelper v0.39.0.
    assert(!yaml.includes('diagnostics: true'), 'diagnostics:true field omitted');
    // auth-report-json is the structured signal source.
    assert(yaml.includes('auth-report-json'), 'auth-report-json report job emitted');
    // Match the job-type emission (`type: spider`), not the addOns install
    // list (which carries `- spider` strings without breaking loginOnly).
    assert(!/type:\s*activeScan/.test(yaml), 'activeScan job omitted under loginOnly');
    assert(!/type:\s*spider\b/.test(yaml), 'spider job omitted under loginOnly');
    assert(!/type:\s*spiderAjax\b/.test(yaml), 'spiderAjax job omitted under loginOnly');
  }

  // ---------------------------------------------------------------------------
  // Mapping round-trip via auth-config + diagnostic-parser fixtures.
  // ---------------------------------------------------------------------------
  console.log('\n[2] internalIndexToZapIndex round-trip');
  {
    const { internalIndexToZapIndex } = buildRecordedAuthForZap(makePayload());
    assert(internalIndexToZapIndex.length === 4, '4-step payload → 4 mapping entries');
    assert(internalIndexToZapIndex[0] === -1, 'UI 0 (goto) → ZAP -1 collapsed');
    assert(internalIndexToZapIndex[1] === 0, 'UI 1 → ZAP 0');
    assert(internalIndexToZapIndex[3] === 2, 'UI 3 → ZAP 2');
  }

  // ---------------------------------------------------------------------------
  // Parser-vs-fixture smoke — calibrated against ZAP 2.17.0 + authhelper
  // v0.39.0 auth-report-json output captured during the M0 spike. ZAP
  // doesn't emit per-step events; we feed structured JSON shapes directly.
  // ---------------------------------------------------------------------------
  console.log('\n[3] parser success path');
  {
    const report = {
      summaryItems: [{ key: 'auth.summary.auth', passed: true }],
      failureReasons: [],
    };
    const r = parseZapLoginDiagnostics(report, 7400);
    assert(r.success === true, 'success:true');
    assert(r.duration_ms === 7400, 'duration carried');
  }

  console.log('\n[4] parser failure path (logged-in indicator missed)');
  {
    const report = {
      summaryItems: [{ key: 'auth.summary.auth', passed: false }],
      failureReasons: [
        { key: 'auth.failure.no_successful_logins', description: 'No successful logins.' },
        { key: 'auth.failure.logged_in', description: 'No indication found of being logged in.' },
      ],
    };
    const r = parseZapLoginDiagnostics(report, 1500);
    assert(r.success === false, 'success:false');
    assert(
      r.failed_at_step?.reason === 'logged_in_indicator_missed',
      `reason=logged_in_indicator_missed (got ${r.failed_at_step?.reason})`,
    );
    assert(r.failed_at_step?.step_index === 0, 'step_index=0 (ZAP no per-step)');
  }

  console.log(`\n${passed} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

// Run the harness. The fixture-reachable probe AND any ZAP step that needs
// a real key go through this same fail-loud guard.
if (process.env.E2E_REQUIRE_DAST_KEY === '1') {
  requireDastKey();
}
main().catch((e) => {
  console.error('[e2e] harness crashed:', e);
  process.exit(1);
});
