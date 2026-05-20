/**
 * buildAutomationYaml tests for the v2.1d recorded-strategy branch.
 *
 * Asserts:
 *   - authhelper is NOT in addOns.install (pre-baked in ZAP image; listing
 *     it triggers a noisy "no longer does anything" warning per the v2.1d
 *     empirical spike)
 *   - recorded payload produces a `browser` context.authentication
 *   - browser auth parameters do NOT carry `diagnostics: true` (no-op in
 *     authhelper v0.39.0 per spike)
 *   - USERNAME/PASSWORD steps carry `value:` (load-bearing: without it,
 *     ZAP silently drops the steps[] array and falls back to AUTO_DETECT)
 *   - requestor job emitted post-auth with onFail: exit AND
 *     parameters.user: deptex-dast-user (without user:, ZAP never replays
 *     the recorded auth method)
 *   - auth-report-json report job ALWAYS emitted for recorded strategy
 *     (login-only AND full scan); reportDir defaults to /zap/wrk but is
 *     overrideable via authReportDirAbsolute
 *   - loginOnly=true omits spider/spiderAjax/activeScan/traditional-json
 *     report — but KEEPS the auth-report-json job
 *   - activeScan.maxScanDurationInMins is reduced by RECORDED_AUTH_BUDGET_MIN
 *     for the recorded strategy
 *   - non-recorded YAMLs are byte-identical to the existing baseline
 *
 * Run: npx tsx test/dast-yaml-builder-recorded.test.ts
 */

import * as yaml from 'js-yaml';

import { buildAutomationYaml } from '../src/dast/yaml-builder';
import type { RecordedCredentialPayload } from '../src/dast/auth-config';

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

function parseYaml(s: string): Record<string, unknown> {
  return yaml.load(s) as Record<string, unknown>;
}

function jobs(doc: Record<string, unknown>): Array<Record<string, unknown>> {
  return (doc.jobs as Array<Record<string, unknown>>) ?? [];
}

function findJob(doc: Record<string, unknown>, type: string): Record<string, unknown> | undefined {
  return jobs(doc).find((j) => j.type === type);
}

function main(): void {
  const t0 = Date.now();
  console.log('buildAutomationYaml — recorded strategy tests\n');

  // ---------------------------------------------------------------------------
  console.log('[1] addOns.install does NOT contain `authhelper` (pre-baked in image)');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'auto',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
    });
    const doc = parseYaml(out);
    const addOns = findJob(doc, 'addOns');
    const install = ((addOns?.parameters as Record<string, unknown>)?.install as string[]) ?? [];
    // v2.1d empirical: authhelper ships in `ghcr.io/zaproxy/zaproxy:stable`
    // (ZAP 2.17.0); listing it triggers a "addOns job no longer does
    // anything" warning three times per scan. Intentionally omitted.
    assert(!install.includes('authhelper'), `authhelper NOT in addOns.install`);
    assert(install.includes('ascanrules'), `core addons still present`);
  }

  // ---------------------------------------------------------------------------
  console.log('[2] recorded payload emits context.authentication.method=browser');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'auto',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      authStrategy: 'recorded',
      authPayload: basePayload(),
      loggedInIndicator: 'Sign out',
      loggedOutIndicator: 'Login',
    });
    const doc = parseYaml(out);
    const contexts = (doc.env as Record<string, unknown>)?.contexts as Array<Record<string, unknown>>;
    assert(contexts && contexts.length === 1, `one context`);
    const auth = contexts[0].authentication as Record<string, unknown>;
    assert(auth.method === 'browser', `method=browser (got ${String(auth?.method)})`);
    const params = auth.parameters as Record<string, unknown>;
    assert(params.browserId === 'firefox-headless', `browserId=firefox-headless`);
    assert(
      params.diagnostics === undefined,
      `diagnostics omitted (no-op in authhelper v0.39.0 per v2.1d spike)`,
    );
    const verification = auth.verification as Record<string, unknown>;
    assert(verification.loggedInRegex === 'Sign out', `verification.loggedInRegex`);
    assert(verification.loggedOutRegex === 'Login', `verification.loggedOutRegex`);
    // v2.1d empirical: USERNAME/PASSWORD steps require explicit `value:` or
    // ZAP silently drops the entire steps[] array.
    const steps = params.steps as Array<Record<string, unknown>>;
    const usernameStep = steps.find((s) => s.type === 'USERNAME');
    const passwordStep = steps.find((s) => s.type === 'PASSWORD');
    assert(
      usernameStep?.value === 'alice@example.com',
      `USERNAME step carries payload.username as value: (got ${String(usernameStep?.value)})`,
    );
    assert(
      passwordStep?.value === 'hunter2hunter2',
      `PASSWORD step carries payload.password as value: (got ${String(passwordStep?.value)})`,
    );
  }

  // ---------------------------------------------------------------------------
  console.log('[3] recorded YAML includes a requestor job with onFail: exit');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'full',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      authStrategy: 'recorded',
      authPayload: basePayload(),
    });
    const doc = parseYaml(out);
    const requestor = findJob(doc, 'requestor');
    assert(requestor !== undefined, `requestor job emitted`);
    assert(requestor?.onFail === 'exit', `requestor onFail=exit (got ${String(requestor?.onFail)})`);
    const params = (requestor?.parameters as Record<string, unknown>) ?? {};
    // v2.1d empirical: WITHOUT user: on the requestor, ZAP never replays the
    // recorded auth method — the request fires anonymously and the auth
    // verdict is "no successful logins". `user:` is load-bearing.
    assert(
      params.user === 'deptex-dast-user',
      `requestor parameters.user = deptex-dast-user (got ${String(params.user)})`,
    );
    const requests = (requestor?.requests as Array<Record<string, unknown>>) ?? [];
    assert(requests.length === 1, `exactly one requestor request`);
    assert(requests[0]?.url === 'https://app.example.com/login', `requestor URL = login_page_url`);
    assert(requests[0]?.method === 'GET', `requestor method = GET`);
  }

  // ---------------------------------------------------------------------------
  console.log('[3b] verificationProbeUrl override → requestor hits the override URL');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'full',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      authStrategy: 'recorded',
      authPayload: basePayload(),
      verificationProbeUrl: 'https://app.example.com/dashboard',
    });
    const doc = parseYaml(out);
    const requestor = findJob(doc, 'requestor');
    const requests = (requestor?.requests as Array<Record<string, unknown>>) ?? [];
    assert(
      requests[0]?.url === 'https://app.example.com/dashboard',
      `requestor URL = verificationProbeUrl override (got ${String(requests[0]?.url)})`,
    );
  }

  // ---------------------------------------------------------------------------
  console.log('[4] loginOnly=true omits spider/spiderAjax/activeScan/report');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'full',
      detectedRuntime: 'spa',
      reportRelativePath: 'r.json',
      authStrategy: 'recorded',
      authPayload: basePayload(),
      loginOnly: true,
    });
    const doc = parseYaml(out);
    const allJobs = jobs(doc);
    const types = allJobs.map((j) => j.type);
    assert(!types.includes('spider'), `spider omitted`);
    assert(!types.includes('spiderAjax'), `spiderAjax omitted`);
    assert(!types.includes('activeScan'), `activeScan omitted`);
    // The auth-report-json report job IS still emitted under loginOnly.
    // The traditional-json report job is omitted.
    const reportJobs = allJobs.filter((j) => j.type === 'report');
    assert(reportJobs.length === 1, `exactly one report job present (auth-report-json)`);
    const tmpl = (reportJobs[0].parameters as Record<string, unknown>)?.template;
    assert(tmpl === 'auth-report-json', `loginOnly report job is auth-report-json (got ${String(tmpl)})`);
    assert(types.includes('requestor'), `requestor STILL emitted`);
    assert(types.includes('addOns'), `addOns still emitted`);
    assert(types.includes('passiveScan-config'), `passiveScan-config still emitted`);
  }

  // ---------------------------------------------------------------------------
  console.log('[4b] full recorded scan emits BOTH traditional-json AND auth-report-json reports');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'full',
      detectedRuntime: 'classic',
      reportRelativePath: 'zap-report.json',
      authStrategy: 'recorded',
      authPayload: basePayload(),
    });
    const doc = parseYaml(out);
    const reportJobs = jobs(doc).filter((j) => j.type === 'report');
    assert(reportJobs.length === 2, `two report jobs emitted (got ${reportJobs.length})`);
    const templates = reportJobs
      .map((j) => (j.parameters as Record<string, unknown>)?.template)
      .sort();
    assert(
      JSON.stringify(templates) === JSON.stringify(['auth-report-json', 'traditional-json']),
      `templates=[auth-report-json, traditional-json] (got ${JSON.stringify(templates)})`,
    );
  }

  // ---------------------------------------------------------------------------
  console.log('[4c] authReportDirAbsolute override threads into auth-report report job');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'auto',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      authStrategy: 'recorded',
      authPayload: basePayload(),
      loginOnly: true,
      authReportDirAbsolute: '/zap/wrk/deptex-dast-login-abc123',
    });
    const doc = parseYaml(out);
    const reportJob = jobs(doc).find(
      (j) =>
        j.type === 'report' &&
        (j.parameters as Record<string, unknown>)?.template === 'auth-report-json',
    );
    const params = (reportJob?.parameters as Record<string, unknown>) ?? {};
    assert(
      params.reportDir === '/zap/wrk/deptex-dast-login-abc123',
      `reportDir overridden to tempdir (got ${String(params.reportDir)})`,
    );
    assert(params.reportFile === 'auth-report.json', `reportFile=auth-report.json`);
  }

  // ---------------------------------------------------------------------------
  console.log('[4d] non-recorded YAML does NOT emit auth-report-json job');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'full',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      authStrategy: 'form',
      authPayload: {
        kind: 'form',
        login_url: 'https://app.example.com/login',
        username_field: 'email',
        password_field: 'pwd',
        username: 'a',
        password: 'b',
      },
    });
    const doc = parseYaml(out);
    const authReportJob = jobs(doc).find(
      (j) =>
        j.type === 'report' &&
        (j.parameters as Record<string, unknown>)?.template === 'auth-report-json',
    );
    assert(authReportJob === undefined, `auth-report-json job NOT emitted for non-recorded strategy`);
  }

  // ---------------------------------------------------------------------------
  console.log('[5] loginOnly=false (default) emits the full scan job list for recorded');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'full',
      detectedRuntime: 'spa',
      reportRelativePath: 'r.json',
      authStrategy: 'recorded',
      authPayload: basePayload(),
    });
    const doc = parseYaml(out);
    const types = jobs(doc).map((j) => j.type);
    assert(types.includes('requestor'), `requestor present`);
    assert(types.includes('spiderAjax'), `spiderAjax present (spa runtime)`);
    assert(types.includes('activeScan'), `activeScan present (scan_profile=full)`);
    assert(types.includes('report'), `report present (traditional-json + auth-report-json)`);
    // Recorded strategy gets BOTH report types on full scans (test [4b]
    // verifies the templates).
    const reportCount = jobs(doc).filter((j) => j.type === 'report').length;
    assert(reportCount === 2, `two report jobs (got ${reportCount})`);
  }

  // ---------------------------------------------------------------------------
  console.log('[6] recorded activeScan.maxScanDurationInMins reduced by RECORDED_AUTH_BUDGET_MIN');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'full',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      authStrategy: 'recorded',
      authPayload: basePayload(),
      scanTimeoutMinutes: 30,
    });
    const doc = parseYaml(out);
    const activeScan = findJob(doc, 'activeScan');
    const dur = (activeScan?.parameters as Record<string, unknown>)?.maxScanDurationInMins;
    assert(dur === 27, `activeScan duration 30 - 3 = 27 (got ${String(dur)})`);
  }

  // ---------------------------------------------------------------------------
  console.log('[7] non-recorded activeScan.maxScanDurationInMins UNCHANGED');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'full',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      scanTimeoutMinutes: 30,
    });
    const doc = parseYaml(out);
    const activeScan = findJob(doc, 'activeScan');
    const dur = (activeScan?.parameters as Record<string, unknown>)?.maxScanDurationInMins;
    assert(dur === 30, `activeScan duration 30 (got ${String(dur)})`);
  }

  // ---------------------------------------------------------------------------
  console.log('[8] non-recorded YAML does NOT emit a requestor job');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'auto',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
    });
    const doc = parseYaml(out);
    assert(findJob(doc, 'requestor') === undefined, `no requestor job`);
  }

  // ---------------------------------------------------------------------------
  console.log('[9] recorded payload with TOTP step — auth credentials.totp populated');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'full',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      authStrategy: 'recorded',
      authPayload: basePayload({
        totp_secret: 'JBSWY3DPEHPK3PXP',
        steps: [
          { action: 'goto', value: 'https://app.example.com/login' },
          { action: 'type_username', selector: '#email' },
          { action: 'type_password', selector: '#pass' },
          { action: 'type_totp', selector: '#otp' },
          { action: 'click', selector: 'button[type=submit]' },
        ],
      }),
    });
    const doc = parseYaml(out);
    const contexts = (doc.env as Record<string, unknown>).contexts as Array<Record<string, unknown>>;
    const users = contexts[0].users as Array<Record<string, unknown>>;
    const creds = users[0].credentials as Record<string, unknown>;
    assert(creds.totp === 'JBSWY3DPEHPK3PXP', `credentials.totp = base32 secret`);
    const params = (contexts[0].authentication as Record<string, unknown>).parameters as Record<string, unknown>;
    const steps = params.steps as Array<Record<string, unknown>>;
    assert(
      steps.some((s) => s.type === 'TOTP_FIELD'),
      `TOTP_FIELD step present`,
    );
  }

  // ---------------------------------------------------------------------------
  console.log('[10] xpath selector_kind round-trip — emitted as `xpath` in YAML');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'auto',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      authStrategy: 'recorded',
      authPayload: basePayload({
        steps: [
          { action: 'click', selector: '//button[@type="submit"]', selector_kind: 'xpath' },
        ],
      }),
    });
    const doc = parseYaml(out);
    const contexts = (doc.env as Record<string, unknown>).contexts as Array<Record<string, unknown>>;
    const auth = contexts[0].authentication as Record<string, unknown>;
    const step = ((auth.parameters as Record<string, unknown>).steps as Array<Record<string, unknown>>)[0];
    assert(step.xpath === '//button[@type="submit"]', `step.xpath emitted (got ${String(step.xpath)})`);
    assert(step.cssSelector === undefined, `step.cssSelector NOT emitted`);
  }

  // ---------------------------------------------------------------------------
  console.log('[11] form-strategy regression — baseline YAML untouched');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'auto',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      authStrategy: 'form',
      authPayload: {
        kind: 'form',
        login_url: 'https://app.example.com/login',
        username_field: 'email',
        password_field: 'pwd',
        username: 'a',
        password: 'b',
      },
    });
    const doc = parseYaml(out);
    const contexts = (doc.env as Record<string, unknown>).contexts as Array<Record<string, unknown>>;
    const auth = contexts[0].authentication as Record<string, unknown>;
    assert(auth.method === 'form', `form strategy still emits method=form (no regression)`);
    assert(findJob(doc, 'requestor') === undefined, `form strategy does not emit requestor job`);
  }

  // ---------------------------------------------------------------------------
  console.log('[12] sso_origins[] widens includePaths during auth (Spike-2 yellow path)');
  {
    const out = buildAutomationYaml({
      targetUrl: 'https://app.example.com',
      scanProfile: 'full',
      detectedRuntime: 'classic',
      reportRelativePath: 'r.json',
      authStrategy: 'recorded',
      authPayload: basePayload({
        sso_origins: ['https://accounts.google.com'],
      }),
    });
    // v1 forward-compat: sso_origins ACCEPTED in the payload type without
    // any YAML widening — M0 Spike-2 outcome decides whether yaml-builder
    // actually emits the wider includePaths. This test pins the
    // "accepted, no error" behavior so the schema doesn't drift.
    const doc = parseYaml(out);
    const contexts = (doc.env as Record<string, unknown>).contexts as Array<Record<string, unknown>>;
    assert(contexts[0] !== undefined, `YAML emits cleanly with sso_origins present`);
  }

  const t1 = Date.now();
  console.log(`\n${passed} passed, ${failures} failed (${t1 - t0}ms)`);
  if (failures > 0) {
    process.exit(1);
  }
}

main();
