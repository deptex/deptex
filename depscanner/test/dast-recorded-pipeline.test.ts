/**
 * parseZapLoginDiagnostics tests — calibrated against ZAP's `auth-report-json`
 * report template (the only structured signal ZAP browser-auth exposes).
 *
 * The empirical v2.1d M0 spike against ZAP 2.17.0 + authhelper v0.39.0
 * confirmed that ZAP does NOT emit per-step success/failure events to
 * stderr / stdout / zap.log. The auth verdict lives entirely in the
 * auth-report.json file. These cases lock the parser contract against:
 *
 *   - real captured failure fixture (logged_in_indicator_missed)
 *   - fabricated success fixture (mutate captured one: passed=true,
 *     empty failureReasons)
 *   - missing / null report → browser_crashed
 *   - non-object payload → unknown
 *   - afPlanErrors[] non-empty → unknown with detail
 *   - failureReasons[] mapping table — known keys → reason enum
 *   - rolled-up auth.failure.no_successful_logins skipped in favor of
 *     more specific entries
 *   - secret redaction grid — every output string field is run through
 *     redactCredentials so a captured value can't leak to the FE
 *
 * Run: npx tsx test/dast-recorded-pipeline.test.ts
 */

import * as fs from 'fs';
import * as path from 'path';

import {
  parseZapLoginDiagnostics,
  redactCredentials,
  type ZapAuthReport,
} from '../src/dast/runner';

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

const FIXTURE_DIR = path.join(
  __dirname,
  'fixtures',
  'zap-login-diagnostics',
  '2.17.0',
);

function loadFixture(name: string): ZapAuthReport {
  const raw = fs.readFileSync(path.join(FIXTURE_DIR, name), { encoding: 'utf-8' });
  return JSON.parse(raw) as ZapAuthReport;
}

/**
 * Fabricate a success-case auth-report by mutating the captured failure
 * fixture. The resume plan explicitly authorizes this approach — capturing
 * a real success-case fixture requires a login-app the fixture's click step
 * doesn't trip Selenium's stale-element on, and the success shape is
 * deterministically the inverse of the failure shape (passed=true,
 * empty failureReasons).
 */
function fabricateSuccessReport(): ZapAuthReport {
  const base = loadFixture('auth-report-failure-logged-in-missed.json');
  const summary = (base.summaryItems ?? []).map((s) => ({ ...s }));
  const authItem = summary.find((s) => s.key === 'auth.summary.auth');
  if (authItem) authItem.passed = true;
  return {
    ...base,
    summaryItems: summary,
    failureReasons: [],
    afPlanErrors: [],
  };
}

function main(): void {
  const t0 = Date.now();
  console.log('parseZapLoginDiagnostics (auth-report-json shape) tests\n');

  // ---------------------------------------------------------------------------
  console.log('[1] real captured failure fixture → logged_in_indicator_missed');
  {
    const report = loadFixture('auth-report-failure-logged-in-missed.json');
    const r = parseZapLoginDiagnostics(report, 17_000);
    assert(r.success === false, `success:false on captured failure`);
    assert(r.duration_ms === 17_000, `duration_ms passes through`);
    assert(r.failed_at_step !== undefined, `failed_at_step populated`);
    assert(
      r.failed_at_step?.reason === 'logged_in_indicator_missed',
      `reason=logged_in_indicator_missed (got ${r.failed_at_step?.reason})`,
    );
    assert(
      r.failed_at_step?.step_index === 0,
      `step_index=0 (ZAP doesn't expose per-step failure; got ${r.failed_at_step?.step_index})`,
    );
  }

  // ---------------------------------------------------------------------------
  console.log('[2] fabricated success → success:true, no failed_at_step');
  {
    const r = parseZapLoginDiagnostics(fabricateSuccessReport(), 7400);
    assert(r.success === true, `success:true`);
    assert(r.failed_at_step === undefined, `no failed_at_step on success`);
    assert(r.duration_ms === 7400, `duration_ms passes through`);
    assert(r.steps_run === 0, `steps_run=0 (ZAP doesn't expose per-step counts)`);
  }

  // ---------------------------------------------------------------------------
  console.log('[3] null report (file missing) → browser_crashed');
  {
    const r = parseZapLoginDiagnostics(null, 2000);
    assert(r.success === false, `success:false`);
    assert(
      r.failed_at_step?.reason === 'browser_crashed',
      `reason=browser_crashed on missing report`,
    );
    assert(
      r.failed_at_step?.detail?.includes('missing'),
      `detail mentions missing report`,
    );
  }

  // ---------------------------------------------------------------------------
  console.log('[4] non-object payload → unknown');
  {
    const r = parseZapLoginDiagnostics('not an object', 1000);
    assert(r.success === false, `success:false on string payload`);
    assert(r.failed_at_step?.reason === 'unknown', `reason=unknown`);
  }

  // ---------------------------------------------------------------------------
  console.log('[5] afPlanErrors[] non-empty → unknown + AF plan error detail');
  {
    const report: ZapAuthReport = {
      summaryItems: [],
      failureReasons: [],
      afPlanErrors: [{ description: 'requestor: user "deptex-dast-user" not found' }],
    };
    const r = parseZapLoginDiagnostics(report, 500);
    assert(r.success === false, `success:false`);
    assert(r.failed_at_step?.reason === 'unknown', `reason=unknown for AF plan errors`);
    assert(
      r.failed_at_step?.detail?.includes('AF plan error'),
      `detail mentions AF plan error (got: ${r.failed_at_step?.detail})`,
    );
  }

  // ---------------------------------------------------------------------------
  console.log('[6] afPlanErrors[] as bare strings (alternate ZAP shape)');
  {
    const report: ZapAuthReport = {
      summaryItems: [],
      failureReasons: [],
      afPlanErrors: ['Unknown job type: requestorrr' as unknown as { description?: string }],
    };
    const r = parseZapLoginDiagnostics(report);
    assert(r.success === false, `success:false`);
    assert(
      r.failed_at_step?.detail?.includes('Unknown job type'),
      `string-shaped AF plan error surfaces as detail`,
    );
  }

  // ---------------------------------------------------------------------------
  console.log('[7] failureReasons key → reason enum mapping');
  {
    const cases: Array<{ key: string; expected: string }> = [
      { key: 'auth.failure.logged_in', expected: 'logged_in_indicator_missed' },
      { key: 'auth.failure.logged_out', expected: 'logged_out_indicator_present_after_login' },
      { key: 'auth.failure.username', expected: 'selector_not_visible_after_timeout' },
      { key: 'auth.failure.password', expected: 'selector_not_visible_after_timeout' },
    ];
    for (const c of cases) {
      const report: ZapAuthReport = {
        summaryItems: [{ key: 'auth.summary.auth', passed: false, description: 'Authentication failed' }],
        failureReasons: [{ key: c.key, description: 'desc' }],
      };
      const r = parseZapLoginDiagnostics(report);
      assert(
        r.failed_at_step?.reason === c.expected,
        `${c.key} → ${c.expected} (got ${r.failed_at_step?.reason})`,
      );
    }
  }

  // ---------------------------------------------------------------------------
  console.log('[8] no_successful_logins skipped in favor of more specific reason');
  {
    const report: ZapAuthReport = {
      summaryItems: [{ key: 'auth.summary.auth', passed: false }],
      failureReasons: [
        { key: 'auth.failure.no_successful_logins', description: 'No successful logins.' },
        { key: 'auth.failure.logged_in', description: 'No indication of being logged in.' },
      ],
    };
    const r = parseZapLoginDiagnostics(report);
    assert(
      r.failed_at_step?.reason === 'logged_in_indicator_missed',
      `picks logged_in over the no_successful_logins roll-up`,
    );
  }

  // ---------------------------------------------------------------------------
  console.log('[9] unmapped failureReason → unknown + detail surfaces description');
  {
    const report: ZapAuthReport = {
      summaryItems: [{ key: 'auth.summary.auth', passed: false }],
      failureReasons: [{ key: 'auth.failure.experimental_thing', description: 'some new ZAP shape' }],
    };
    const r = parseZapLoginDiagnostics(report);
    assert(r.failed_at_step?.reason === 'unknown', `reason=unknown for unmapped key`);
    assert(
      r.failed_at_step?.detail === 'some new ZAP shape',
      `detail surfaces description (got: ${r.failed_at_step?.detail})`,
    );
  }

  // ---------------------------------------------------------------------------
  console.log('[10] failed auth with empty failureReasons → unknown + raw_log');
  {
    const report: ZapAuthReport = {
      summaryItems: [{ key: 'auth.summary.auth', passed: false }],
      failureReasons: [],
    };
    const r = parseZapLoginDiagnostics(report, 1500);
    assert(r.success === false, `success:false when auth.summary.auth false even w/ empty reasons`);
    assert(r.failed_at_step?.reason === 'unknown', `reason=unknown`);
    assert(typeof r.raw_log === 'string', `raw_log populated with summary+failures JSON`);
  }

  // ---------------------------------------------------------------------------
  console.log('[11] secret redaction grid — patterns scrubbed in detail and raw_log');
  {
    const password = 'hunter2hunter2';
    const bearer = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature1234567890';
    const report: ZapAuthReport = {
      summaryItems: [{ key: 'auth.summary.auth', passed: false }],
      failureReasons: [
        {
          key: 'auth.failure.logged_in',
          description: `Verification probe saw Bearer ${bearer}; password=${password} echoed back`,
        },
      ],
    };
    const r = parseZapLoginDiagnostics(report);
    const surface = (r.raw_log ?? '') + JSON.stringify(r);
    assert(!surface.includes(password), `password= value redacted from output`);
    assert(!surface.includes(bearer.slice(20)), `Bearer token redacted`);
  }

  // ---------------------------------------------------------------------------
  console.log('[12] redactCredentials inverse smoke — hits the worker-emitted formats');
  {
    const samples: Array<[string, string]> = [
      ['Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIi.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'Bearer'],
      ['password=hunter2hunter2 next=...', 'password='],
      ['api_key=ABCDEFGHIJK01234567890 next=...', 'api_key='],
      ['Set-Cookie: sess=verysecretvalue1234', 'Set-Cookie:'],
    ];
    for (const [src, label] of samples) {
      const out = redactCredentials(src) ?? '';
      assert(
        out !== src && out.includes('[REDACTED'),
        `${label} redacted (out=${out})`,
      );
    }
  }

  // ---------------------------------------------------------------------------
  console.log('[13] real captured fixture round-trips redaction without lossy field shape');
  {
    const report = loadFixture('auth-report-failure-logged-in-missed.json');
    const r = parseZapLoginDiagnostics(report);
    // The captured fixture's afEnv echoes back our YAML, including the
    // fixture's hardcoded password ("hunter2hunter2"). The parser must not
    // copy afEnv into the output — only the failure description string —
    // and the description should pass through redaction unchanged because
    // it doesn't contain a patterned secret.
    const surface = JSON.stringify(r);
    assert(
      !surface.includes('hunter2hunter2'),
      `password from afEnv not leaked into output JSON`,
    );
    assert(
      r.failed_at_step?.detail !== undefined,
      `detail populated from failure description`,
    );
  }

  // ---------------------------------------------------------------------------
  console.log('[14] auth.summary.auth=true with stray failureReason → still success');
  {
    // ZAP CAN emit failureReasons for diagnostic categories even when
    // auth.summary.auth.passed===true (e.g. partial sub-check failures).
    // The auth-summary key is the load-bearing verdict.
    const report: ZapAuthReport = {
      summaryItems: [{ key: 'auth.summary.auth', passed: true }],
      failureReasons: [{ key: 'auth.failure.diagnostic_note', description: 'minor' }],
    };
    const r = parseZapLoginDiagnostics(report);
    assert(r.success === true, `success:true when auth.summary.auth.passed`);
    assert(r.failed_at_step === undefined, `no failed_at_step on success`);
  }

  const t1 = Date.now();
  console.log(`\n${passed} passed, ${failures} failed (${t1 - t0}ms)`);
  if (failures > 0) {
    process.exit(1);
  }
}

main();
