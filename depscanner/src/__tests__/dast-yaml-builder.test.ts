// Phase 24 (v2.1a): unit tests for the ZAP AF YAML builder.
//
// We round-trip via js-yaml.load so assertions hit the structured object the
// builder claims to emit, not whitespace-fragile snapshots. A handful of
// string-level checks confirm the YAML doesn't accidentally omit critical
// fields (e.g. context.includePaths).

import * as yaml from 'js-yaml';

import {
  buildAutomationYaml,
  type BuildAutomationYamlOptions,
} from '../dast/yaml-builder';
import {
  type CredentialPayload,
} from '../dast/auth-config';

function dumpAndParse(opts: BuildAutomationYamlOptions): {
  yamlText: string;
  doc: any;
} {
  const yamlText = buildAutomationYaml(opts);
  const doc = yaml.load(yamlText) as any;
  return { yamlText, doc };
}

const BASELINE_OPTS: BuildAutomationYamlOptions = {
  targetUrl: 'https://app.example.com/',
  scanProfile: 'auto',
  detectedRuntime: 'classic',
  reportRelativePath: 'deptex-dast-af-XYZ/zap-report.json',
};

describe('buildAutomationYaml — anonymous baseline (parity case)', () => {
  it('produces valid YAML that parses', () => {
    const { yamlText, doc } = dumpAndParse(BASELINE_OPTS);
    expect(yamlText.length).toBeGreaterThan(0);
    expect(doc).toBeDefined();
    expect(doc.env).toBeDefined();
    expect(doc.jobs).toBeDefined();
    expect(Array.isArray(doc.jobs)).toBe(true);
  });

  it('has exactly one context with default include scope = origin .*', () => {
    const { doc } = dumpAndParse(BASELINE_OPTS);
    expect(doc.env.contexts.length).toBe(1);
    const ctx = doc.env.contexts[0];
    expect(ctx.urls).toEqual(['https://app.example.com/']);
    expect(ctx.includePaths).toEqual([
      'https://app\\.example\\.com.*',
    ]);
    expect(ctx.excludePaths).toEqual([]);
    expect(ctx.authentication).toBeUndefined();
    expect(ctx.users).toBeUndefined();
  });

  it('emits jobs in the canonical order: addOns → passiveScan-config → spider → report', () => {
    const { doc } = dumpAndParse(BASELINE_OPTS);
    const types = doc.jobs.map((j: any) => j.type);
    expect(types).toEqual(['addOns', 'passiveScan-config', 'spider', 'report']);
  });

  it('does NOT emit a replacer job when there are no rules', () => {
    const { doc } = dumpAndParse(BASELINE_OPTS);
    expect(doc.jobs.find((j: any) => j.type === 'replacer')).toBeUndefined();
  });

  it('does NOT emit activeScan when scanProfile is not full', () => {
    const { doc } = dumpAndParse(BASELINE_OPTS);
    expect(doc.jobs.find((j: any) => j.type === 'activeScan')).toBeUndefined();
  });

  it('report job points at /zap/wrk + the relative path', () => {
    const { doc } = dumpAndParse(BASELINE_OPTS);
    const report = doc.jobs.find((j: any) => j.type === 'report');
    expect(report.parameters.reportDir).toBe('/zap/wrk');
    expect(report.parameters.reportFile).toBe(
      'deptex-dast-af-XYZ/zap-report.json',
    );
    expect(report.parameters.template).toBe('traditional-json');
  });

  // Real-ZAP parity gates — locks the AF YAML rule coverage to the helper-script
  // baseline. Without these, dropping pscanrulesAlpha/Beta or re-introducing the
  // maxAlertsPerRule cap regresses Juice Shop anonymous parity from 80 findings
  // back to 19 (mocked-spawn unit tests passed clean on both regressions).
  it('addOns install list includes pscanrulesAlpha + pscanrulesBeta for parity', () => {
    const { doc } = dumpAndParse(BASELINE_OPTS);
    const addOns = doc.jobs.find((j: any) => j.type === 'addOns');
    expect(addOns.parameters.install).toEqual(
      expect.arrayContaining(['pscanrulesAlpha', 'pscanrulesBeta']),
    );
  });

  it('passiveScan-config does NOT cap maxAlertsPerRule (zap-baseline.py has no cap)', () => {
    const { doc } = dumpAndParse(BASELINE_OPTS);
    const ps = doc.jobs.find((j: any) => j.type === 'passiveScan-config');
    expect(ps.parameters.maxAlertsPerRule).toBeUndefined();
  });
});

describe('buildAutomationYaml — runtime branching', () => {
  it("classic runtime → spider job (not spiderAjax)", () => {
    const { doc } = dumpAndParse({ ...BASELINE_OPTS, detectedRuntime: 'classic' });
    expect(doc.jobs.find((j: any) => j.type === 'spider')).toBeDefined();
    expect(doc.jobs.find((j: any) => j.type === 'spiderAjax')).toBeUndefined();
  });

  it("spa runtime → spiderAjax job (not spider)", () => {
    const { doc } = dumpAndParse({ ...BASELINE_OPTS, detectedRuntime: 'spa' });
    expect(doc.jobs.find((j: any) => j.type === 'spiderAjax')).toBeDefined();
    expect(doc.jobs.find((j: any) => j.type === 'spider')).toBeUndefined();
  });

  it("unknown runtime → spiderAjax (safer default; downsizes once classified)", () => {
    const { doc } = dumpAndParse({ ...BASELINE_OPTS, detectedRuntime: 'unknown' });
    expect(doc.jobs.find((j: any) => j.type === 'spiderAjax')).toBeDefined();
  });
});

describe('buildAutomationYaml — scan profile', () => {
  it("'full' profile adds an activeScan job after the spider", () => {
    const { doc } = dumpAndParse({ ...BASELINE_OPTS, scanProfile: 'full' });
    const types = doc.jobs.map((j: any) => j.type);
    const spiderIdx = types.indexOf('spider');
    const activeIdx = types.indexOf('activeScan');
    expect(spiderIdx).toBeGreaterThanOrEqual(0);
    expect(activeIdx).toBeGreaterThan(spiderIdx);
    const active = doc.jobs[activeIdx];
    expect(active.parameters.context).toBe('deptex-dast');
  });

  it("'quick' profile is passive-only (no activeScan)", () => {
    const { doc } = dumpAndParse({ ...BASELINE_OPTS, scanProfile: 'quick' });
    expect(doc.jobs.find((j: any) => j.type === 'activeScan')).toBeUndefined();
  });

  it("'auto' profile is passive-only — no auto-escalation to active", () => {
    const { doc } = dumpAndParse({ ...BASELINE_OPTS, scanProfile: 'auto' });
    expect(doc.jobs.find((j: any) => j.type === 'activeScan')).toBeUndefined();
  });

  it("activeScan honours scanTimeoutMinutes", () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      scanProfile: 'full',
      scanTimeoutMinutes: 45,
    });
    const active = doc.jobs.find((j: any) => j.type === 'activeScan');
    expect(active.parameters.maxScanDurationInMins).toBe(45);
  });
});

describe('buildAutomationYaml — scope', () => {
  it('emits caller-supplied includePaths verbatim', () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      scope: {
        includePaths: ['https://app\\.example\\.com/api/.*'],
        excludePaths: ['https://app\\.example\\.com/logout.*'],
      },
    });
    const ctx = doc.env.contexts[0];
    expect(ctx.includePaths).toEqual(['https://app\\.example\\.com/api/.*']);
    expect(ctx.excludePaths).toEqual(['https://app\\.example\\.com/logout.*']);
  });

  it('header_rules become req_header replacer rules by default', () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      scope: {
        headerRules: [
          { name: 'X-Tenant-Id', value: 'org-42', scope: 'all' },
          { name: 'X-Trace-Id', value: 'trace-1', scope: 'requests' },
        ],
      },
    });
    const replacer = doc.jobs.find((j: any) => j.type === 'replacer');
    expect(replacer).toBeDefined();
    expect(replacer.rules.length).toBe(2);
    for (const r of replacer.rules) expect(r.matchType).toBe('req_header');
    expect(replacer.rules[0].matchString).toBe('X-Tenant-Id');
    expect(replacer.rules[0].replacementString).toBe('org-42');
  });

  it('header_rules with scope=responses become resp_header rules', () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      scope: {
        headerRules: [
          { name: 'X-Trace-Id', value: 'trace-1', scope: 'responses' },
        ],
      },
    });
    const replacer = doc.jobs.find((j: any) => j.type === 'replacer');
    expect(replacer.rules[0].matchType).toBe('resp_header');
  });
});

describe('buildAutomationYaml — auth strategies', () => {
  it("form auth populates context.authentication + context.users", () => {
    const formCred: CredentialPayload = {
      kind: 'form',
      login_url: 'https://app.example.com/login',
      username_field: 'email',
      password_field: 'password',
      username: 'admin@example.com',
      password: 's3cr3t-fixture',
    };
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      authStrategy: 'form',
      authPayload: formCred,
      loggedInIndicator: '\\Q<a href=logout>\\E',
      loggedOutIndicator: '<button>Login</button>',
    });
    const ctx = doc.env.contexts[0];
    expect(ctx.authentication.method).toBe('form');
    expect(ctx.authentication.parameters.loginPageUrl).toBe(
      'https://app.example.com/login',
    );
    expect(ctx.authentication.parameters.loginRequestUrl).toBe(
      'https://app.example.com/login',
    );
    expect(ctx.authentication.parameters.loginRequestBody).toBe(
      'email={%username%}&password={%password%}',
    );
    expect(ctx.authentication.verification.method).toBe('response');
    expect(ctx.authentication.verification.loggedInRegex).toBe(
      '\\Q<a href=logout>\\E',
    );
    expect(ctx.authentication.verification.loggedOutRegex).toBe(
      '<button>Login</button>',
    );
    expect(ctx.users.length).toBe(1);
    expect(ctx.users[0].name).toBe('deptex-dast-user');
    expect(ctx.users[0].credentials.username).toBe('admin@example.com');
    expect(ctx.users[0].credentials.password).toBe('s3cr3t-fixture');
  });

  it("jwt auth becomes a replacer rule (Authorization: Bearer <token>)", () => {
    const jwtCred: CredentialPayload = {
      kind: 'jwt',
      token: 'eyJhbGciOiJIUzI1NiJ9.testpayload.testsig',
    };
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      authStrategy: 'jwt',
      authPayload: jwtCred,
    });
    const replacer = doc.jobs.find((j: any) => j.type === 'replacer');
    expect(replacer).toBeDefined();
    expect(replacer.rules.length).toBe(1);
    const r = replacer.rules[0];
    expect(r.matchType).toBe('req_header');
    expect(r.matchString).toBe('Authorization');
    expect(r.replacementString).toBe(
      'Bearer eyJhbGciOiJIUzI1NiJ9.testpayload.testsig',
    );
    // No context.authentication — JWT is replacer-only.
    expect(doc.env.contexts[0].authentication).toBeUndefined();
  });

  it("cookie auth becomes a single replacer rule with all cookies joined", () => {
    const cookieCred: CredentialPayload = {
      kind: 'cookie',
      cookies: [
        { name: 'session', value: 'fixture-cookie-value-7f3e' },
        { name: 'csrf', value: 'csrf-fixture' },
      ],
    };
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      authStrategy: 'cookie',
      authPayload: cookieCred,
    });
    const replacer = doc.jobs.find((j: any) => j.type === 'replacer');
    expect(replacer.rules.length).toBe(1);
    const r = replacer.rules[0];
    expect(r.matchType).toBe('req_header');
    expect(r.matchString).toBe('Cookie');
    expect(r.replacementString).toBe(
      'session=fixture-cookie-value-7f3e; csrf=csrf-fixture',
    );
  });

  it("auth + header_rules combine into one replacer job (auth rules appended after header rules)", () => {
    const jwtCred: CredentialPayload = {
      kind: 'jwt',
      token: 'eyJhbGciOiJIUzI1NiJ9.testpayload.testsig',
    };
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      authStrategy: 'jwt',
      authPayload: jwtCred,
      scope: {
        headerRules: [
          { name: 'X-Tenant-Id', value: 'org-42', scope: 'all' },
        ],
      },
    });
    const replacer = doc.jobs.find((j: any) => j.type === 'replacer');
    expect(replacer.rules.length).toBe(2);
    expect(replacer.rules[0].matchString).toBe('X-Tenant-Id');
    expect(replacer.rules[1].matchString).toBe('Authorization');
  });

  it("'recorded' strategy is now implemented (v2.1d) — full coverage lives in dast-yaml-builder-recorded.test.ts", () => {
    // v2.1a stub: `buildAuthForStrategy('recorded', …)` threw
    // `UnsupportedAuthStrategyError` (code `dast_strategy_not_supported_in_v2_1a`).
    // v2.1d removed that branch — the call now delegates to
    // `buildRecordedAuthForZap`. This smoke confirms the implementation
    // path is reached (an empty payload fails the inner validator, NOT
    // the UnsupportedAuthStrategyError guard).
    expect(() =>
      buildAutomationYaml({
        ...BASELINE_OPTS,
        authStrategy: 'recorded',
        authPayload: { kind: 'recorded' as any } as any,
      }),
    ).toThrow(/at least one non-goto step|payload.kind/);
  });
});

describe('buildAutomationYaml — invalid input', () => {
  it('throws on a malformed targetUrl', () => {
    expect(() =>
      buildAutomationYaml({
        ...BASELINE_OPTS,
        targetUrl: 'not-a-url',
      }),
    ).toThrow(/invalid targetUrl/);
  });
});

// Phase 35 (v1.1) — openapi: AF job + 'api' profile + user-binding convention.
describe("buildAutomationYaml — openapi job (Phase 35 v1.1)", () => {
  function jobsOf(doc: any): Array<Record<string, any>> {
    return doc.jobs as Array<Record<string, any>>;
  }

  it("does NOT emit an openapi job when openApiSpecPath is unset", () => {
    const { doc } = dumpAndParse(BASELINE_OPTS);
    expect(jobsOf(doc).find((j) => j.type === 'openapi')).toBeUndefined();
  });

  it("emits an openapi job when openApiSpecPath is set", () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      openApiSpecPath: '/zap/wrk/spec.yaml',
    });
    const job = jobsOf(doc).find((j) => j.type === 'openapi');
    expect(job).toBeDefined();
    expect(job!.parameters.apiFile).toBe('/zap/wrk/spec.yaml');
    expect(job!.parameters.targetUrl).toBe('https://app.example.com/');
    expect(job!.parameters.context).toBe('deptex-dast');
  });

  it("emits openapi job AFTER replacer (when replacer present) and BEFORE spider", () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      openApiSpecPath: '/zap/wrk/spec.yaml',
      scope: {
        headerRules: [{ name: 'X-Test', value: '1', scope: 'all' }],
      },
    });
    const types = jobsOf(doc).map((j) => j.type);
    const openapiIdx = types.indexOf('openapi');
    const replacerIdx = types.indexOf('replacer');
    const spiderIdx = types.findIndex((t) => t === 'spider' || t === 'spiderAjax');
    expect(replacerIdx).toBeGreaterThanOrEqual(0);
    expect(openapiIdx).toBeGreaterThan(replacerIdx);
    expect(openapiIdx).toBeLessThan(spiderIdx);
  });

  it("emits openapi job BEFORE spider/spiderAjax even without a replacer", () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      openApiSpecPath: '/zap/wrk/spec.yaml',
    });
    const types = jobsOf(doc).map((j) => j.type);
    const openapiIdx = types.indexOf('openapi');
    const spiderIdx = types.findIndex((t) => t === 'spider' || t === 'spiderAjax');
    expect(openapiIdx).toBeGreaterThan(-1);
    expect(spiderIdx).toBeGreaterThan(openapiIdx);
  });

  it("does NOT set parameters.user on openapi for form/jwt/cookie strategies", () => {
    const formAuth: CredentialPayload = {
      kind: 'form',
      login_page_url: 'https://app.example.com/login',
      username: 'u',
      password: 'p',
      username_selector: '#u',
      password_selector: '#p',
      submit_selector: '#go',
    };
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      openApiSpecPath: '/zap/wrk/spec.yaml',
      authStrategy: 'form',
      authPayload: formAuth,
    });
    const job = jobsOf(doc).find((j) => j.type === 'openapi');
    expect(job).toBeDefined();
    expect(job!.parameters.user).toBeUndefined();
    expect(job!.parameters.context).toBe('deptex-dast');
  });

  it("DOES set parameters.user='deptex-dast-user' on openapi for the recorded strategy", () => {
    const recordedAuth: CredentialPayload = {
      kind: 'recorded',
      login_page_url: 'https://app.example.com/login',
      steps: [
        { action: 'type-username', selector: '#u', value: 'user' },
        { action: 'type-password', selector: '#p', value: 'pass' },
        { action: 'click', selector: '#submit' },
      ],
    } as CredentialPayload;
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      openApiSpecPath: '/zap/wrk/spec.yaml',
      authStrategy: 'recorded',
      authPayload: recordedAuth,
    });
    const job = jobsOf(doc).find((j) => j.type === 'openapi');
    expect(job).toBeDefined();
    expect(job!.parameters.user).toBe('deptex-dast-user');
  });

  it("emits activeScan when scanProfile='api' (new in v1.1)", () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      scanProfile: 'api',
      openApiSpecPath: '/zap/wrk/spec.yaml',
    });
    const types = jobsOf(doc).map((j) => j.type);
    expect(types).toContain('activeScan');
    expect(types).toContain('openapi');
  });

  it("does NOT emit activeScan when scanProfile='auto' (even with openapi spec)", () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      scanProfile: 'auto',
      openApiSpecPath: '/zap/wrk/spec.yaml',
    });
    const types = jobsOf(doc).map((j) => j.type);
    expect(types).not.toContain('activeScan');
    // openapi still emits — row-driven gating decouples it from profile.
    expect(types).toContain('openapi');
  });

  it("does NOT emit openapi job in loginOnly mode", () => {
    const recordedAuth: CredentialPayload = {
      kind: 'recorded',
      login_page_url: 'https://app.example.com/login',
      steps: [
        { action: 'type-username', selector: '#u', value: 'user' },
        { action: 'type-password', selector: '#p', value: 'pass' },
      ],
    } as CredentialPayload;
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      openApiSpecPath: '/zap/wrk/spec.yaml',
      loginOnly: true,
      authStrategy: 'recorded',
      authPayload: recordedAuth,
    });
    const types = jobsOf(doc).map((j) => j.type);
    expect(types).not.toContain('openapi');
    expect(types).not.toContain('spider');
    expect(types).not.toContain('spiderAjax');
  });
});

describe('buildAutomationYaml — replay strategy (Phase 36 v1.1)', () => {
  // Local helper (the openapi describe block has its own jobsOf at line ~338).
  function jobsOf(doc: any): Array<Record<string, any>> {
    return (doc.jobs ?? []) as Array<Record<string, any>>;
  }

  function replayPayload(): CredentialPayload {
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
        },
      ],
      origins_observed: ['app.example.com'],
    } as CredentialPayload;
  }

  it('emits method=script + scriptEngine="ECMAScript : Graal.js" + scriptInline', () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      authStrategy: 'replay',
      authPayload: replayPayload(),
    });
    const ctx = doc.env.contexts[0];
    expect(ctx.authentication.method).toBe('script');
    expect(ctx.authentication.parameters.scriptEngine).toBe('ECMAScript : Graal.js');
    expect(typeof ctx.authentication.parameters.scriptInline).toBe('string');
    expect((ctx.authentication.parameters.scriptInline as string).length).toBeGreaterThan(100);
    // No separate `type: script` job — the script is INLINED in
    // context.authentication.parameters, not a sibling job.
    const types = jobsOf(doc).map((j) => j.type);
    expect(types).not.toContain('script');
  });

  it('emits the deptex-dast-user binding with an empty credentials map', () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      authStrategy: 'replay',
      authPayload: replayPayload(),
    });
    const ctx = doc.env.contexts[0];
    expect(ctx.users).toHaveLength(1);
    expect(ctx.users[0].name).toBe('deptex-dast-user');
    expect(ctx.users[0].credentials).toEqual({});
  });

  it('emits a requestor job with user binding for the post-auth probe', () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      authStrategy: 'replay',
      authPayload: replayPayload(),
    });
    const requestor = jobsOf(doc).find((j) => j.type === 'requestor');
    expect(requestor).toBeDefined();
    expect(requestor.parameters.user).toBe('deptex-dast-user');
  });

  it('does NOT emit the auth-report-json report job for replay (script-based auth has no auth-report)', () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      authStrategy: 'replay',
      authPayload: replayPayload(),
    });
    const reportTemplates = jobsOf(doc)
      .filter((j) => j.type === 'report')
      .map((j) => j.parameters.template);
    expect(reportTemplates).not.toContain('auth-report-json');
  });

  it("reserves the AUTH_SETUP_BUDGET_MIN carveout from activeScan duration", () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      scanProfile: 'full',
      scanTimeoutMinutes: 30,
      authStrategy: 'replay',
      authPayload: replayPayload(),
    });
    const activeScan = jobsOf(doc).find((j) => j.type === 'activeScan');
    expect(activeScan).toBeDefined();
    // 30 - AUTH_SETUP_BUDGET_MIN (3) = 27 expected.
    expect(activeScan.parameters.maxScanDurationInMins).toBe(27);
  });

  it('binds the openapi job to deptex-dast-user when a spec is set', () => {
    const { doc } = dumpAndParse({
      ...BASELINE_OPTS,
      openApiSpecPath: '/zap/wrk/spec.yaml',
      authStrategy: 'replay',
      authPayload: replayPayload(),
    });
    const openapi = jobsOf(doc).find((j) => j.type === 'openapi');
    expect(openapi).toBeDefined();
    expect(openapi.parameters.user).toBe('deptex-dast-user');
  });
});
