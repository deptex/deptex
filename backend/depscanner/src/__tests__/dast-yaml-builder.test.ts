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
  UnsupportedAuthStrategyError,
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

  it("'recorded' strategy throws UnsupportedAuthStrategyError with stable code", () => {
    expect(() =>
      buildAutomationYaml({
        ...BASELINE_OPTS,
        authStrategy: 'recorded',
        authPayload: { kind: 'recorded' as any } as any,
      }),
    ).toThrow(UnsupportedAuthStrategyError);
    try {
      buildAutomationYaml({
        ...BASELINE_OPTS,
        authStrategy: 'recorded',
        authPayload: { kind: 'recorded' as any } as any,
      });
    } catch (e: any) {
      expect(e.code).toBe('dast_strategy_not_supported_in_v2_1a');
    }
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
