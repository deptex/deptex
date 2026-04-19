import {
  runPackagePolicy,
  runProjectStatus,
  runPRCheck,
  validatePolicyCode,
  type PolicyDependencyContext,
  type PolicyTierContext,
} from '../policy-engine';

const TIER_INTERNAL: PolicyTierContext = { name: 'Internal', rank: 3, multiplier: 1.0 };
const TIER_CROWN_JEWELS: PolicyTierContext = { name: 'Crown Jewels', rank: 1, multiplier: 1.5 };

function makeDep(overrides: Partial<PolicyDependencyContext> = {}): PolicyDependencyContext {
  return {
    name: 'test-pkg',
    version: '1.0.0',
    license: 'MIT',
    openSsfScore: 7.5,
    weeklyDownloads: 100000,
    lastPublishedAt: new Date().toISOString(),
    releasesLast12Months: 12,
    dependencyScore: 75,
    maliciousIndicator: null,
    slsaLevel: 0,
    registryIntegrityStatus: 'pass',
    installScriptsStatus: 'pass',
    entropyAnalysisStatus: 'pass',
    ...overrides,
  };
}

describe('runPackagePolicy', () => {
  const SIMPLE_POLICY = `function packagePolicy(context) {
    if (context.dependency.maliciousIndicator) {
      return { allowed: false, reasons: ['Malicious'] };
    }
    return { allowed: true, reasons: [] };
  }`;

  it('allows a clean dependency', async () => {
    const result = await runPackagePolicy(SIMPLE_POLICY, makeDep(), TIER_INTERNAL);
    expect(result.allowed).toBe(true);
    expect(result.reasons).toEqual([]);
  });

  it('blocks a malicious dependency', async () => {
    const dep = makeDep({ maliciousIndicator: { source: 'socket', confidence: 1, reason: 'typosquat' } });
    const result = await runPackagePolicy(SIMPLE_POLICY, dep, TIER_INTERNAL);
    expect(result.allowed).toBe(false);
    expect(result.reasons).toContain('Malicious');
  });

  it('returns error result on syntax error in code', async () => {
    const result = await runPackagePolicy('function packagePolicy(ctx) { {{{{ }', makeDep(), TIER_INTERNAL);
    expect(result.allowed).toBe(false);
    expect(result.reasons[0]).toContain('Policy execution error');
  });

  it('returns error result on runtime throw', async () => {
    const code = `function packagePolicy(ctx) { throw new Error('boom'); }`;
    const result = await runPackagePolicy(code, makeDep(), TIER_INTERNAL);
    expect(result.allowed).toBe(false);
    expect(result.reasons[0]).toContain('boom');
  });

  it('receives tier context correctly', async () => {
    const code = `function packagePolicy(ctx) {
      if (ctx.tier.rank <= 2) return { allowed: false, reasons: ['Blocked for ' + ctx.tier.name] };
      return { allowed: true, reasons: [] };
    }`;
    const crownResult = await runPackagePolicy(code, makeDep(), TIER_CROWN_JEWELS);
    expect(crownResult.allowed).toBe(false);

    const internalResult = await runPackagePolicy(code, makeDep(), TIER_INTERNAL);
    expect(internalResult.allowed).toBe(true);
  });

  it('handles null dependency fields gracefully', async () => {
    const code = `function packagePolicy(ctx) {
      if (ctx.dependency.dependencyScore != null && ctx.dependency.dependencyScore < 40) {
        return { allowed: false, reasons: ['Low score'] };
      }
      return { allowed: true, reasons: [] };
    }`;
    const dep = makeDep({ dependencyScore: null });
    const result = await runPackagePolicy(code, dep, TIER_INTERNAL);
    expect(result.allowed).toBe(true);
  });
});

describe('runProjectStatus', () => {
  it('returns Compliant for clean project', async () => {
    const code = `function projectStatus(ctx) {
      var blocked = ctx.dependencies.filter(function(d) { return !d.policyResult.allowed; });
      if (blocked.length > 0) return { status: 'Non-Compliant', violations: ['has blocked deps'] };
      return { status: 'Compliant', violations: [] };
    }`;
    const context = {
      project: { name: 'test', tier: TIER_INTERNAL, teamName: 'Team' },
      dependencies: [{ name: 'a', policyResult: { allowed: true, reasons: [] }, vulnerabilities: [] }],
      statuses: ['Compliant', 'Non-Compliant'],
    };
    const result = await runProjectStatus(code, context);
    expect(result.status).toBe('Compliant');
    expect(result.violations).toEqual([]);
  });

  it('returns Non-Compliant when deps are blocked', async () => {
    const code = `function projectStatus(ctx) {
      var blocked = ctx.dependencies.filter(function(d) { return !d.policyResult.allowed; });
      if (blocked.length > 0) return { status: 'Non-Compliant', violations: blocked.map(function(d) { return d.name; }) };
      return { status: 'Compliant', violations: [] };
    }`;
    const context = {
      project: { name: 'test', tier: TIER_INTERNAL, teamName: 'Team' },
      dependencies: [{ name: 'bad-pkg', policyResult: { allowed: false, reasons: ['banned'] }, vulnerabilities: [] }],
      statuses: ['Compliant', 'Non-Compliant'],
    };
    const result = await runProjectStatus(code, context);
    expect(result.status).toBe('Non-Compliant');
    expect(result.violations).toContain('bad-pkg');
  });

  it('returns error status on runtime throw', async () => {
    const code = `function projectStatus(ctx) { throw new Error('status error'); }`;
    const result = await runProjectStatus(code, { project: {}, dependencies: [], statuses: [] });
    expect(result.status).toBe('Non-Compliant');
    expect(result.violations[0]).toContain('status error');
  });
});

describe('runPRCheck', () => {
  it('passes clean PR', async () => {
    const code = `function pullRequestCheck(ctx) {
      var violations = ctx.added.concat(ctx.updated).filter(function(d) { return !d.policyResult.allowed; });
      if (violations.length > 0) return { status: 'Non-Compliant', violations: ['blocked'] };
      return { status: 'Compliant', violations: [] };
    }`;
    const context = {
      project: { name: 'test', tier: TIER_INTERNAL },
      added: [{ name: 'new-pkg', policyResult: { allowed: true, reasons: [] } }],
      updated: [],
      removed: [],
      statuses: ['Compliant', 'Non-Compliant'],
    };
    const result = await runPRCheck(code, context);
    expect(result.status).toBe('Compliant');
  });

  it('blocks PR adding disallowed dependency', async () => {
    const code = `function pullRequestCheck(ctx) {
      var violations = ctx.added.concat(ctx.updated).filter(function(d) { return !d.policyResult.allowed; });
      if (violations.length > 0) return { status: 'Non-Compliant', violations: ['blocked'] };
      return { status: 'Compliant', violations: [] };
    }`;
    const context = {
      project: { name: 'test', tier: TIER_INTERNAL },
      added: [{ name: 'bad-pkg', policyResult: { allowed: false, reasons: ['banned license'] } }],
      updated: [],
      removed: [],
      statuses: ['Compliant', 'Non-Compliant'],
    };
    const result = await runPRCheck(code, context);
    expect(result.status).toBe('Non-Compliant');
  });
});

describe('validatePolicyCode', () => {
  it('rejects empty code', async () => {
    const result = await validatePolicyCode('', 'package_policy', 'test-org');
    expect(result.allPassed).toBe(false);
    expect(result.syntaxError).toContain('empty');
  });

  it('rejects code exceeding 50KB', async () => {
    const longCode = 'x'.repeat(51_000);
    const result = await validatePolicyCode(longCode, 'package_policy', 'test-org');
    expect(result.allPassed).toBe(false);
    expect(result.syntaxError).toContain('50KB');
  });

  it('rejects syntax errors', async () => {
    const result = await validatePolicyCode('function packagePolicy(ctx { }', 'package_policy', 'test-org');
    expect(result.syntaxPass).toBe(false);
    expect(result.syntaxError).toBeTruthy();
  });

  it('rejects wrong function name', async () => {
    const result = await validatePolicyCode('function myPolicy(ctx) { return { allowed: true, reasons: [] }; }', 'package_policy', 'test-org');
    expect(result.allPassed).toBe(false);
  });

  it('rejects wrong return shape', async () => {
    const code = `function packagePolicy(ctx) { return { pass: true }; }`;
    const result = await validatePolicyCode(code, 'package_policy', 'test-org');
    expect(result.shapePass).toBe(false);
  });

  it('passes valid package policy code', async () => {
    const code = `function packagePolicy(ctx) { return { allowed: true, reasons: [] }; }`;
    const result = await validatePolicyCode(code, 'package_policy', 'test-org');
    expect(result.syntaxPass).toBe(true);
    expect(result.shapePass).toBe(true);
    expect(result.allPassed).toBe(true);
  });

  it('passes valid project status code', async () => {
    const code = `function projectStatus(ctx) { return { status: 'Compliant', violations: [] }; }`;
    const result = await validatePolicyCode(code, 'project_status', 'test-org');
    expect(result.allPassed).toBe(true);
  });

  it('passes valid PR check code', async () => {
    const code = `function pullRequestCheck(ctx) { return { status: 'Compliant', violations: [] }; }`;
    const result = await validatePolicyCode(code, 'pr_check', 'test-org');
    expect(result.allPassed).toBe(true);
  });

  it('rejects reasons as string instead of string[]', async () => {
    const code = `function packagePolicy(ctx) { return { allowed: true, reasons: "not an array" }; }`;
    const result = await validatePolicyCode(code, 'package_policy', 'test-org');
    expect(result.shapePass).toBe(false);
    expect(result.shapeError).toContain('string[]');
  });

  it('fetch resilience check runs when code contains fetch(', async () => {
    const code = `function packagePolicy(ctx) {
      return { allowed: true, reasons: [] };
    }`;
    const codeWithFetch = `async function packagePolicy(ctx) {
      try { await fetch('https://example.com'); } catch(e) {}
      return { allowed: true, reasons: [] };
    }`;

    const resultNoFetch = await validatePolicyCode(code, 'package_policy', 'test-org');
    expect(resultNoFetch.fetchResiliencePass).toBe(true);
    expect(resultNoFetch.allPassed).toBe(true);

    const resultWithFetch = await validatePolicyCode(codeWithFetch, 'package_policy', 'test-org');
    expect(resultWithFetch.fetchResiliencePass).toBe(true);
    expect(resultWithFetch.allPassed).toBe(true);
  });

  it('fetch resilience: passes code with try/catch fallback', async () => {
    const code = `async function packagePolicy(ctx) {
      try {
        var resp = await fetch('https://example.com/api');
        var data = await resp.json();
      } catch (e) {
        // fallback
      }
      return { allowed: true, reasons: [] };
    }`;
    const result = await validatePolicyCode(code, 'package_policy', 'test-org');
    expect(result.fetchResiliencePass).toBe(true);
    expect(result.allPassed).toBe(true);
  });
});
