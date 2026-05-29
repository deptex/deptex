import {
  runPackagePolicy,
  runProjectStatus,
  runPRCheck,
  validatePolicyCode,
  type PolicyDependencyContext,
  type PolicyImportance,
} from '../policy-engine';

const IMPORTANCE_DEFAULT: PolicyImportance = 1.0;
const IMPORTANCE_HIGH: PolicyImportance = 1.5;

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
    const result = await runPackagePolicy(SIMPLE_POLICY, makeDep(), IMPORTANCE_DEFAULT);
    expect(result.allowed).toBe(true);
    expect(result.reasons).toEqual([]);
  });

  it('blocks a malicious dependency', async () => {
    const dep = makeDep({ maliciousIndicator: { source: 'socket', confidence: 1, reason: 'typosquat' } });
    const result = await runPackagePolicy(SIMPLE_POLICY, dep, IMPORTANCE_DEFAULT);
    expect(result.allowed).toBe(false);
    expect(result.reasons).toContain('Malicious');
  });

  it('returns error result on syntax error in code', async () => {
    const result = await runPackagePolicy('function packagePolicy(ctx) { {{{{ }', makeDep(), IMPORTANCE_DEFAULT);
    expect(result.allowed).toBe(false);
    expect(result.reasons[0]).toContain('Policy execution error');
  });

  it('returns error result on runtime throw', async () => {
    const code = `function packagePolicy(ctx) { throw new Error('boom'); }`;
    const result = await runPackagePolicy(code, makeDep(), IMPORTANCE_DEFAULT);
    expect(result.allowed).toBe(false);
    expect(result.reasons[0]).toContain('boom');
  });

  it('receives importance context correctly', async () => {
    const code = `function packagePolicy(ctx) {
      if (ctx.importance >= 1.3) return { allowed: false, reasons: ['Blocked for high-importance project (' + ctx.importance + ')'] };
      return { allowed: true, reasons: [] };
    }`;
    const crownResult = await runPackagePolicy(code, makeDep(), IMPORTANCE_HIGH);
    expect(crownResult.allowed).toBe(false);

    const internalResult = await runPackagePolicy(code, makeDep(), IMPORTANCE_DEFAULT);
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
    const result = await runPackagePolicy(code, dep, IMPORTANCE_DEFAULT);
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
      project: { name: 'test', tier: IMPORTANCE_DEFAULT, teamName: 'Team' },
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
      project: { name: 'test', tier: IMPORTANCE_DEFAULT, teamName: 'Team' },
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
      if (violations.length > 0) return { passed: false, violations: ['blocked'] };
      return { passed: true, violations: [] };
    }`;
    const context = {
      project: { name: 'test', tier: IMPORTANCE_DEFAULT },
      added: [{ name: 'new-pkg', policyResult: { allowed: true, reasons: [] } }],
      updated: [],
      removed: [],
      statuses: ['Compliant', 'Non-Compliant'],
    };
    const result = await runPRCheck(code, context);
    expect(result.passed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('blocks PR adding disallowed dependency', async () => {
    const code = `function pullRequestCheck(ctx) {
      var violations = ctx.added.concat(ctx.updated).filter(function(d) { return !d.policyResult.allowed; });
      if (violations.length > 0) return { passed: false, violations: ['blocked'] };
      return { passed: true, violations: [] };
    }`;
    const context = {
      project: { name: 'test', tier: IMPORTANCE_DEFAULT },
      added: [{ name: 'bad-pkg', policyResult: { allowed: false, reasons: ['banned license'] } }],
      updated: [],
      removed: [],
      statuses: ['Compliant', 'Non-Compliant'],
    };
    const result = await runPRCheck(code, context);
    expect(result.passed).toBe(false);
    expect(result.violations).toEqual(['blocked']);
  });

  it('accepts return { passed: true, violations: [] }', async () => {
    const code = `function pullRequestCheck(ctx) { return { passed: true, violations: [] }; }`;
    const context = {
      project: { name: 'test' },
      added: [],
      updated: [],
      removed: [],
    };
    const result = await runPRCheck(code, context);
    expect(result.passed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('accepts return { passed: false, violations: ["x"] }', async () => {
    const code = `function pullRequestCheck(ctx) { return { passed: false, violations: ['x'] }; }`;
    const context = { project: { name: 'test' }, added: [], updated: [], removed: [] };
    const result = await runPRCheck(code, context);
    expect(result.passed).toBe(false);
    expect(result.violations).toEqual(['x']);
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
    // pr_check shape requires { passed, violations } (not projectStatus-style { status })
    const code = `function pullRequestCheck(ctx) { return { passed: true, violations: [] }; }`;
    const result = await validatePolicyCode(code, 'pr_check', 'test-org');
    expect(result.allPassed).toBe(true);
  });

  it('passes PR check code returning { passed, violations }', async () => {
    const code = `function pullRequestCheck(ctx) { return { passed: true, violations: [] }; }`;
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

// ─── M0 hardening: isolated-vm sandbox invariants ───
//
// These tests verify the per-call sandbox actually delivers the security and
// performance properties the plan promises. They exercise the engine through
// `runPackagePolicy` (the hottest call site) so a regression here also tells
// us the legacy callers still work.

describe('isolated-vm sandbox invariants', () => {
  it('fresh isolate per call: prototype mutations do not leak between calls', async () => {
    // Mutate Object.prototype in call N; verify call N+1 sees a clean prototype.
    const pollute = `function packagePolicy(ctx) {
      Object.prototype.__leaked = 'pwned';
      return { allowed: true, reasons: [] };
    }`;
    const observe = `function packagePolicy(ctx) {
      var obj = {};
      var leaked = (obj).__leaked;
      return { allowed: leaked == null, reasons: leaked == null ? [] : ['LEAK: ' + leaked] };
    }`;
    const a = await runPackagePolicy(pollute, makeDep(), IMPORTANCE_DEFAULT);
    expect(a.allowed).toBe(true);
    const b = await runPackagePolicy(observe, makeDep(), IMPORTANCE_DEFAULT);
    expect(b.allowed).toBe(true);
    expect(b.reasons).toEqual([]);
  });

  it('CPU cap preempts an infinite loop and surfaces a timeout error', async () => {
    const code = `function packagePolicy(ctx) { while (true) {} return { allowed: true, reasons: [] }; }`;
    const start = Date.now();
    const result = await runPackagePolicy(code, makeDep(), IMPORTANCE_DEFAULT);
    const elapsed = Date.now() - start;
    expect(result.allowed).toBe(false);
    expect(result.reasons[0]).toMatch(/Policy execution error/i);
    // EXECUTION_TIMEOUT_MS is 30s; we just want to confirm the cap actually fires
    // (legacy Function() couldn't preempt a synchronous while(true)).
    expect(elapsed).toBeLessThan(35_000);
  }, 40_000);

  it('return-value cap blocks payloads larger than 256KB', async () => {
    // Build a string just over the cap. JSON.stringify of a 300_000-char string
    // produces ~300_002 chars (quotes), comfortably above the 262_144 limit.
    const code = `function packagePolicy(ctx) {
      var big = 'x'.repeat(300000);
      return { allowed: true, reasons: [big] };
    }`;
    const result = await runPackagePolicy(code, makeDep(), IMPORTANCE_DEFAULT);
    expect(result.allowed).toBe(false);
    expect(result.reasons[0]).toMatch(/256KB cap|exceeds/i);
  });

  it('hostile Proxy with throwing getters cannot hang the host', async () => {
    // A Proxy whose getter throws would have crashed naive copy paths. With
    // JSON.stringify-then-slice inside the isolate, the throw happens during
    // stringify and surfaces as a normal policy execution error.
    const code = `function packagePolicy(ctx) {
      var hostile = new Proxy({}, { get: function() { throw new Error('boom getter'); } });
      return { allowed: true, reasons: [], extra: hostile };
    }`;
    const start = Date.now();
    const result = await runPackagePolicy(code, makeDep(), IMPORTANCE_DEFAULT);
    const elapsed = Date.now() - start;
    expect(result.allowed).toBe(false);
    // Host did not infinite-loop — must complete well inside the CPU cap.
    expect(elapsed).toBeLessThan(2_000);
  });

  it('snapshot-warm-restore bench: per-call p50 < 5ms, 1500-call sweep < 10s', async () => {
    // Acceptance gate from plan M0: this is the perf path that gates the
    // extraction pipeline. If it fails, fall back to batch evaluation before
    // declaring M0 complete.
    const code = `function packagePolicy(ctx) {
      if (ctx.dependency.dependencyScore != null && ctx.dependency.dependencyScore < 40) {
        return { allowed: false, reasons: ['Low score'] };
      }
      return { allowed: true, reasons: [] };
    }`;

    const N = 1500;
    const samples: number[] = new Array(N);
    const sweepStart = Date.now();
    for (let i = 0; i < N; i++) {
      const t0 = Date.now();
      await runPackagePolicy(code, makeDep(), IMPORTANCE_DEFAULT);
      samples[i] = Date.now() - t0;
    }
    const sweepMs = Date.now() - sweepStart;
    samples.sort((a, b) => a - b);
    const p50 = samples[Math.floor(N * 0.5)];
    const p95 = samples[Math.floor(N * 0.95)];

    // eslint-disable-next-line no-console
    console.log(
      `[bench] 1500-call sweep: total=${sweepMs}ms, p50=${p50}ms, p95=${p95}ms`,
    );

    expect(sweepMs).toBeLessThan(10_000);
    expect(p50).toBeLessThan(5);
  }, 30_000);

  it('helpers round-trip correctly through host references', async () => {
    // Verify each host helper proxy actually invokes the host function and
    // returns its result. If a Reference were misconfigured, helpers would
    // return undefined and the test would fail.
    const code = `function packagePolicy(ctx) {
      var reasons = [];
      if (!isLicenseAllowed('MIT', ['MIT', 'Apache-2.0'])) reasons.push('isLicenseAllowed broke');
      if (isLicenseBanned('MIT', ['GPL-3.0'])) reasons.push('isLicenseBanned broke');
      if (!semverGt('2.0.0', '1.9.0')) reasons.push('semverGt broke');
      if (!semverLt('1.0.0', '2.0.0')) reasons.push('semverLt broke');
      var ds = daysSince('2000-01-01T00:00:00Z');
      if (typeof ds !== 'number' || ds < 1000) reasons.push('daysSince broke: ' + ds);
      return { allowed: reasons.length === 0, reasons: reasons };
    }`;
    const result = await runPackagePolicy(code, makeDep(), IMPORTANCE_DEFAULT);
    expect(result.reasons).toEqual([]);
    expect(result.allowed).toBe(true);
  });
});
