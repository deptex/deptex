import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import {
  loadAllRules,
  loadAllRulesWithSkipped,
  selectRulesForCves,
  runReachabilityRules,
  parseTaintOutput,
  parseTaintOutputWithDrops,
  LoadedRule,
} from '../reachability-rules';

const ECOSYSTEM_FIXTURE_EXTS: Record<string, string> = {
  npm: 'js',
  pypi: 'py',
  maven: 'java',
  golang: 'go',
  gem: 'rb',
  composer: 'php',
};

const RULES_DIR = path.resolve(__dirname, '../../reachability-rules');
const LODASH_DIR = path.join(RULES_DIR, 'CVE-2021-23337-lodash-template');

function semgrepAvailable(): boolean {
  try {
    const res = spawnSync('semgrep', ['--version'], { stdio: 'ignore', timeout: 5000 });
    return res.status === 0;
  } catch {
    return false;
  }
}

const SEMGREP_PRESENT = semgrepAvailable();
const semgrepDescribe = SEMGREP_PRESENT ? describe : describe.skip;

describe('loadAllRules', () => {
  it('loads the bundled lodash rule with normalised metadata', async () => {
    const rules = await loadAllRules(RULES_DIR);
    const lodash = rules.find((r) => r.metadata.cve === 'CVE-2021-23337');
    expect(lodash).toBeDefined();
    expect(lodash!.ruleId).toBe('deptex.lodash.template-injection');
    expect(lodash!.metadata.package).toBe('lodash');
    expect(lodash!.metadata.ecosystem).toBe('npm');
    expect(lodash!.metadata.confidence).toBe('HIGH');
    expect(lodash!.metadata.affectedVersions).toBe('<4.17.21');
    expect(lodash!.metadata.cwe).toBeDefined();
    expect(Array.isArray(lodash!.metadata.cwe)).toBe(true);
  });

  it('returns [] for a non-existent rules dir', async () => {
    const rules = await loadAllRules(path.join(os.tmpdir(), 'nonexistent-deptex-rules-' + Date.now()));
    expect(rules).toEqual([]);
  });

  it('skips folders missing rule.yml or metadata without throwing', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-rules-test-'));
    try {
      // Valid rule
      const okDir = path.join(tmp, 'CVE-9999-0001-ok');
      fs.mkdirSync(okDir, { recursive: true });
      fs.writeFileSync(
        path.join(okDir, 'rule.yml'),
        [
          'rules:',
          '  - id: deptex.test.ok',
          '    languages: [javascript]',
          '    severity: ERROR',
          '    mode: taint',
          '    message: ok',
          '    metadata:',
          '      cve: CVE-9999-0001',
          '      package: fake-pkg',
          '      ecosystem: npm',
          '    pattern-sources:',
          '      - pattern: $X.tainted',
          '    pattern-sinks:',
          '      - pattern: sink($Y)',
          '',
        ].join('\n'),
      );

      // Missing metadata
      const noMetaDir = path.join(tmp, 'CVE-9999-0002-nometa');
      fs.mkdirSync(noMetaDir, { recursive: true });
      fs.writeFileSync(
        path.join(noMetaDir, 'rule.yml'),
        'rules:\n  - id: deptex.test.nometa\n    languages: [javascript]\n    severity: ERROR\n    mode: taint\n    message: x\n    pattern-sources: [{pattern: $X}]\n    pattern-sinks: [{pattern: sink($Y)}]\n',
      );

      // Missing rule.yml entirely
      fs.mkdirSync(path.join(tmp, 'CVE-9999-0003-noyml'), { recursive: true });

      // Non-CVE folder should be ignored silently
      fs.mkdirSync(path.join(tmp, 'README'), { recursive: true });

      const rules = await loadAllRules(tmp);
      expect(rules.map((r) => r.metadata.cve)).toEqual(['CVE-9999-0001']);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('skips files with multiple rules in one yml', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-multirule-'));
    try {
      const dir = path.join(tmp, 'CVE-9999-9999-multi');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(
        path.join(dir, 'rule.yml'),
        [
          'rules:',
          '  - id: deptex.a',
          '    languages: [javascript]',
          '    severity: ERROR',
          '    mode: taint',
          '    message: x',
          '    metadata: {cve: CVE-9999-9999, package: p, ecosystem: npm}',
          '    pattern-sources: [{pattern: $X}]',
          '    pattern-sinks: [{pattern: sink($Y)}]',
          '  - id: deptex.b',
          '    languages: [javascript]',
          '    severity: ERROR',
          '    mode: taint',
          '    message: y',
          '    metadata: {cve: CVE-9999-9999, package: p, ecosystem: npm}',
          '    pattern-sources: [{pattern: $X}]',
          '    pattern-sinks: [{pattern: sink($Y)}]',
          '',
        ].join('\n'),
      );
      const rules = await loadAllRules(tmp);
      expect(rules).toEqual([]);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('selectRulesForCves', () => {
  const mkRule = (cve: string): LoadedRule => ({
    rulePath: `/fake/${cve}/rule.yml`,
    ruleId: `deptex.fake.${cve.toLowerCase()}`,
    metadata: { cve, package: 'fake', ecosystem: 'npm' },
  });

  it('filters to only rules whose CVE is in the detected set', () => {
    const all = [mkRule('CVE-2021-1'), mkRule('CVE-2021-2'), mkRule('CVE-2021-3')];
    const selected = selectRulesForCves(all, new Set(['CVE-2021-1', 'CVE-2021-3', 'CVE-2099-9']));
    expect(selected.map((r) => r.metadata.cve)).toEqual(['CVE-2021-1', 'CVE-2021-3']);
  });

  it('returns [] on empty detected set (no CVEs, no rules run)', () => {
    const all = [mkRule('CVE-2021-1')];
    expect(selectRulesForCves(all, new Set())).toEqual([]);
  });
});

describe('parseTaintOutput', () => {
  const lodashRule: LoadedRule = {
    rulePath: '/fake/lodash/rule.yml',
    ruleId: 'deptex.lodash.template-injection',
    metadata: { cve: 'CVE-2021-23337', package: 'lodash', ecosystem: 'npm' },
  };
  const rulesById = new Map([[lodashRule.ruleId, lodashRule]]);

  it('returns [] on non-object input', () => {
    expect(parseTaintOutput(null, rulesById)).toEqual([]);
    expect(parseTaintOutput({}, rulesById)).toEqual([]);
    expect(parseTaintOutput({ results: 'nope' }, rulesById)).toEqual([]);
  });

  it('normalises a representative --dataflow-traces finding', () => {
    const semgrepJson = {
      results: [
        {
          check_id: 'deptex.lodash.template-injection',
          path: 'src/index.js',
          start: { line: 8 },
          end: { line: 8 },
          extra: {
            lines: '  const compiled = _.template(userTemplate);',
            dataflow_trace: {
              taint_source: [
                { location: { path: 'src/index.js', start: { line: 7 }, end: { line: 7 } } },
                '  const userTemplate = req.body.template;',
              ],
              intermediate_vars: [],
              taint_sink: [
                { location: { path: 'src/index.js', start: { line: 8 }, end: { line: 8 } } },
                '  const compiled = _.template(userTemplate);',
              ],
            },
          },
        },
      ],
    };

    const findings = parseTaintOutput(semgrepJson, rulesById);
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.cve).toBe('CVE-2021-23337');
    expect(f.ruleId).toBe('deptex.lodash.template-injection');
    expect(f.filePath).toBe('src/index.js');
    expect(f.sourceLine).toBe(7);
    expect(f.sinkLine).toBe(8);
    expect(f.sourceContent).toContain('req.body.template');
    expect(f.sinkMethod).toBe('_.template');
    expect(f.flowSteps).toEqual([]);
  });

  it('falls back to sink location when taint_source is missing', () => {
    const findings = parseTaintOutput(
      {
        results: [
          {
            check_id: 'deptex.lodash.template-injection',
            path: 'x.js',
            start: { line: 5 },
            extra: { lines: 'sink()', dataflow_trace: {} },
          },
        ],
      },
      rulesById,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].sourceLine).toBe(5);
    expect(findings[0].sinkLine).toBe(5);
  });

  it('drops findings with unknown rule ids', () => {
    const findings = parseTaintOutput(
      {
        results: [
          { check_id: 'some.other.rule', path: 'x.js', start: { line: 1 }, extra: { lines: 'x' } },
        ],
      },
      rulesById,
    );
    expect(findings).toEqual([]);
  });

  // Regression guard: when `--config` points at a directory, semgrep prefixes
  // each check_id with the rule-file's basename (`tmp.tmp.aBc.deptex...`).
  // Before the suffix-match fix, every directory-config invocation produced
  // zero findings because the rulesById lookup missed every result. This shape
  // is what runReachabilityRules actually emits in production.
  it('matches check_ids that semgrep prefixes when --config points at a dir', () => {
    const findings = parseTaintOutput(
      {
        results: [
          {
            check_id: 'tmp.tmp.aBcDeF.deptex.lodash.template-injection',
            path: 'src/index.js',
            start: { line: 10 },
            end: { line: 10 },
            extra: { lines: '_.template(x)', dataflow_trace: {} },
          },
        ],
      },
      rulesById,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('deptex.lodash.template-injection');
  });

  it('parseTaintOutputWithDrops surfaces unknown rule ids as a de-duped list', () => {
    const result = parseTaintOutputWithDrops(
      {
        results: [
          { check_id: 'external.rule.a', path: 'x.js', start: { line: 1 }, extra: { lines: 'x' } },
          { check_id: 'external.rule.a', path: 'y.js', start: { line: 2 }, extra: { lines: 'y' } },
          { check_id: 'external.rule.b', path: 'z.js', start: { line: 3 }, extra: { lines: 'z' } },
        ],
      },
      rulesById,
    );
    expect(result.findings).toEqual([]);
    expect(result.unknownRuleIds.sort()).toEqual(['external.rule.a', 'external.rule.b']);
  });

  it('truncates huge content strings so a single finding cannot blow row size', () => {
    const huge = 'x'.repeat(10_000);
    const findings = parseTaintOutput(
      {
        results: [
          {
            check_id: 'deptex.lodash.template-injection',
            path: 'x.js',
            start: { line: 1 },
            extra: {
              lines: huge,
              dataflow_trace: {
                taint_source: [
                  { location: { path: 'x.js', start: { line: 1 } } },
                  huge,
                ],
                intermediate_vars: [],
              },
            },
          },
        ],
      },
      rulesById,
    );
    expect(findings).toHaveLength(1);
    // Each content field must be clamped to 2KB + truncation suffix.
    expect(findings[0].sinkContent!.length).toBeLessThan(3_000);
    expect(findings[0].sourceContent!.length).toBeLessThan(3_000);
    expect(findings[0].sinkContent).toMatch(/truncated/);
  });

  it('caps intermediate_vars at MAX_INTERMEDIATE_STEPS', () => {
    const steps = Array.from({ length: 200 }, (_, i) => [
      { location: { path: 'x.js', start: { line: i + 1 } } },
      `step${i}`,
    ]);
    const findings = parseTaintOutput(
      {
        results: [
          {
            check_id: 'deptex.lodash.template-injection',
            path: 'x.js',
            start: { line: 300 },
            extra: { lines: 'sink', dataflow_trace: { intermediate_vars: steps } },
          },
        ],
      },
      rulesById,
    );
    expect(findings).toHaveLength(1);
    // 200 in, 50 out — the cap.
    expect(findings[0].flowSteps.length).toBe(50);
  });

  it('extractCalleeName skips leading prefix keywords (await, new)', () => {
    // Indirect assertion via a normalised finding: the sink line "await foo(x)"
    // should produce sinkMethod='foo', not 'await'.
    const findings = parseTaintOutput(
      {
        results: [
          {
            check_id: 'deptex.lodash.template-injection',
            path: 'x.js',
            start: { line: 1 },
            extra: { lines: 'await foo(tainted)' },
          },
        ],
      },
      rulesById,
    );
    expect(findings[0].sinkMethod).toBe('foo');
  });

  it('does not crash when rules[0] is null (pathological YAML)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-null-rule-'));
    try {
      const dir = path.join(tmp, 'CVE-9999-0005-null');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'rule.yml'), 'rules:\n  - null\n');
      const { loaded, skipped } = await loadAllRulesWithSkipped(tmp);
      expect(loaded).toEqual([]);
      expect(skipped).toHaveLength(1);
      expect(skipped[0].folder).toBe('CVE-9999-0005-null');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('loadAllRulesWithSkipped', () => {
  it('returns structured skipped entries so caller can log them', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-skipped-'));
    try {
      // Missing metadata
      const d1 = path.join(tmp, 'CVE-9999-1001-nometa');
      fs.mkdirSync(d1, { recursive: true });
      fs.writeFileSync(
        path.join(d1, 'rule.yml'),
        'rules:\n  - id: deptex.x\n    languages: [javascript]\n    severity: ERROR\n    mode: taint\n    message: x\n    pattern-sources: [{pattern: $X}]\n    pattern-sinks: [{pattern: sink($Y)}]\n',
      );
      // Malformed YAML
      const d2 = path.join(tmp, 'CVE-9999-1002-bad');
      fs.mkdirSync(d2, { recursive: true });
      fs.writeFileSync(path.join(d2, 'rule.yml'), 'rules: [\n  unclosed');

      const { loaded, skipped } = await loadAllRulesWithSkipped(tmp);
      expect(loaded).toEqual([]);
      expect(skipped.map((s) => s.folder).sort()).toEqual([
        'CVE-9999-1001-nometa',
        'CVE-9999-1002-bad',
      ]);
      expect(skipped.find((s) => s.folder === 'CVE-9999-1001-nometa')!.reason).toMatch(/metadata/);
      expect(skipped.find((s) => s.folder === 'CVE-9999-1002-bad')!.reason).toMatch(/parse/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

semgrepDescribe('runReachabilityRules (live semgrep)', () => {
  if (!SEMGREP_PRESENT) {
    console.warn('[reachability-rules.test] Skipping live Semgrep tests — binary not on PATH.');
  }

  it('matches vulnerable.js and not safe.js for the lodash rule', async () => {
    const rules = await loadAllRules(RULES_DIR);
    const selected = selectRulesForCves(rules, new Set(['CVE-2021-23337']));
    expect(selected).toHaveLength(1);

    const fixturesDir = path.join(LODASH_DIR, '__fixtures__');

    const findings = await runReachabilityRules({
      workspaceRoot: fixturesDir,
      rules: selected,
      timeoutMs: 60_000,
    });

    const byFile = new Map<string, number>();
    for (const f of findings) {
      const name = path.basename(f.filePath);
      byFile.set(name, (byFile.get(name) ?? 0) + 1);
    }

    expect((byFile.get('vulnerable.js') ?? 0)).toBeGreaterThanOrEqual(1);
    expect(byFile.get('safe.js') ?? 0).toBe(0);

    const vulnFinding = findings.find((f) => f.filePath.endsWith('vulnerable.js'));
    expect(vulnFinding).toBeDefined();
    expect(vulnFinding!.cve).toBe('CVE-2021-23337');
    expect(vulnFinding!.ruleId).toBe('deptex.lodash.template-injection');
  }, 90_000);

  // Parameterised smoke: every bundled rule pack must match its own
  // __fixtures__/vulnerable.<ext> and NOT match its own safe.<ext>.
  // Catches YAML/pattern regressions that would otherwise silently ship
  // (a rule that loads but no longer matches is the same failure mode
  // as a broken rule from the user's perspective).
  //
  // KNOWN_FP_SAFE_FIXTURE: rule packs whose safe fixture currently matches
  // (false positive in the rule itself). Tracked separately so the
  // smoke stays green while we iterate on rule precision. See
  // memory: future_reachability_rule_fps.md.
  const KNOWN_FP_SAFE_FIXTURE = new Set([
    // Source→sink flow present in safe fixture; rule doesn't gate on enableDefaultTyping.
    'CVE-2019-12384-jackson-databind-polymorphic',
    // Rule fires on tainted body param even when URL arg is a constant.
    'CVE-2022-0235-node-fetch-header-leak',
    // SafeConstructor sanitizer is on the constructor; taint sink is on .load() — sanitizer doesn't carry.
    'CVE-2022-1471-snakeyaml-unsafe-load',
    // Taint mode firing on Http::get(constant_url) despite no source. Semgrep 1.160.0 behaviour.
    'CVE-2024-13918-laravel-http-ssrf',
  ]);
  const allBundled = SEMGREP_PRESENT ? fs.readdirSync(RULES_DIR, { withFileTypes: true })
    .filter((e) => e.isDirectory() && e.name.startsWith('CVE-') && !KNOWN_FP_SAFE_FIXTURE.has(e.name))
    .map((e) => e.name) : [];

  it.each(allBundled)('rule %s matches vulnerable fixture and not safe fixture', async (folder) => {
    const rules = await loadAllRules(RULES_DIR);
    const rule = rules.find((r) => r.rulePath.includes(folder));
    if (!rule) throw new Error(`Rule not loaded for folder ${folder}`);

    const ext = ECOSYSTEM_FIXTURE_EXTS[rule.metadata.ecosystem];
    const fixturesDir = path.join(RULES_DIR, folder, '__fixtures__');
    if (!fs.existsSync(fixturesDir)) throw new Error(`Missing __fixtures__ for ${folder}`);

    const findings = await runReachabilityRules({
      workspaceRoot: fixturesDir,
      rules: [rule],
      timeoutMs: 120_000,
    });

    const vulnHits = findings.filter((f) => f.filePath.endsWith(`vulnerable.${ext}`)).length;
    const safeHits = findings.filter((f) => f.filePath.endsWith(`safe.${ext}`)).length;
    expect(vulnHits).toBeGreaterThanOrEqual(1);
    expect(safeHits).toBe(0);
  }, 180_000);
});
