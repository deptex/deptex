/**
 * Tests for the pre-flight pattern-syntax validator and its end-to-end
 * integration with `validateRule` (Gate "pattern_compile").
 *
 * Closes the gap left when Phase 5 retired `semgrep --validate`. Without
 * this gate, `pattern: "_.template((*"` (unbalanced parens) passed zod
 * (string + min(1)) and the engine's hand-rolled validateSpec but silently
 * no-op'd at flow-walk time -- malformed CVE candidates reported
 * `schema_pass:true` while emitting zero flows, indistinguishable in the
 * funnel from "the model wrote a structurally fine but mistaken pattern".
 */

import { validatePatternSyntax } from '../taint-engine/pattern-syntax';
import { validateRule, makeRuleGenWorkdir } from '../rule-generator/validate';

describe('validatePatternSyntax — unit', () => {
  describe('accepts well-formed engine patterns', () => {
    const ok = [
      'eval',
      'eval(*)',
      '_.template(*)',
      'pkg.api(*)',
      'Math.random',
      'os.system(*)',
      'request.GET.*',
      'params.*',
      '*.html_safe',
      '*.method(*)',
      '*->method(*)',
      '*::method(*)',
      'Net::HTTP::get(*)',
      'Files.readAllBytes(*)',
      'req.uri().path()',
      'Paths.get(*).normalize(*)',
      'new ProcessBuilder',
      'node-fetch(*)',
      'params[*]',
      '@RequestParam',
      '@Route(*)',
      '`(*)',
      'Kernel.`(*)',
      '[FromBody]',
      'Query.0.*',
    ];
    test.each(ok)('accepts %p', (p) => {
      const r = validatePatternSyntax(p);
      expect(r).toEqual({ ok: true });
    });
  });

  describe('rejects malformed patterns', () => {
    const cases: [string, RegExp][] = [
      ['', /empty/],
      ['_.template((*', /unbalanced/i],
      ['pkg.foo)(*)', /unmatched closing/i],
      ['{unclosed', /unbalanced/i],
      ['mismatch(]', /mismatched|unbalanced/i],
      [' eval', /whitespace/i],
      ['eval ', /whitespace/i],
      ['line\nbreak', /newline|tab/i],
      ['col\tumn', /newline|tab/i],
      ['***', /identifier characters/i],
      ['(*)', /identifier characters/i],
      ['..', /identifier characters/i],
    ];
    test.each(cases)('rejects %p with reason %s', (p, reasonMatcher) => {
      const r = validatePatternSyntax(p);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toMatch(reasonMatcher);
    });
  });

  it('rejects ASCII control characters', () => {
    const ctrl = `eval${String.fromCharCode(0x07)}`;
    const r = validatePatternSyntax(ctrl);
    expect(r.ok).toBe(false);
  });
});

describe('validateRule — pattern_compile gate (integration)', () => {
  jest.setTimeout(30_000);

  const basePayload = {
    framework_spec: {
      framework: 'pkg',
      version: '*',
      language: 'js',
      sources: [],
      sinks: [
        {
          pattern: 'pkg.dangerous(*)',
          vuln_class: 'command_injection',
          argument_indices: [0],
          description: 'demo sink',
        },
      ],
      sanitizers: [],
    },
    vulnerable_fixture: 'module.exports = (req) => pkg.dangerous(req.body.x)',
    safe_fixture: 'module.exports = () => pkg.dangerous("static")',
    reachability_level: 'confirmed' as const,
    entry_point_class: 'PUBLIC_UNAUTH' as const,
    rationale: 'demo',
  };

  test('happy path — well-formed patterns pass the new gate', async () => {
    const result = await validateRule({
      payload: basePayload,
      cveId: 'CVE-9999-OK',
      ecosystem: 'npm',
      workDir: makeRuleGenWorkdir(),
      runPatchValidation: false,
    });
    // Whatever Gate 2 says (it depends on tree-sitter loading), the
    // pattern_compile gate must have run and reported pass=true.
    expect(result.log.validation_breakdown.pattern_compile_pass).toBe(true);
  });

  test('the audit smoking gun — `_.template((*` is rejected with pattern_compile error', async () => {
    const bad = JSON.parse(JSON.stringify(basePayload));
    bad.framework_spec.sinks[0].pattern = '_.template((*';
    const result = await validateRule({
      payload: bad,
      cveId: 'CVE-9999-AUDIT',
      ecosystem: 'npm',
      workDir: makeRuleGenWorkdir(),
      runPatchValidation: false,
    });
    expect(result.status).toBe('failed_validation');
    expect(result.log.validation_breakdown.pattern_compile_pass).toBe(false);
    expect(result.log.validation_breakdown.fixture_pre_match).toBe(false);
    expect(result.log.errors[0]).toMatch(/pattern_compile/);
    expect(result.log.errors[0]).toMatch(/_\.template/);
  });

  test('rejects malformed source patterns too', async () => {
    const bad = JSON.parse(JSON.stringify(basePayload));
    bad.framework_spec.sources = [
      { pattern: 'req.body)(*)', taint_kind: 'http_input', description: 'broken' },
    ];
    const result = await validateRule({
      payload: bad,
      cveId: 'CVE-9999-SOURCE',
      ecosystem: 'npm',
      workDir: makeRuleGenWorkdir(),
      runPatchValidation: false,
    });
    expect(result.status).toBe('failed_validation');
    expect(result.log.validation_breakdown.pattern_compile_pass).toBe(false);
    expect(result.log.errors[0]).toMatch(/pattern_compile: source/);
  });

  test('rejects malformed sanitizer patterns too', async () => {
    const bad = JSON.parse(JSON.stringify(basePayload));
    bad.framework_spec.sanitizers = [
      { pattern: 'scrub((((', vuln_classes: ['command_injection'], description: 'broken' },
    ];
    const result = await validateRule({
      payload: bad,
      cveId: 'CVE-9999-SAN',
      ecosystem: 'npm',
      workDir: makeRuleGenWorkdir(),
      runPatchValidation: false,
    });
    expect(result.status).toBe('failed_validation');
    expect(result.log.validation_breakdown.pattern_compile_pass).toBe(false);
    expect(result.log.errors[0]).toMatch(/pattern_compile: sanitizer/);
  });

  test('does not run fixture round-trip when pattern_compile fails', async () => {
    // Sentinel: the broken pattern would trip Gate 2 with `fixture_round_trip_failed`
    // (zero pre-matches). pattern_compile runs first and short-circuits; verify
    // we see the pattern_compile error, NOT the fixture error.
    const bad = JSON.parse(JSON.stringify(basePayload));
    bad.framework_spec.sinks[0].pattern = '_.template((*';
    const result = await validateRule({
      payload: bad,
      cveId: 'CVE-9999-ORDER',
      ecosystem: 'npm',
      workDir: makeRuleGenWorkdir(),
      runPatchValidation: false,
    });
    expect(result.log.errors.some((e) => e.startsWith('pattern_compile:'))).toBe(true);
    expect(result.log.errors.every((e) => !e.startsWith('fixture_round_trip_failed'))).toBe(true);
    expect(result.log.fixture_pre_matches).toBe(0);
    expect(result.log.fixture_post_matches).toBe(0);
  });
});
