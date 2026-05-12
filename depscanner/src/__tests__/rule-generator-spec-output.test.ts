/**
 * Unit tests for the Phase 6.5 generator's FrameworkSpec output path
 * (plan task 11).
 *
 * Covers:
 *   1. Strict zod schema accepts a hand-authored payload + rejects extras.
 *   2. parseAndValidate surfaces `prompt_injection_suspect` for an osv_id-on-
 *      sink emission, distinct from `invalid_schema`.
 *   3. validateRule's Gate 2 catches an obvious regression — sink-pattern
 *      mismatch makes pre-match drop to 0 even when the source is correct.
 *      (JS path only — full multi-language Gate 2 lives in the tsx-script
 *      test/few-shot-roundtrip-gate2.ts because the per-language propagators
 *      use tree-sitter WASM that jest's vm-isolate sandbox refuses.)
 *   4. buildAttemptFailureFeedback produces a usable revision prompt for
 *      both validation-failure and pre-validate-failure paths.
 */

import {
  parseAndValidate,
  GeneratedPayloadSchema,
  GenerationError,
} from '../rule-generator/generate';
import {
  FrameworkSinkSchema,
  isBroadSinkPattern,
} from '../rule-generator/framework-spec-schema';
import {
  validateRule,
  makeRuleGenWorkdir,
} from '../rule-generator/validate';
import {
  buildAttemptFailureFeedback,
} from '../rule-generator';

const validPayload = {
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
  reachability_level: 'confirmed',
  entry_point_class: 'PUBLIC_UNAUTH',
  rationale: 'demo',
};

describe('rule-generator FrameworkSpec output — schema gate (Gate 1)', () => {
  test('strict schema accepts a well-shaped payload', () => {
    const r = GeneratedPayloadSchema.safeParse(validPayload);
    expect(r.success).toBe(true);
  });

  test('rejects rule_yaml leftover from Phase 5 (strict mode)', () => {
    const r = GeneratedPayloadSchema.safeParse({ ...validPayload, rule_yaml: 'rules: []' });
    expect(r.success).toBe(false);
  });

  test('rejects sinks with off-enum vuln_class', () => {
    const bad = JSON.parse(JSON.stringify(validPayload));
    bad.framework_spec.sinks[0].vuln_class = 'not_a_real_class';
    const r = GeneratedPayloadSchema.safeParse(bad);
    expect(r.success).toBe(false);
  });

  test('parseAndValidate surfaces prompt_injection_suspect on rogue osv_id', () => {
    const bad = JSON.parse(JSON.stringify(validPayload));
    bad.framework_spec.sinks[0].osv_id = 'CVE-9999-99999';
    let caught: unknown;
    try { parseAndValidate(JSON.stringify(bad)); } catch (err) { caught = err; }
    expect(caught).toBeInstanceOf(GenerationError);
    expect((caught as GenerationError).code).toBe('prompt_injection_suspect');
  });

  test('parseAndValidate surfaces invalid_schema for a missing required field', () => {
    const bad: Record<string, unknown> = { ...validPayload };
    delete bad.framework_spec;
    let caught: unknown;
    try { parseAndValidate(JSON.stringify(bad)); } catch (err) { caught = err; }
    expect(caught).toBeInstanceOf(GenerationError);
    expect((caught as GenerationError).code).toBe('invalid_schema');
  });

  test('parseAndValidate surfaces vuln_class_out_of_scope for off-enum sink vuln_class', () => {
    // Phase 6.5 e2e baseline: 3 of 88 corpus CVEs (Spring SpEL CVE-2023-34053,
    // Apache POI scriptable CVE-2017-12626, HTTP/2 Rapid Reset CVE-2023-44487)
    // had Qwen invent vuln_class values the engine doesn't model. They were
    // bucketed as generic invalid_schema, hiding "this CVE is not a taint
    // flow" behind "the model garbled the schema." This test pins the new
    // labelled bucket so the signal stays visible after future schema work.
    const bad = JSON.parse(JSON.stringify(validPayload));
    bad.framework_spec.sinks[0].vuln_class = 'http2_rapid_reset';
    let caught: unknown;
    try { parseAndValidate(JSON.stringify(bad)); } catch (err) { caught = err; }
    expect(caught).toBeInstanceOf(GenerationError);
    expect((caught as GenerationError).code).toBe('vuln_class_out_of_scope');
    expect((caught as GenerationError).message).toMatch(/non-taint-modelable/);
  });

  test('parseAndValidate surfaces vuln_class_out_of_scope for off-enum sanitizer vuln_classes', () => {
    const bad = JSON.parse(JSON.stringify(validPayload));
    bad.framework_spec.sanitizers = [
      {
        pattern: 'pkg.scrub(*)',
        vuln_classes: ['xml_billion_laughs'],
        description: 'demo',
      },
    ];
    let caught: unknown;
    try { parseAndValidate(JSON.stringify(bad)); } catch (err) { caught = err; }
    expect(caught).toBeInstanceOf(GenerationError);
    expect((caught as GenerationError).code).toBe('vuln_class_out_of_scope');
  });

  test('parseAndValidate keeps invalid_schema bucket when vuln_class fails alongside another field', () => {
    // Conservative: a payload that fails for vuln_class AND something else
    // stays in invalid_schema so we don't suppress real schema bugs.
    const bad = JSON.parse(JSON.stringify(validPayload));
    bad.framework_spec.sinks[0].vuln_class = 'spel_injection';
    bad.framework_spec.language = 'klingon';
    let caught: unknown;
    try { parseAndValidate(JSON.stringify(bad)); } catch (err) { caught = err; }
    expect(caught).toBeInstanceOf(GenerationError);
    expect((caught as GenerationError).code).toBe('invalid_schema');
  });

  test('parseAndValidate accepts the new code_injection vuln_class', () => {
    // phase28b adds code_injection to the engine taxonomy. Confirm the zod
    // schema now accepts it so SpEL-style CVEs round-trip cleanly.
    const ok = JSON.parse(JSON.stringify(validPayload));
    ok.framework_spec.sinks[0].vuln_class = 'code_injection';
    const r = parseAndValidate(JSON.stringify(ok));
    expect(r.payload.framework_spec.sinks[0].vuln_class).toBe('code_injection');
  });

  test('parseAndValidate accepts the new weak_crypto vuln_class', () => {
    // phase28c adds weak_crypto to the engine taxonomy. Confirm the zod
    // schema now accepts it so CVE-2022-23541 (jsonwebtoken kid → weak key)
    // and similar crypto-misuse CVEs round-trip cleanly.
    const ok = JSON.parse(JSON.stringify(validPayload));
    ok.framework_spec.sinks[0].vuln_class = 'weak_crypto';
    const r = parseAndValidate(JSON.stringify(ok));
    expect(r.payload.framework_spec.sinks[0].vuln_class).toBe('weak_crypto');
  });

  test('parseAndValidate accepts the new auth_bypass vuln_class', () => {
    // phase28c adds auth_bypass to the engine taxonomy. Confirm the zod
    // schema now accepts it so CVE-2022-22978 (Spring Security regex
    // newline bypass) and similar auth-decision-routing CVEs round-trip
    // cleanly.
    const ok = JSON.parse(JSON.stringify(validPayload));
    ok.framework_spec.sinks[0].vuln_class = 'auth_bypass';
    const r = parseAndValidate(JSON.stringify(ok));
    expect(r.payload.framework_spec.sinks[0].vuln_class).toBe('auth_bypass');
  });

  test('parseAndValidate parses well-shaped payload with promptInjectionSuspect=false', () => {
    const r = parseAndValidate(JSON.stringify(validPayload));
    expect(r.payload.framework_spec.framework).toBe('pkg');
    expect(r.promptInjectionSuspect).toBe(false);
  });
});

describe('validateRule Gate 2 — fixture round-trip (JS path)', () => {
  jest.setTimeout(30_000);

  /**
   * The Express few-shot's vulnerable fixture writes `req.query.next` →
   * `res.redirect(target)`. We exercise Gate 2 by passing the real spec
   * (open_redirect on res.redirect) and a sink-pattern regression where
   * the model emits a NON-MATCHING pattern. Pre-match should be ≥1 in the
   * good case and 0 in the regression — Gate 2 is the only thing that
   * catches this; Gate 1 (zod) accepts both.
   */
  const expressBasePayload = {
    framework_spec: {
      framework: 'express',
      version: '*',
      language: 'js',
      sources: [],
      sinks: [
        {
          pattern: 'res.redirect(*)',
          vuln_class: 'open_redirect',
          argument_indices: [0, 1],
          description: 'Express open redirect',
        },
      ],
      sanitizers: [],
    },
    vulnerable_fixture: `const express = require('express');
const app = express();
app.get('/go', (req, res) => {
  const target = req.query.next;
  res.redirect(target);
});`,
    safe_fixture: `const express = require('express');
const app = express();
app.get('/go', (req, res) => {
  res.redirect('/dashboard');
});`,
    reachability_level: 'confirmed',
    entry_point_class: 'PUBLIC_UNAUTH',
    rationale: '',
  };

  test('validates a correctly-shaped FrameworkSpec end-to-end', async () => {
    const result = await validateRule({
      payload: expressBasePayload,
      cveId: 'CVE-9999-EXPRESS',
      ecosystem: 'npm',
      workDir: makeRuleGenWorkdir(),
      runPatchValidation: false,
    });
    expect(result.status).toBe('validated');
    expect(result.log.fixture_pre_matches).toBeGreaterThan(0);
    expect(result.log.fixture_post_matches).toBe(0);
    expect(result.log.validation_breakdown.fixture_pre_match).toBe(true);
    expect(result.log.validation_breakdown.fixture_safe_clean).toBe(true);
  });

  test('catches an obvious sink-pattern regression — pre=0 with wrong callee text', async () => {
    // The fixture exercises a non-bundled sink (`app.proxy(target)`), and the
    // AI rule declares a wrong pattern. The Gate 2 widening can't rescue
    // this because no bundled JS spec models `app.proxy` for open_redirect,
    // so the regression-detection semantic is preserved.
    const wrongPattern = JSON.parse(JSON.stringify(expressBasePayload));
    wrongPattern.framework_spec.sinks[0].pattern = 'res.thisDoesNotExist(*)';
    wrongPattern.vulnerable_fixture = `const express = require('express');
const app = express();
app.get('/go', (req, res) => {
  const target = req.query.next;
  app.proxy(target);
});`;
    wrongPattern.safe_fixture = `const express = require('express');
const app = express();
app.get('/go', (req, res) => {
  app.proxy('/dashboard');
});`;
    const result = await validateRule({
      payload: wrongPattern,
      cveId: 'CVE-9999-EXPRESS',
      ecosystem: 'npm',
      workDir: makeRuleGenWorkdir(),
      runPatchValidation: false,
    });
    expect(result.status).toBe('failed_validation');
    expect(result.log.fixture_pre_matches).toBe(0);
    expect(result.log.errors.join(' ')).toMatch(/fixture_round_trip_failed/);
  });

  /**
   * Widening: when the AI rule names a wrong/unmatched sink pattern but
   * declares a vuln_class for which a bundled framework spec already models
   * the sink the fixture actually exercises, Gate 2 should validate — the
   * AI's contribution is the OSV→vuln_class mapping, not net-new sink shapes.
   * Gate 3 (patch round-trip) is the harder check for actual rule correctness.
   */
  test('Gate 2 widening accepts bundled-spec sinks of matching vuln_class', async () => {
    const widened = JSON.parse(JSON.stringify(expressBasePayload));
    // AI's named sink doesn't match the fixture, but its vuln_class
    // (open_redirect) matches express.yaml's `res.redirect(*)` sink, which
    // the fixture DOES exercise.
    widened.framework_spec.sinks[0].pattern = 'someLib.weirdRedirect(*)';
    // expressBasePayload's fixtures already use `res.redirect(target)`.
    const result = await validateRule({
      payload: widened,
      cveId: 'CVE-9999-EXPRESS-WIDENED',
      ecosystem: 'npm',
      workDir: makeRuleGenWorkdir(),
      runPatchValidation: false,
    });
    expect(result.status).toBe('validated');
    expect(result.log.fixture_pre_matches).toBeGreaterThan(0);
    expect(result.log.fixture_post_matches).toBe(0);
  });
});

describe('buildAttemptFailureFeedback', () => {
  test('produces a revision prompt for the pre-validate-failure path', () => {
    const feedback = buildAttemptFailureFeedback({
      payload: null,
      errorMessage: 'parse_failed: Provider response did not contain a JSON object.',
      validation: null,
    });
    expect(feedback).toContain('framework_spec');
    expect(feedback).toContain('Do NOT include osv_id');
    expect(feedback).toContain('parse_failed');
  });

  test('produces a revision prompt for the validation-failure path with concrete counts', () => {
    const log = {
      fixture_pre_matches: 0,
      fixture_post_matches: 0,
      patch_pre_matches: null,
      patch_post_matches: null,
      semgrep_stderr_excerpt: null,
      errors: ['fixture_round_trip_failed'],
      took_ms: 100,
      validation_breakdown: {
        schema_pass: true,
        pattern_compile_pass: true,
        fixture_pre_match: false,
        fixture_safe_clean: true,
        patch_pre_match: null,
        patch_post_clean: null,
        semgrep_parse_error: null,
      },
    };
    const feedback = buildAttemptFailureFeedback({
      payload: validPayload,
      errorMessage: log.errors.join(' | '),
      validation: { log },
      patchDiff: '+ const safe_load = yaml.safe_load\n',
    });
    expect(feedback).toContain('previous_framework_spec');
    expect(feedback).toContain('previous_vulnerable_fixture');
    expect(feedback).toContain('previous_safe_fixture');
    expect(feedback).toContain('Vulnerable fixture flows: 0');
    expect(feedback).toContain('too NARROW');
    expect(feedback).toContain('safe_load');
  });

  test('reflects the too-broad case correctly', () => {
    const log = {
      fixture_pre_matches: 1,
      fixture_post_matches: 1,
      patch_pre_matches: null,
      patch_post_matches: null,
      semgrep_stderr_excerpt: null,
      errors: [],
      took_ms: 100,
      validation_breakdown: {
        schema_pass: true,
        pattern_compile_pass: true,
        fixture_pre_match: true,
        fixture_safe_clean: false,
        patch_pre_match: null,
        patch_post_clean: null,
        semgrep_parse_error: null,
      },
    };
    const feedback = buildAttemptFailureFeedback({
      payload: validPayload,
      errorMessage: '',
      validation: { log },
    });
    expect(feedback).toContain('too BROAD');
    expect(feedback).toContain('STATIC LITERAL');
  });
});

describe('Phase 6.5 hardening — sink-pattern broadness guard', () => {
  // Direct heuristic checks. Phase 6.5 / T4.2 added isBroadSinkPattern as a
  // .refine() on FrameworkSinkSchema's `pattern`. The list of rejected forms
  // is the prompt-injection attack surface — bare wildcards lift coverage to
  // every call in the program. Explicit literal receivers must always pass.
  test('rejects bare "*"', () => {
    expect(isBroadSinkPattern('*')).toBe(true);
  });

  test('rejects "*.*(*)" (wildcard receiver and method)', () => {
    expect(isBroadSinkPattern('*.*(*)')).toBe(true);
  });

  test('rejects "*.execute(*)" (wildcard receiver, concrete method)', () => {
    expect(isBroadSinkPattern('*.execute(*)')).toBe(true);
  });

  test('rejects empty / whitespace-only patterns', () => {
    expect(isBroadSinkPattern('')).toBe(true);
    expect(isBroadSinkPattern('  ')).toBe(true);
  });

  test('accepts a literal-receiver dotted pattern', () => {
    expect(isBroadSinkPattern('_.template(*)')).toBe(false);
  });

  test('accepts a single-identifier function pattern', () => {
    expect(isBroadSinkPattern('eval(*)')).toBe(false);
  });

  test('accepts a multi-segment literal receiver', () => {
    expect(isBroadSinkPattern('child_process.exec(*)')).toBe(false);
  });

  test('FrameworkSinkSchema rejects a too-broad pattern via the .refine()', () => {
    const result = FrameworkSinkSchema.safeParse({
      pattern: '*.execute(*)',
      vuln_class: 'sql_injection',
      argument_indices: [0],
      description: 'too broad — would match every .execute call in the repo',
    });
    expect(result.success).toBe(false);
  });

  test('FrameworkSinkSchema accepts a literal-receiver pattern', () => {
    const result = FrameworkSinkSchema.safeParse({
      pattern: '_.template(*)',
      vuln_class: 'prototype_pollution',
      argument_indices: [0],
      description: 'lodash template prototype pollution sink',
    });
    expect(result.success).toBe(true);
  });
});
