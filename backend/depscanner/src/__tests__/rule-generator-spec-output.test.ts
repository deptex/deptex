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
    const wrongPattern = JSON.parse(JSON.stringify(expressBasePayload));
    wrongPattern.framework_spec.sinks[0].pattern = 'res.thisDoesNotExist(*)';
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
