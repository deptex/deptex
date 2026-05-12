/**
 * Unit + integration tests for the Gate 2 vuln-class normalization layer.
 *
 * Background. The Gate 2 widening in `validateRule` (validate.ts) accepts
 * bundled framework_model sinks whose `vuln_class` matches one the AI rule
 * declared. Exact-string equality on the enum value silently rejects pairs
 * that are semantically equivalent but lexically different — e.g. AI says
 * `log_injection` for a Logger.info sink that log4j.yaml models as
 * `code_injection`. `canonicalVulnClass` normalises both sides at the
 * comparison site so the widening fires.
 *
 * Triage row this unblocks: 2026-05-12 close-call rows where
 * vulnClassesEmitted=['log_injection'] but the AI rule's named class is
 * code_injection (or vice versa).
 */

import {
  canonicalVulnClass,
  getVulnClassAliases,
} from '../rule-generator/vuln-class-alias';
import { ALL_VULN_CLASSES } from '../taint-engine/spec';
import { validateRule, makeRuleGenWorkdir } from '../rule-generator/validate';

describe('canonicalVulnClass — unit', () => {
  test('returns input unchanged when no alias applies', () => {
    expect(canonicalVulnClass('sql_injection')).toBe('sql_injection');
    expect(canonicalVulnClass('xss')).toBe('xss');
    expect(canonicalVulnClass('code_injection')).toBe('code_injection');
    expect(canonicalVulnClass('redos')).toBe('redos');
    // Unknown / out-of-enum input is identity-mapped too — callers never
    // see this since zod gates the rule schema, but defensive identity
    // means we don't silently swallow typos at the matching site.
    expect(canonicalVulnClass('not_a_real_class')).toBe('not_a_real_class');
    expect(canonicalVulnClass('')).toBe('');
  });

  test('maps log-context aliases onto code_injection', () => {
    expect(canonicalVulnClass('log_injection')).toBe('code_injection');
    expect(canonicalVulnClass('log4shell')).toBe('code_injection');
  });

  test('maps template-injection aliases onto code_injection', () => {
    expect(canonicalVulnClass('ssti')).toBe('code_injection');
    expect(canonicalVulnClass('template_injection')).toBe('code_injection');
  });

  test('maps generic dos onto redos', () => {
    expect(canonicalVulnClass('dos')).toBe('redos');
  });

  test('every alias target is a member of ALL_VULN_CLASSES (no dangling targets)', () => {
    const enumSet = new Set<string>(ALL_VULN_CLASSES as readonly string[]);
    for (const [from, to] of Object.entries(getVulnClassAliases())) {
      expect(enumSet.has(to)).toBe(true);
      // sanity: never alias something onto itself
      expect(from).not.toBe(to);
    }
  });
});

describe('Gate 2 widening — vuln-class alias integration (JS path)', () => {
  jest.setTimeout(30_000);

  /**
   * AI rule declares `vuln_class: ssti` on a non-bundled / non-matching
   * sink pattern, but the fixture exercises `_.template(req.body.tmpl)` —
   * lodash.yaml models that as `code_injection`. Without canonical-vuln-class
   * normalisation, the widening's exact-string match rejects the lodash
   * sink (ssti != code_injection) and the fixture pre-match drops to 0.
   * With the alias `ssti → code_injection`, the widening includes
   * `_.template(*)` in `cveSinkPatterns` and the fixture validates.
   *
   * This isolates the alias contribution: pattern mismatch on the AI sink,
   * vuln_class label mismatch on the bundled sink — neither alone would
   * widen, only the combination does.
   */
  const sstiOnLodashPayload = {
    framework_spec: {
      framework: 'lodash',
      version: '*',
      language: 'js',
      sources: [],
      sinks: [
        {
          // Deliberately doesn't match the fixture's actual sink shape.
          // Forces Gate 2 to rely on the widening to find a flow.
          pattern: 'someLib.compileTemplate(*)',
          // `ssti` is NOT in the engine enum — but zod accepts it via the
          // schema's enum. To keep this test exercising the alias path
          // without touching zod, we use `log_injection` instead, which
          // IS in the enum AND aliases onto `code_injection` (lodash's
          // bundled vuln_class). Same shape, validated path.
          vuln_class: 'log_injection',
          argument_indices: [0],
          description: 'AI-named sink with log_injection label',
        },
      ],
      sanitizers: [],
    },
    vulnerable_fixture: `const express = require('express');
const _ = require('lodash');
const app = express();
app.post('/render', (req, res) => {
  const tmpl = req.body.tmpl;
  const compiled = _.template(tmpl);
  res.send(compiled({}));
});`,
    safe_fixture: `const express = require('express');
const _ = require('lodash');
const app = express();
app.post('/render', (req, res) => {
  const compiled = _.template('<p>static</p>');
  res.send(compiled({}));
});`,
    reachability_level: 'confirmed' as const,
    entry_point_class: 'PUBLIC_UNAUTH' as const,
    rationale: '',
  };

  test('AI rule with log_injection-labelled sink widens onto bundled lodash code_injection sink', async () => {
    const result = await validateRule({
      payload: sstiOnLodashPayload,
      cveId: 'CVE-9999-VULNCLASS-ALIAS',
      ecosystem: 'npm',
      workDir: makeRuleGenWorkdir(),
      runPatchValidation: false,
    });
    expect(result.status).toBe('validated');
    expect(result.log.fixture_pre_matches).toBeGreaterThan(0);
    expect(result.log.fixture_post_matches).toBe(0);
  });

  test('control — same payload without lodash fixture stays unwidened (pre=0)', async () => {
    // Sanity: confirm the AI's named pattern alone can't match anything in
    // the fixture. Drop _.template entirely and the widening has nothing
    // to bring in.
    const noLodashFixture = JSON.parse(JSON.stringify(sstiOnLodashPayload));
    noLodashFixture.vulnerable_fixture = `const express = require('express');
const app = express();
app.post('/render', (req, res) => {
  const tmpl = req.body.tmpl;
  res.send(tmpl);
});`;
    noLodashFixture.safe_fixture = `const express = require('express');
const app = express();
app.post('/render', (req, res) => {
  res.send('static');
});`;
    const result = await validateRule({
      payload: noLodashFixture,
      cveId: 'CVE-9999-VULNCLASS-ALIAS-CTRL',
      ecosystem: 'npm',
      workDir: makeRuleGenWorkdir(),
      runPatchValidation: false,
    });
    // The widening will pull in res.send (express xss sink) only if a
    // bundled xss sink overlaps — but the AI declared log_injection which
    // aliases to code_injection, NOT xss, so widening can't rescue. Pre
    // should be 0.
    expect(result.log.fixture_pre_matches).toBe(0);
    expect(result.status).toBe('failed_validation');
  });
});
