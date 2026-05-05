/**
 * Few-shot CI gate (Phase 6.5 / M2 / PDA-4).
 *
 * Iterates `FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES` and asserts each entry passes:
 *
 *   Gate 1 (M2a / this commit) — strict zod schema validation. Rejects extra
 *   keys, missing required fields, off-enum values, and any sink that leaked
 *   an `osv_id` from a model copy-paste. After substitution, the persisted
 *   shape passes the post-substitution schema.
 *
 *   Gate 2 (M2b / next commit) — fixture round-trip. Loads the (substituted)
 *   spec into the Phase 6 engine, runs it on `vulnerable_fixture` (must emit
 *   ≥1 flow tagged with the row's `osv_id`), runs it on `safe_fixture` (must
 *   emit 0 flows). Wired in M2b once `validate.ts` exposes the round-trip
 *   harness — TODO marker below.
 *
 * Why this gates the build: Phase 5's tournament-tuned few-shot library was
 * the single highest-leverage knob on recall. A typo or shape regression in
 * a hand-port can ship a generator that "works" in CI smokes but silently
 * misclassifies on real CVEs.
 */

import {
  GeneratedFrameworkSpecPayloadSchema,
  PersistedFrameworkSpecSchema,
  withOsvIdsSubstituted,
  findRogueOsvIdInSinks,
} from '../../depscanner/src/rule-generator/framework-spec-schema';
import { FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES } from '../../depscanner/src/rule-generator/few-shot-examples';
import { ALL_VULN_CLASSES } from '../../depscanner/src/taint-engine/spec';

describe('few-shot library — Gate 1 schema validation', () => {
  test('library is non-empty and CVE ids are unique', () => {
    expect(FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES.length).toBeGreaterThan(0);
    const ids = FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES.map((e) => e.cveId);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test('library covers ≥3 distinct languages', () => {
    const languages = new Set(
      FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES.map((e) => e.payload.framework_spec.language),
    );
    expect(languages.size).toBeGreaterThanOrEqual(3);
  });

  describe.each(FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES)('$cveId ($packageName, $ecosystem)', (ex) => {
    test('payload passes strict zod schema (no extra keys, all required fields)', () => {
      const result = GeneratedFrameworkSpecPayloadSchema.safeParse(ex.payload);
      if (!result.success) {
        const issues = result.error.issues
          .map((i) => `${i.path.join('.')}: ${i.message}`)
          .join('\n  ');
        throw new Error(`schema validation failed:\n  ${issues}`);
      }
    });

    test('no sink leaks an osv_id field (server-side substitution is the only assignment site)', () => {
      const idx = findRogueOsvIdInSinks(ex.payload.framework_spec);
      expect(idx).toBeNull();
    });

    test('every sink uses a known vuln_class', () => {
      const known = new Set<string>(ALL_VULN_CLASSES);
      for (const sink of ex.payload.framework_spec.sinks) {
        expect(known.has(sink.vuln_class)).toBe(true);
      }
    });

    test('post-substitution shape matches the persisted schema', () => {
      const persisted = withOsvIdsSubstituted(ex.payload.framework_spec, ex.cveId);
      const result = PersistedFrameworkSpecSchema.safeParse(persisted);
      if (!result.success) {
        const issues = result.error.issues
          .map((i) => `${i.path.join('.')}: ${i.message}`)
          .join('\n  ');
        throw new Error(`persisted schema failed:\n  ${issues}`);
      }
      // Every sink carries the substituted osv_id.
      for (const sink of result.data.sinks) {
        expect(sink.osv_id).toBe(ex.cveId);
      }
    });

    test('vulnerable_fixture and safe_fixture are non-empty and parse-shaped', () => {
      // We don't compile here (Gate 2 will run the engine in M2b). Just
      // sanity-check that the fixtures are real source bodies, not
      // placeholder strings.
      expect(ex.payload.vulnerable_fixture.trim().length).toBeGreaterThan(20);
      expect(ex.payload.safe_fixture.trim().length).toBeGreaterThan(20);
      expect(ex.payload.vulnerable_fixture).not.toEqual(ex.payload.safe_fixture);
    });
  });

  // Gate 2 placeholder. The engine round-trip lives in validate.ts (M2b);
  // once that's wired this test will switch from `test.todo` to a real
  // assertion that each example produces ≥1 flow on its vulnerable fixture
  // and 0 on its safe fixture.
  test.todo('Gate 2 (M2b) — every example round-trips through Phase 6 engine on its fixtures');
});

describe('osv_id substitution', () => {
  test('rejects rogue osv_id on a sink', () => {
    const malicious = {
      framework: 'x',
      version: '*',
      language: 'js',
      sources: [],
      sinks: [
        {
          pattern: 'x.y(*)',
          vuln_class: 'sql_injection',
          argument_indices: [0],
          description: 'd',
          osv_id: 'CVE-9999-99999',
        },
      ],
      sanitizers: [],
    };
    expect(findRogueOsvIdInSinks(malicious)).toBe(0);
    // strict zod rejects the extra key too — belt + suspenders.
    expect(GeneratedFrameworkSpecPayloadSchema.safeParse({
      framework_spec: malicious,
      vulnerable_fixture: 'x'.repeat(20),
      safe_fixture: 'y'.repeat(20),
      reachability_level: 'confirmed',
      entry_point_class: 'PUBLIC_UNAUTH',
    }).success).toBe(false);
  });
});
