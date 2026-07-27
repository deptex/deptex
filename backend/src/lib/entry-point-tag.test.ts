/**
 * Parity + behavior test for the backend `entry_point_tag` parser (entry-point
 * auth classification, T11). The mapping table below is the shared contract
 * both copies must satisfy — the depscanner source of truth
 * (`depscanner/src/taint-engine/match-flow-to-routes.ts` parseEntryPointTag)
 * has the byte-identical implementation and the same fixtures in its tsx suite.
 * The second block reads the depscanner source and asserts the load-bearing
 * branch literals are present in both copies (scrub.ts convention).
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseEntryPointTag, entryPointClassForDto } from './entry-point-tag';

/** [tag, expected cls, expected votes]. */
const FIXTURES: Array<[string | null, string, boolean]> = [
  ['framework-route:auth_internal', 'AUTH_INTERNAL', true],
  ['framework-route:offline_worker', 'OFFLINE_WORKER', true],
  ['framework-route:public_unauth', 'PUBLIC_UNAUTH', true],
  ['framework-input:unmatched', 'PUBLIC_UNAUTH', false],
  ['framework-input:PUBLIC_UNAUTH', 'PUBLIC_UNAUTH', false], // legacy constant
  ['framework-route:bogus', 'PUBLIC_UNAUTH', false],
  ['something-else', 'PUBLIC_UNAUTH', false],
  [null, 'PUBLIC_UNAUTH', false],
];

describe('parseEntryPointTag — contract table', () => {
  for (const [tag, cls, votes] of FIXTURES) {
    it(`${tag ?? 'null'} → ${cls} (votes=${votes})`, () => {
      expect(parseEntryPointTag(tag)).toEqual({ cls, votes });
    });
  }
});

describe('entryPointClassForDto — badge visibility', () => {
  it('returns the class for voting framework-route tags', () => {
    expect(entryPointClassForDto('framework-route:auth_internal')).toBe('AUTH_INTERNAL');
    expect(entryPointClassForDto('framework-route:offline_worker')).toBe('OFFLINE_WORKER');
    expect(entryPointClassForDto('framework-route:public_unauth')).toBe('PUBLIC_UNAUTH');
  });
  it('returns null (no badge) for unmatched / legacy / null tags', () => {
    expect(entryPointClassForDto('framework-input:unmatched')).toBeNull();
    expect(entryPointClassForDto('framework-input:PUBLIC_UNAUTH')).toBeNull();
    expect(entryPointClassForDto(null)).toBeNull();
  });
});

describe('parity with the depscanner source of truth', () => {
  it('the depscanner copy carries the same load-bearing branch literals', () => {
    const depscannerPath = path.resolve(
      __dirname,
      '../../../depscanner/src/taint-engine/match-flow-to-routes.ts',
    );
    const src = fs.readFileSync(depscannerPath, 'utf8');
    // The discriminating prefix + the three voting tokens + the fail-safe default
    // must all appear in the depscanner implementation.
    expect(src).toContain("startsWith('framework-route:')");
    expect(src).toContain("'framework-route:'.length");
    expect(src).toContain("token === 'AUTH_INTERNAL' || token === 'OFFLINE_WORKER' || token === 'PUBLIC_UNAUTH'");
    expect(src).toMatch(/return \{ cls: 'PUBLIC_UNAUTH', votes: false \}/);
  });
});
