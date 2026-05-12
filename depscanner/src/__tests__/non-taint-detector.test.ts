/**
 * Unit tests for the F4 non-taint detector prototype.
 *
 * These tests exercise the stand-alone `detectSanitizerAbsence` building
 * block on synthetic CallSite + FrameworkSpec inputs. They do NOT run the
 * full taint pipeline; the detector is not wired in yet (see
 * `docs/non-taint-detector-regime.md`).
 *
 * Scenarios covered (one per F4 sub-shape):
 *
 *   1. Required kwarg ABSENT  → finding fires
 *      Models CVE-2022-23539: `jwt.verify(token, key)` without the
 *      `algorithms` option.
 *
 *   2. Forbidden literal PRESENT → finding fires
 *      Models CVE-2024-35195: `requests.Session(verify=False)`.
 *
 *   3. Required kwarg PRESENT → finding suppressed
 *      Sanity check that the hardened-call shape does not produce a false
 *      positive.
 */

import {
  detectSanitizerAbsence,
  type CallSite,
  type NonTaintFrameworkSink,
} from '../taint-engine/non-taint-detector';
import type { FrameworkSpec } from '../taint-engine/spec';

function makeSpec(sinks: NonTaintFrameworkSink[]): FrameworkSpec {
  return {
    framework: 'test',
    version: '*',
    language: 'js',
    sources: [],
    sinks,
    sanitizers: [],
  };
}

describe('detectSanitizerAbsence', () => {
  it('fires on a sink whose required kwarg is missing (CVE-2022-23539 shape)', () => {
    const spec = makeSpec([
      {
        pattern: 'jwt.verify(*)',
        vuln_class: 'auth_bypass',
        argument_indices: [],
        description: 'jwt.verify without an algorithms allowlist',
        required_arguments: [{ name: 'algorithms', match_mode: 'required' }],
      },
    ]);

    const callsites: CallSite[] = [
      {
        calleeText: 'jwt.verify',
        argTexts: ['token', 'key'],
        kwargNames: [],
        filePath: 'src/handler.js',
        line: 12,
        column: 4,
      },
    ];

    const findings = detectSanitizerAbsence(spec, callsites);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      vuln_class: 'auth_bypass',
      sink_file: 'src/handler.js',
      sink_line: 12,
      sink_method: 'jwt.verify',
      sink_pattern: 'jwt.verify(*)',
      trigger: { argument_name: 'algorithms', match_mode: 'required' },
    });
    expect(findings[0].engine_confidence).toBeGreaterThan(0.5);
    expect(findings[0].id.startsWith('ntd_')).toBe(true);
  });

  it('fires on a forbidden literal value (CVE-2024-35195 shape)', () => {
    const spec = makeSpec([
      {
        pattern: 'requests.Session(*)',
        vuln_class: 'auth_bypass',
        argument_indices: [],
        description: 'requests.Session with verify disabled',
        required_arguments: [
          {
            name: 'verify',
            match_mode: 'forbidden',
            unsafe_literals: ['False', 'false', '0'],
          },
        ],
      },
    ]);

    const callsites: CallSite[] = [
      {
        calleeText: 'requests.Session',
        argTexts: [],
        kwargNames: ['verify'],
        kwargValues: { verify: 'False' },
        filePath: 'app.py',
        line: 7,
        column: 2,
      },
    ];

    const findings = detectSanitizerAbsence(spec, callsites);

    expect(findings).toHaveLength(1);
    expect(findings[0].trigger.observed_literal).toBe('False');
  });

  it('suppresses the finding when the required kwarg is present', () => {
    const spec = makeSpec([
      {
        pattern: 'jwt.verify(*)',
        vuln_class: 'auth_bypass',
        argument_indices: [],
        description: 'jwt.verify without an algorithms allowlist',
        required_arguments: [{ name: 'algorithms', match_mode: 'required' }],
      },
    ]);

    const callsites: CallSite[] = [
      {
        calleeText: 'jwt.verify',
        argTexts: ['token', 'key', '{ algorithms: ["HS256"] }'],
        kwargNames: ['algorithms'],
        kwargValues: { algorithms: '["HS256"]' },
        filePath: 'src/handler.js',
        line: 12,
        column: 4,
      },
    ];

    const findings = detectSanitizerAbsence(spec, callsites);
    expect(findings).toHaveLength(0);
  });
});
