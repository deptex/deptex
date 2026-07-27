/**
 * Phase 6.5 / M5 task 28 — `aggregateEpdFromFlows` + `parsePerFlowVerdict` +
 * `shouldFallbackToAnthropic` unit coverage. Exercises the seven new
 * EpdStatus paths the orchestrator can produce:
 *
 *   - 'flow_aggregated' — happy path (≥1 high-confidence flow voted in MAX)
 *   - 'no_flows_evaluated' — empty array
 *   - 'all_flows_suppressed' — every input flow is user-suppressed
 *   - 'ai_truncated' / 'kept_on_error' — error-path flows excluded from MAX
 *   - low-confidence sanitization filtered out (vote/render parity)
 *   - worst-case endpoint pick across surviving flows
 *   - all-sanitized PDV rollup (one un-sanitized leak fails the rollup)
 *
 * Plus the gating logic for the OD-6 Anthropic fallback.
 */

import {
  aggregateEpdFromFlows,
  parsePerFlowVerdict,
  shouldFallbackToAnthropic,
  type PerFlowVerdict,
} from '../epd';
import { MAX_VOTE_THRESHOLD, UNCERTAIN_UPPER } from '../taint-engine/confidence-thresholds';

function makeVerdict(overrides: Partial<PerFlowVerdict> = {}): PerFlowVerdict {
  return {
    flowId: 'f-1',
    isSuppressed: false,
    filterVerdict: 'kept',
    sanitization: { is_sanitized: false, confidence: 0.9 },
    endpoint: { classification: 'PUBLIC_UNAUTH' },
    flowLength: 3,
    reachabilitySource: 'taint_engine',
    entryPointTag: 'framework-input:PUBLIC_UNAUTH',
    ...overrides,
  };
}

describe('aggregateEpdFromFlows — empty + suppression states', () => {
  it('returns no_flows_evaluated on empty input (UNKNOWN endpoint, not sanitized)', () => {
    const r = aggregateEpdFromFlows([], 8.0, 'confirmed', true);
    expect(r.epd_status).toBe('no_flows_evaluated');
    expect(r.entry_point_classification).toBe('UNKNOWN');
    expect(r.is_sanitized).toBe(false);
    expect(r.flowsAggregated).toBe(0);
  });

  it('returns all_flows_suppressed when every flow is user-suppressed (retains last verdict)', () => {
    const last = makeVerdict({
      isSuppressed: true,
      sanitization: { is_sanitized: true, confidence: 0.9 },
      endpoint: { classification: 'OFFLINE_WORKER' },
    });
    const r = aggregateEpdFromFlows([
      makeVerdict({ isSuppressed: true }),
      last,
    ], 5.0, 'confirmed', true);
    expect(r.epd_status).toBe('all_flows_suppressed');
    // Retains last suppressed flow's verdict so depscore reflects user judgement.
    expect(r.entry_point_classification).toBe('OFFLINE_WORKER');
    expect(r.is_sanitized).toBe(true);
  });

  it('collapses to no_flows_evaluated when all surviving flows are ai_truncated or kept_on_error', () => {
    const r = aggregateEpdFromFlows([
      makeVerdict({ filterVerdict: 'ai_truncated' }),
      makeVerdict({ filterVerdict: 'kept_on_error' }),
    ], 5.0, 'confirmed', true);
    expect(r.epd_status).toBe('no_flows_evaluated');
    expect(r.flowsConsidered).toBe(2);
    expect(r.flowsAggregated).toBe(0);
  });
});

describe('aggregateEpdFromFlows — two-vote-set split (Core Semantics 7)', () => {
  // The AI endpoint verdict is gated by the SAME sanitization-confidence bar as
  // the sanitization vote, so a no-auth-map scan scores identically to pre-arc: a
  // sub-threshold flow with no route evidence casts no endpoint vote. But
  // framework-route EVIDENCE is independent of sanitization confidence, so a
  // sub-threshold flow carrying a voting `framework-route:` tag STILL demotes.
  it(`sub-threshold flow's AI endpoint verdict is gated → no vote without evidence`, () => {
    const lowConf = makeVerdict({
      endpoint: { classification: 'PUBLIC_UNAUTH' },
      sanitization: { is_sanitized: true, confidence: MAX_VOTE_THRESHOLD - 0.01 },
      entryPointTag: 'framework-input:PUBLIC_UNAUTH', // legacy constant, no vote
    });
    const r = aggregateEpdFromFlows([lowConf], 5.0, 'confirmed', true);
    // No auth evidence + sub-threshold AI verdict → no endpoint vote → identical to
    // the legacy coupled filter (the no-auth-map path is unchanged).
    expect(r.epd_status).toBe('no_flows_evaluated');
  });

  it(`sub-threshold flow with framework-route EVIDENCE still votes (evidence is unconditional)`, () => {
    const lowConfAuthed = makeVerdict({
      endpoint: { classification: 'UNKNOWN' },
      sanitization: { is_sanitized: true, confidence: MAX_VOTE_THRESHOLD - 0.01 },
      entryPointTag: 'framework-route:auth_internal', // real route evidence, votes
    });
    const r = aggregateEpdFromFlows([lowConfAuthed], 5.0, 'confirmed', true);
    // Evidence demotes even below the AI confidence bar.
    expect(r.epd_status).toBe('flow_aggregated');
    expect(r.entry_point_classification).toBe('AUTH_INTERNAL');
    // Sanitization still gated — a sub-threshold sanitizer is not trusted.
    expect(r.is_sanitized).toBe(false);
  });

  it('an auth demotion re-weights the entry point but never mutates reachability_status', () => {
    const shared = { sanitization: { is_sanitized: false, confidence: 0.9 }, endpoint: { classification: 'UNKNOWN' as const } };
    const asPublic = aggregateEpdFromFlows(
      [makeVerdict({ ...shared, entryPointTag: 'framework-input:PUBLIC_UNAUTH' })], 5.0, 'confirmed', true);
    const asAuthed = aggregateEpdFromFlows(
      [makeVerdict({ ...shared, entryPointTag: 'framework-route:auth_internal' })], 5.0, 'confirmed', true);
    // The evidence demotes the entry-point class...
    expect(asAuthed.entry_point_classification).toBe('AUTH_INTERNAL');
    expect(asPublic.entry_point_classification).not.toBe('AUTH_INTERNAL');
    // ...but reachability_status is derived from (reachabilityLevel, isReachable)
    // only, so it is identical — EPD auth scoring never touches the reachability
    // tier (a demotion can never hide a finding from the visible set).
    expect(asAuthed.reachability_status).toBe(asPublic.reachability_status);
  });

  it(`sub-threshold flow with NO endpoint + NO evidence contributes nothing`, () => {
    const lowConfNoEndpoint = makeVerdict({
      endpoint: null,
      sanitization: { is_sanitized: true, confidence: MAX_VOTE_THRESHOLD - 0.01 },
      entryPointTag: 'framework-input:PUBLIC_UNAUTH', // legacy constant, no vote
    });
    const r = aggregateEpdFromFlows([lowConfNoEndpoint], 5.0, 'confirmed', true);
    expect(r.epd_status).toBe('no_flows_evaluated');
  });

  it(`keeps flows whose sanitization confidence === ${MAX_VOTE_THRESHOLD} (sanitization voter)`, () => {
    const exact = makeVerdict({
      sanitization: { is_sanitized: false, confidence: MAX_VOTE_THRESHOLD },
    });
    const r = aggregateEpdFromFlows([exact], 5.0, 'confirmed', true);
    expect(r.epd_status).toBe('flow_aggregated');
    expect(r.flowsAggregated).toBe(1);
  });
});

describe('aggregateEpdFromFlows — evidence merge (Core Semantics 7 matrix)', () => {
  // matched route evidence rides on entryPointTag as framework-route:<class>.
  const ev = (cls: 'auth_internal' | 'offline_worker' | 'public_unauth') => `framework-route:${cls}`;

  it('verdict-less + evidence-authed + sanitization-filtered → demotes (intended expansion)', () => {
    // No AI verdict at all (endpoint null, sanitization null → not a sanitization
    // voter), but the flow's source fell inside an authed handler span.
    const f = makeVerdict({
      endpoint: null,
      sanitization: null,
      filterVerdict: null,
      entryPointTag: ev('auth_internal'),
    });
    const r = aggregateEpdFromFlows([f], 10.0, 'confirmed', true);
    expect(r.epd_status).toBe('flow_aggregated');
    expect(r.entry_point_classification).toBe('AUTH_INTERNAL');
    expect(r.entry_point_weight).toBe(0.5); // demoted from the UNKNOWN 1.0 it'd get today
    expect(r.is_sanitized).toBe(false);
  });

  it('AI-public verdict is never overridden by evidence-authed (Locked-6)', () => {
    const f = makeVerdict({
      endpoint: { classification: 'PUBLIC_UNAUTH' },
      sanitization: { is_sanitized: false, confidence: 0.9 },
      entryPointTag: ev('auth_internal'),
    });
    const r = aggregateEpdFromFlows([f], 10.0, 'confirmed', true);
    expect(r.entry_point_classification).toBe('PUBLIC_UNAUTH');
  });

  it('evidence-offline_worker demotes a verdict-less flow to weight 0.2', () => {
    const f = makeVerdict({
      endpoint: null,
      sanitization: null,
      filterVerdict: null,
      entryPointTag: ev('offline_worker'),
    });
    const r = aggregateEpdFromFlows([f], 10.0, 'confirmed', true);
    expect(r.entry_point_classification).toBe('OFFLINE_WORKER');
    expect(r.entry_point_weight).toBe(0.2);
  });

  it('unmatched tag never votes (verdict-less unmatched flow contributes nothing)', () => {
    const f = makeVerdict({
      endpoint: null,
      sanitization: null,
      filterVerdict: null,
      entryPointTag: 'framework-input:unmatched',
    });
    const r = aggregateEpdFromFlows([f], 10.0, 'confirmed', true);
    expect(r.epd_status).toBe('no_flows_evaluated');
  });

  it('legacy constant tag never votes (detector-coerced flow contributes nothing)', () => {
    const f = makeVerdict({
      endpoint: null,
      sanitization: null,
      filterVerdict: null,
      entryPointTag: 'framework-input:PUBLIC_UNAUTH',
    });
    const r = aggregateEpdFromFlows([f], 10.0, 'confirmed', true);
    expect(r.epd_status).toBe('no_flows_evaluated');
  });

  it('suppressed-public + surviving evidence-authed → AUTH_INTERNAL (suppressed excluded)', () => {
    const suppressedPublic = makeVerdict({
      isSuppressed: true,
      endpoint: { classification: 'PUBLIC_UNAUTH' },
      sanitization: { is_sanitized: false, confidence: 0.9 },
    });
    const authed = makeVerdict({
      endpoint: null,
      sanitization: null,
      filterVerdict: null,
      entryPointTag: ev('auth_internal'),
    });
    const r = aggregateEpdFromFlows([suppressedPublic, authed], 10.0, 'confirmed', true);
    expect(r.entry_point_classification).toBe('AUTH_INTERNAL');
  });

  it('evidence-authed + AI-authed agree → AUTH_INTERNAL (worst-case of equals)', () => {
    const f = makeVerdict({
      endpoint: { classification: 'AUTH_INTERNAL' },
      sanitization: { is_sanitized: false, confidence: 0.9 },
      entryPointTag: ev('auth_internal'),
    });
    const r = aggregateEpdFromFlows([f], 10.0, 'confirmed', true);
    expect(r.entry_point_classification).toBe('AUTH_INTERNAL');
    expect(r.entry_point_weight).toBe(0.5);
  });
});

describe('aggregateEpdFromFlows — worst-case endpoint pick', () => {
  it('picks PUBLIC_UNAUTH over AUTH_INTERNAL over OFFLINE_WORKER', () => {
    const r = aggregateEpdFromFlows([
      makeVerdict({ endpoint: { classification: 'OFFLINE_WORKER' } }),
      makeVerdict({ endpoint: { classification: 'PUBLIC_UNAUTH' } }),
      makeVerdict({ endpoint: { classification: 'AUTH_INTERNAL' } }),
    ], 5.0, 'confirmed', true);
    expect(r.entry_point_classification).toBe('PUBLIC_UNAUTH');
  });

  it('returns AUTH_INTERNAL when only auth/offline flows survive', () => {
    const r = aggregateEpdFromFlows([
      makeVerdict({ endpoint: { classification: 'OFFLINE_WORKER' } }),
      makeVerdict({ endpoint: { classification: 'AUTH_INTERNAL' } }),
    ], 5.0, 'confirmed', true);
    expect(r.entry_point_classification).toBe('AUTH_INTERNAL');
  });
});

describe('aggregateEpdFromFlows — sanitization rollup', () => {
  it('PDV is_sanitized=true only when EVERY surviving flow is sanitized=true', () => {
    const r = aggregateEpdFromFlows([
      makeVerdict({ sanitization: { is_sanitized: true, confidence: 0.9 } }),
      makeVerdict({ sanitization: { is_sanitized: true, confidence: 0.9 } }),
    ], 5.0, 'confirmed', true);
    expect(r.is_sanitized).toBe(true);
  });

  it('a single un-sanitized survivor flips PDV is_sanitized=false', () => {
    const r = aggregateEpdFromFlows([
      makeVerdict({ sanitization: { is_sanitized: true, confidence: 0.9 } }),
      makeVerdict({ sanitization: { is_sanitized: false, confidence: 0.9 } }),
    ], 5.0, 'confirmed', true);
    expect(r.is_sanitized).toBe(false);
  });

  it('null is_sanitized counts as not sanitized (AI couldn’t verify → safe-default)', () => {
    const r = aggregateEpdFromFlows([
      makeVerdict({ sanitization: { is_sanitized: null, confidence: 0.9 } }),
    ], 5.0, 'confirmed', true);
    expect(r.is_sanitized).toBe(false);
  });
});

describe('aggregateEpdFromFlows — depth + factor', () => {
  it('uses min flow_length - 1 as depth (shortest hop closest to source)', () => {
    const r = aggregateEpdFromFlows([
      makeVerdict({ flowLength: 5 }),
      makeVerdict({ flowLength: 2 }),
    ], 5.0, 'confirmed', true);
    expect(r.epd_depth).toBe(1);
  });

  it('contextual_depscore = baseScore * factor when reachable', () => {
    const r = aggregateEpdFromFlows([
      makeVerdict({ flowLength: 1, endpoint: { classification: 'PUBLIC_UNAUTH' } }),
    ], 10.0, 'confirmed', true);
    // depth=0, weight=1.0, alpha^0=1, isSanitized=false → factor=1.0 → contextual=10.0
    expect(r.epd_factor).toBeCloseTo(1.0);
    expect(r.contextual_depscore).toBeCloseTo(10.0);
  });

  it('zeroes contextual_depscore when reachability_status === unreachable', () => {
    const r = aggregateEpdFromFlows([], 10.0, 'unreachable', false);
    expect(r.contextual_depscore).toBe(0);
    expect(r.epd_factor).toBe(0);
  });
});

describe('parsePerFlowVerdict — synthetic node JSONB extraction', () => {
  it('parses all three synthetic verdict nodes from flow_nodes', () => {
    const flowNodes = [
      { kind: 'source', file: 'a.ts', line: 1 },
      { kind: 'sink', file: 'b.ts', line: 2 },
      {
        kind: 'ai_filter_verdict', synthetic: true,
        verdict: 'kept', confidence: 0.9, model: 'qwen', reasoning: 'r',
      },
      {
        kind: 'ai_sanitization_verdict', synthetic: true,
        is_sanitized: true, confidence: 0.85, sanitizer_line: 12,
      },
      {
        kind: 'ai_endpoint_verdict', synthetic: true,
        classification: 'PUBLIC_UNAUTH',
      },
    ];
    const v = parsePerFlowVerdict({
      flowNodes,
      flowLength: 4,
      reachabilitySource: 'taint_engine',
      entryPointTag: null,
      isSuppressed: false,
    });
    expect(v.filterVerdict).toBe('kept');
    expect(v.sanitization).toEqual({
      is_sanitized: true,
      confidence: 0.85,
      reasoning: null,
      sanitizer_line: 12,
    });
    expect(v.endpoint).toEqual({ classification: 'PUBLIC_UNAUTH', reasoning: null });
  });

  it('ignores non-synthetic nodes with the same kind name', () => {
    const flowNodes = [
      { kind: 'ai_endpoint_verdict', classification: 'PUBLIC_UNAUTH' /* synthetic missing */ },
    ];
    const v = parsePerFlowVerdict({
      flowNodes,
      flowLength: 1,
      reachabilitySource: 'taint_engine',
      entryPointTag: null,
      isSuppressed: false,
    });
    expect(v.endpoint).toBeNull();
  });

  it('handles malformed flow_nodes gracefully (returns nulls, no throw)', () => {
    const v = parsePerFlowVerdict({
      flowNodes: 'not an array',
      flowLength: 1,
      reachabilitySource: null,
      entryPointTag: null,
      isSuppressed: false,
    });
    expect(v.filterVerdict).toBeNull();
    expect(v.sanitization).toBeNull();
    expect(v.endpoint).toBeNull();
  });

  it('clamps confidence into [0,1]', () => {
    const v = parsePerFlowVerdict({
      flowNodes: [{
        kind: 'ai_sanitization_verdict', synthetic: true,
        is_sanitized: true, confidence: 1.5,
      }],
      flowLength: 1,
      reachabilitySource: null,
      entryPointTag: null,
      isSuppressed: false,
    });
    expect(v.sanitization?.confidence).toBe(1);
  });
});

describe('shouldFallbackToAnthropic — gating logic', () => {
  it('FLAG-OFF GUARD: never fires when cveTargetedTaintEnabled=false', () => {
    expect(shouldFallbackToAnthropic({
      cveTargetedTaintEnabled: false,
      flowsCount: 100,
      keptOnErrorRate: 0.9,
      pdvHasHighConfidenceFlow: false,
      tripleIsDegraded: true,
    })).toBe(false);
  });

  it('does NOT fire on small extractions even with high error rate (sample-size noise floor)', () => {
    expect(shouldFallbackToAnthropic({
      cveTargetedTaintEnabled: true,
      flowsCount: 10, // < 20
      keptOnErrorRate: 0.5,
      pdvHasHighConfidenceFlow: false,
      tripleIsDegraded: false,
    })).toBe(false);
  });

  it('fires when ≥20 flows AND keptOnErrorRate > 20%', () => {
    expect(shouldFallbackToAnthropic({
      cveTargetedTaintEnabled: true,
      flowsCount: 30,
      keptOnErrorRate: 0.25,
      pdvHasHighConfidenceFlow: true, // even with high conf, error-rate gate still fires
      tripleIsDegraded: false,
    })).toBe(true);
  });

  it('fires when triple is degraded AND no high-confidence flow on this PDV', () => {
    expect(shouldFallbackToAnthropic({
      cveTargetedTaintEnabled: true,
      flowsCount: 5,
      keptOnErrorRate: 0,
      pdvHasHighConfidenceFlow: false,
      tripleIsDegraded: true,
    })).toBe(true);
  });

  it('does NOT fire when triple is degraded but PDV already has a high-confidence flow', () => {
    expect(shouldFallbackToAnthropic({
      cveTargetedTaintEnabled: true,
      flowsCount: 5,
      keptOnErrorRate: 0,
      pdvHasHighConfidenceFlow: true,
      tripleIsDegraded: true,
    })).toBe(false);
  });
});

describe('confidence-thresholds — frontend mirror byte-equal', () => {
  it('frontend mirror constants byte-match the worker module', () => {
    // Read the frontend module as text so jest doesn't have to cross the
    // package boundary at runtime — the file lives outside backend/'s rootDir
    // and dynamic-importing it would require a tsconfig path mapping for
    // every CI runner. Source-of-truth is the worker module; this test fails
    // loudly when the frontend mirror drifts.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const fs = require('fs');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const path = require('path');
    const mirrorPath = path.resolve(
      __dirname,
      '../../../frontend/src/lib/security/confidence-thresholds.ts',
    );
    const src = fs.readFileSync(mirrorPath, 'utf8');
    // Match exact `export const NAME = NUMBER;` lines so accidental whitespace
    // or string-coercion changes still flag the test.
    expect(src).toMatch(/export const HIDE_BELOW = 0\.5;/);
    expect(src).toMatch(new RegExp(`export const UNCERTAIN_UPPER = ${UNCERTAIN_UPPER};`));
    expect(src).toMatch(/export const MAX_VOTE_THRESHOLD = UNCERTAIN_UPPER;/);
    // Sanity: the worker-side aliases also resolve to the same value.
    expect(MAX_VOTE_THRESHOLD).toBe(UNCERTAIN_UPPER);
  });
});
