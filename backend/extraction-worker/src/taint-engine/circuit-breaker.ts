/**
 * Circuit breaker + killswitch wrapper around the phase26 RPCs.
 *
 * Decisions are made by check_taint_engine_circuit_breaker (per-org rolling
 * window of taint_engine_runs). When a run fails, maybeEngageKillswitch
 * decides whether to flip taint_engine_settings.killswitch_active = true so
 * subsequent extractions skip the engine until an admin manually clears the
 * killswitch (POST /api/orgs/:orgId/taint-engine/killswitch/release, M6).
 *
 * Parameters intentionally match the phase26 RPC defaults: 60-minute window,
 * 5% failure threshold, 5-run minimum sample size before the breaker can
 * trip. These are the same constants the SQL function applies if no
 * override is passed; keeping them in code as named constants makes them
 * grep-able and visible to the M4 integration test.
 */

import type { Storage } from '../storage';

export const CIRCUIT_BREAKER_WINDOW_MINUTES = 60;
export const CIRCUIT_BREAKER_FAILURE_THRESHOLD_PCT = 5.0;
export const CIRCUIT_BREAKER_MIN_SAMPLE_SIZE = 5;

export interface CircuitBreakerState {
  shouldRun: boolean;
  recentRuns: number;
  recentFailures: number;
  failurePct: number;
  killswitchActive: boolean;
  /** Reason the breaker said no, for logging. */
  blockedReason: 'killswitch' | 'failure_rate' | null;
}

/**
 * Calls check_taint_engine_circuit_breaker and normalizes its row-set return
 * (Postgres functions returning TABLE come back as a single-element array
 * via PostgREST). Returns shouldRun=true on RPC error so a transient backend
 * blip never silently disables the engine fleet-wide.
 */
export async function checkCircuitBreaker(
  storage: Storage,
  organizationId: string,
): Promise<CircuitBreakerState> {
  const { data, error } = await storage.rpc('check_taint_engine_circuit_breaker', {
    p_organization_id: organizationId,
    p_window_minutes: CIRCUIT_BREAKER_WINDOW_MINUTES,
    p_failure_threshold_pct: CIRCUIT_BREAKER_FAILURE_THRESHOLD_PCT,
  });
  if (error) {
    return {
      shouldRun: true,
      recentRuns: 0,
      recentFailures: 0,
      failurePct: 0,
      killswitchActive: false,
      blockedReason: null,
    };
  }
  const row = Array.isArray(data) ? data[0] : data;
  if (!row) {
    return {
      shouldRun: true,
      recentRuns: 0,
      recentFailures: 0,
      failurePct: 0,
      killswitchActive: false,
      blockedReason: null,
    };
  }
  const shouldRun = Boolean(row.should_run);
  const killswitchActive = Boolean(row.killswitch_active);
  return {
    shouldRun,
    recentRuns: Number(row.recent_runs ?? 0),
    recentFailures: Number(row.recent_failures ?? 0),
    failurePct: Number(row.failure_pct ?? 0),
    killswitchActive,
    blockedReason: shouldRun ? null : killswitchActive ? 'killswitch' : 'failure_rate',
  };
}

/**
 * If the most-recent failure pushed the org over the threshold, flip the
 * killswitch via engage_taint_engine_killswitch RPC. We re-check the
 * breaker AFTER writing the failed run so the threshold computation
 * includes the failure that just happened.
 *
 * Returns true if the killswitch was engaged on this call.
 */
export async function maybeEngageKillswitch(
  storage: Storage,
  organizationId: string,
  reason: string,
): Promise<boolean> {
  const state = await checkCircuitBreaker(storage, organizationId);
  if (state.shouldRun) return false;
  if (state.killswitchActive) return false; // already engaged
  // Breaker says no for failure_rate reason — flip the switch.
  const { error } = await storage.rpc('engage_taint_engine_killswitch', {
    p_organization_id: organizationId,
    p_reason: reason,
  });
  return !error;
}
