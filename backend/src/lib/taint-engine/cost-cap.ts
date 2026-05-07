/**
 * Per-org cost-cap enforcement for the taint engine's AI features.
 *
 * Source of truth is Redis: bucket key `taint:cost:{orgId}:{yyyy-mm}`,
 * incremented atomically with INCRBYFLOAT on every AI call. ai_usage_logs
 * is still written for analytics, but the SUM-based RPC was racy under
 * concurrent extractions (two callers could both pass the precheck before
 * either incremented the counter, then both burn the cap). The Redis
 * INCRBYFLOAT-then-check + decr-on-exceed pattern eliminates the race —
 * mirrored from `backend/src/lib/ai/cost-cap.ts` (Aegis cost-cap).
 *
 * Used pre-call by:
 *   - inferFrameworkSpec route handler (spec inference)
 *   - M7's per-flow FP filter
 *   - rule-generation-step pLimit(5) loop
 *   - EPD Anthropic fallback
 *
 * The depscanner worker uses the same Redis key shape via
 * `depscanner/src/taint-engine/cost-cap.ts` so both surfaces converge on
 * one counter.
 */

import { Redis } from '@upstash/redis';
import { supabase } from '../supabase';
import { DEFAULT_MONTHLY_AI_COST_CAP_USD } from '../taint-engine-defaults';

let redisClient: Redis | null = null;

function getRedisClient(): Redis | null {
  if (!redisClient) {
    const url = process.env.UPSTASH_REDIS_URL;
    const token = process.env.UPSTASH_REDIS_TOKEN;
    if (!url || !token) return null;
    redisClient = new Redis({ url, token });
  }
  return redisClient;
}

/** Same key shape used by the depscanner worker. Keep in sync. */
function bucketKey(organizationId: string): string {
  const now = new Date();
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
  return `taint:cost:${organizationId}:${yyyy}-${mm}`;
}

/** Bucket lives ~35d so it survives the calendar month boundary. */
const BUCKET_TTL_SECONDS = 35 * 24 * 60 * 60;

export interface CostCapState {
  capUsd: number;
  spentUsdThisMonth: number;
  remainingUsd: number;
  /** True when the cap has been blown; false otherwise. */
  exceeded: boolean;
}

async function readCapForOrg(organizationId: string): Promise<number> {
  const { data: settingsRow } = await supabase
    .from('taint_engine_settings')
    .select('monthly_ai_cost_cap_usd')
    .eq('organization_id', organizationId)
    .maybeSingle();
  const raw = (settingsRow as { monthly_ai_cost_cap_usd?: number } | null)?.monthly_ai_cost_cap_usd;
  const cap = Number(raw ?? DEFAULT_MONTHLY_AI_COST_CAP_USD);
  return Number.isFinite(cap) ? cap : DEFAULT_MONTHLY_AI_COST_CAP_USD;
}

async function readSpentFromRedis(organizationId: string): Promise<number> {
  const client = getRedisClient();
  if (!client) {
    // Fail-closed on missing Redis config: callers treat this as cap
    // exhausted so a misconfigured env can't silently disable enforcement.
    throw new CostCapInfraError('Redis client not configured (UPSTASH_REDIS_URL/UPSTASH_REDIS_TOKEN)');
  }
  const raw = await client.get<string | number | null>(bucketKey(organizationId));
  if (raw === null || raw === undefined) return 0;
  const v = typeof raw === 'number' ? raw : parseFloat(String(raw));
  return Number.isFinite(v) ? v : 0;
}

export class CostCapInfraError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CostCapInfraError';
  }
}

export class CostCapExceededError extends Error {
  constructor(public readonly state: CostCapState, public readonly projectedAdditionalUsd: number) {
    super(
      `taint engine AI cost cap exceeded: $${state.spentUsdThisMonth.toFixed(4)} spent of $${state.capUsd.toFixed(2)} cap, projected +$${projectedAdditionalUsd.toFixed(4)}`,
    );
    this.name = 'CostCapExceededError';
  }
}

export async function getCostCapState(organizationId: string): Promise<CostCapState> {
  const capUsd = await readCapForOrg(organizationId);
  const spent = await readSpentFromRedis(organizationId);
  const remaining = Math.max(0, capUsd - spent);
  return {
    capUsd,
    spentUsdThisMonth: spent,
    remainingUsd: remaining,
    exceeded: spent >= capUsd,
  };
}

/**
 * Atomic check-and-increment. Increments the Redis bucket by
 * `projectedAdditionalUsd`; if the new total exceeds the cap, decrements
 * back and throws. Mirrors `checkMonthlyCostCap` in ai/cost-cap.ts but
 * works in USD floats (INCRBYFLOAT) so per-call estimates can stay
 * fractional cents without rounding.
 *
 * Returns the post-increment state on success — callers can use
 * `state.spentUsdThisMonth` for telemetry.
 *
 * Throws `CostCapInfraError` when Redis is unavailable. Callers that want
 * to fail-closed should let it propagate; the engine's runner translates
 * it into `skippedReason='cost_cap_unavailable'` so admins can see why
 * the AI layer disengaged.
 */
export async function assertWithinCostCap(
  organizationId: string,
  projectedAdditionalUsd = 0,
): Promise<CostCapState> {
  const client = getRedisClient();
  if (!client) {
    throw new CostCapInfraError('Redis client not configured (UPSTASH_REDIS_URL/UPSTASH_REDIS_TOKEN)');
  }
  const capUsd = await readCapForOrg(organizationId);
  const key = bucketKey(organizationId);

  // INCRBYFLOAT is atomic on Upstash. Negative values are also accepted, so
  // refunding on overshoot uses the same primitive (no DECRBYFLOAT exists).
  const newTotalRaw = await client.incrbyfloat(key, projectedAdditionalUsd);
  const newTotal = typeof newTotalRaw === 'number' ? newTotalRaw : parseFloat(String(newTotalRaw));

  // Set TTL on first write so the key naturally rolls over after the
  // calendar month. We can't tell first-vs-existing from incrbyfloat, so
  // re-issue EXPIRE with NX semantics — Upstash accepts EXPIRE without NX
  // and the call is idempotent (overwrites with same value).
  if (Number.isFinite(newTotal) && Math.abs(newTotal - projectedAdditionalUsd) < 1e-9) {
    await client.expire(key, BUCKET_TTL_SECONDS);
  }

  if (!Number.isFinite(newTotal)) {
    // Defensive: reset on parse failure rather than leak a bad value.
    await client.set(key, 0, { ex: BUCKET_TTL_SECONDS });
    throw new CostCapInfraError(`incrbyfloat returned non-numeric: ${String(newTotalRaw)}`);
  }

  if (newTotal > capUsd) {
    // Refund the projected amount so two concurrent over-the-cap callers
    // don't compound the overshoot in the bucket.
    await client.incrbyfloat(key, -projectedAdditionalUsd);
    const stateAtFailure: CostCapState = {
      capUsd,
      spentUsdThisMonth: newTotal - projectedAdditionalUsd,
      remainingUsd: Math.max(0, capUsd - (newTotal - projectedAdditionalUsd)),
      exceeded: true,
    };
    throw new CostCapExceededError(stateAtFailure, projectedAdditionalUsd);
  }

  return {
    capUsd,
    spentUsdThisMonth: newTotal,
    remainingUsd: Math.max(0, capUsd - newTotal),
    exceeded: false,
  };
}

/**
 * Refund a reservation when the actual call ended up cheaper than projected
 * (or never fired at all — abort, transient error, etc). Pass a positive
 * `refundUsd`; we negate internally.
 */
export async function refundReservation(organizationId: string, refundUsd: number): Promise<void> {
  if (refundUsd <= 0) return;
  const client = getRedisClient();
  if (!client) return;
  await client.incrbyfloat(bucketKey(organizationId), -refundUsd);
}
