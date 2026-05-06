/**
 * Worker-side mirror of `backend/src/lib/taint-engine/cost-cap.ts`.
 *
 * Same Redis key shape (`taint:cost:{orgId}:{yyyy-mm}`), same INCRBYFLOAT
 * atomic check-and-increment + decr-on-exceed. Two surfaces (route + worker)
 * write to one bucket so concurrent extractions can't both burn the cap.
 *
 * **Constants must match the backend module byte-for-byte** — there is a
 * unit test that asserts that. If you change the key shape or the default
 * cap here, change it there too.
 */

import { Redis } from '@upstash/redis';
import type { Storage } from '../storage';

/**
 * Default monthly Tier-2 AI spend cap, in USD. Mirrors
 * `backend/src/lib/taint-engine-defaults.ts:DEFAULT_MONTHLY_AI_COST_CAP_USD`.
 * The depscanner can't import from `backend/src/lib`, so we duplicate the
 * constant; a unit test asserts the two values match.
 */
export const DEFAULT_MONTHLY_AI_COST_CAP_USD = 75;

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

/** Internal: reset client for tests that swap env between cases. */
export function _resetRedisClient(): void {
  redisClient = null;
}

function bucketKey(organizationId: string): string {
  const now = new Date();
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
  return `taint:cost:${organizationId}:${yyyy}-${mm}`;
}

const BUCKET_TTL_SECONDS = 35 * 24 * 60 * 60;

export class CostCapInfraError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CostCapInfraError';
  }
}

export class CostCapExceededError extends Error {
  constructor(public readonly capUsd: number, public readonly spentUsd: number, public readonly projectedUsd: number) {
    super(
      `taint engine AI cost cap exceeded: $${spentUsd.toFixed(4)} of $${capUsd.toFixed(2)}, projected +$${projectedUsd.toFixed(4)}`,
    );
    this.name = 'CostCapExceededError';
  }
}

export interface CostCapState {
  capUsd: number;
  spentUsdThisMonth: number;
  remainingUsd: number;
  exceeded: boolean;
}

async function readCapForOrg(storage: Storage, organizationId: string): Promise<number> {
  const { data: settingsRow } = await storage
    .from('taint_engine_settings')
    .select('monthly_ai_cost_cap_usd')
    .eq('organization_id', organizationId)
    .maybeSingle();
  const raw = (settingsRow as { monthly_ai_cost_cap_usd?: number | string } | null)?.monthly_ai_cost_cap_usd;
  const cap = Number(raw ?? DEFAULT_MONTHLY_AI_COST_CAP_USD);
  return Number.isFinite(cap) ? cap : DEFAULT_MONTHLY_AI_COST_CAP_USD;
}

/**
 * Atomic check-and-increment. Mirrors the backend module's behavior; see
 * that file's docstring for design rationale.
 *
 * Throws `CostCapInfraError` when Redis is unavailable so callers can
 * fail-closed cleanly. Throws `CostCapExceededError` when the projected
 * cost would push the bucket over the cap (after refunding the increment).
 */
export async function assertWithinCostCap(
  storage: Storage,
  organizationId: string,
  projectedAdditionalUsd: number,
): Promise<CostCapState> {
  const client = getRedisClient();
  if (!client) {
    throw new CostCapInfraError('Redis client not configured (UPSTASH_REDIS_URL/UPSTASH_REDIS_TOKEN)');
  }
  const capUsd = await readCapForOrg(storage, organizationId);
  const key = bucketKey(organizationId);

  const newTotalRaw = await client.incrbyfloat(key, projectedAdditionalUsd);
  const newTotal = typeof newTotalRaw === 'number' ? newTotalRaw : parseFloat(String(newTotalRaw));

  if (Number.isFinite(newTotal) && Math.abs(newTotal - projectedAdditionalUsd) < 1e-9) {
    await client.expire(key, BUCKET_TTL_SECONDS);
  }

  if (!Number.isFinite(newTotal)) {
    await client.set(key, 0, { ex: BUCKET_TTL_SECONDS });
    throw new CostCapInfraError(`incrbyfloat returned non-numeric: ${String(newTotalRaw)}`);
  }

  if (newTotal > capUsd) {
    await client.incrbyfloat(key, -projectedAdditionalUsd);
    throw new CostCapExceededError(capUsd, newTotal - projectedAdditionalUsd, projectedAdditionalUsd);
  }

  return {
    capUsd,
    spentUsdThisMonth: newTotal,
    remainingUsd: Math.max(0, capUsd - newTotal),
    exceeded: false,
  };
}

/** Refund a reservation when the actual call cost less than projected. */
export async function refundReservation(organizationId: string, refundUsd: number): Promise<void> {
  if (refundUsd <= 0) return;
  const client = getRedisClient();
  if (!client) return;
  await client.incrbyfloat(bucketKey(organizationId), -refundUsd);
}

/**
 * Read-only spent-so-far snapshot. Used for telemetry / display. Returns
 * `null` if Redis is unavailable so callers can decide whether to
 * fail-open (display "unknown") or fail-closed (skip the AI batch).
 */
export async function readSpentUsd(organizationId: string): Promise<number | null> {
  const client = getRedisClient();
  if (!client) return null;
  const raw = await client.get<string | number | null>(bucketKey(organizationId));
  if (raw === null || raw === undefined) return 0;
  const v = typeof raw === 'number' ? raw : parseFloat(String(raw));
  return Number.isFinite(v) ? v : 0;
}
