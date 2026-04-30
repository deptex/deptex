/**
 * Tier-1 platform-AI cost-cap gate.
 *
 * Tier-2 BYOK has its own per-org cap in `cost-cap.ts`. Tier-1 (platform-paid)
 * features instead share a single global wallet — `getPlatformProvider()` calls
 * are billed to Deptex, so abuse on any one feature could drain the whole
 * monthly budget.
 *
 * The gate is a Redis token bucket on two keys:
 *   - `ai:platform:cost:YYYY-MM`                    — global monthly USD ceiling (cents)
 *   - `ai:platform:feature:<feature>:YYYY-MM-DD`    — per-feature daily call counter
 *
 * If Redis is unreachable we fail-OPEN (allowed=true) — Redis outage shouldn't
 * black out platform AI features entirely; runaway-cost protection is a
 * defence-in-depth gate, not the primary cost control. The primary control is
 * the per-feature daily-calls limit being conservative.
 */
import { Redis } from '@upstash/redis';

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

export type PlatformAiFeature = 'malicious_explainer';

export interface PlatformFeatureLimits {
  daily_calls: number;
  monthly_cost_usd: number;
}

export const PLATFORM_AI_LIMITS: Record<PlatformAiFeature, PlatformFeatureLimits> = {
  malicious_explainer: {
    daily_calls: 5000,
    monthly_cost_usd: 50,
  },
};

export interface PlatformBudgetResult {
  allowed: boolean;
  reason?: string;
}

function monthKey(now: Date): string {
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, '0');
  return `${y}-${m}`;
}

function dayKey(now: Date): string {
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, '0');
  const d = String(now.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

/**
 * Gate before issuing a Tier-1 AI call. The estimated USD cost is added to
 * the global monthly counter and the per-feature daily counter is incremented.
 * If either exceeds its limit, the call is rejected and both counters are
 * rolled back.
 *
 * Cost is tracked in cents (integer) so Redis INCRBY stays exact.
 */
export async function checkPlatformAiBudget(
  feature: PlatformAiFeature,
  estimatedCostUsd: number
): Promise<PlatformBudgetResult> {
  const limits = PLATFORM_AI_LIMITS[feature];
  if (!limits) {
    return { allowed: false, reason: `Unknown platform AI feature: ${feature}` };
  }

  const client = getRedisClient();
  if (!client) {
    return { allowed: true };
  }

  const now = new Date();
  const monthlyKey = `ai:platform:cost:${monthKey(now)}`;
  const dailyKey = `ai:platform:feature:${feature}:${dayKey(now)}`;

  const capCents = Math.round(limits.monthly_cost_usd * 100);
  const estCents = Math.max(1, Math.ceil(estimatedCostUsd * 100));

  try {
    const newDaily = await client.incr(dailyKey);
    if (newDaily === 1) {
      await client.expire(dailyKey, 2 * 24 * 60 * 60);
    }
    if (newDaily > limits.daily_calls) {
      await client.decr(dailyKey);
      return {
        allowed: false,
        reason: `Daily ${feature} call limit reached (${limits.daily_calls}/day).`,
      };
    }

    const newMonthly = await client.incrby(monthlyKey, estCents);
    if (newMonthly === estCents) {
      await client.expire(monthlyKey, 35 * 24 * 60 * 60);
    }
    if (newMonthly > capCents) {
      await client.decrby(monthlyKey, estCents);
      await client.decr(dailyKey);
      const used = ((newMonthly - estCents) / 100).toFixed(2);
      const cap = limits.monthly_cost_usd.toFixed(2);
      return {
        allowed: false,
        reason: `Monthly platform AI budget reached ($${used}/$${cap}).`,
      };
    }

    return { allowed: true };
  } catch (err: any) {
    console.warn('[PlatformCostCap] Redis error — failing open:', err?.message ?? err);
    return { allowed: true };
  }
}

/**
 * After the AI call completes, settle the actual cost against the estimate.
 * Increments only — never decrements — because the daily-calls counter was
 * already taken at gate time and the monthly-cost counter is the only column
 * that benefits from a true-up.
 */
export async function recordActualPlatformCost(
  estimatedCostUsd: number,
  actualCostUsd: number
): Promise<void> {
  const client = getRedisClient();
  if (!client) return;

  const delta = actualCostUsd - estimatedCostUsd;
  if (delta <= 0) return;

  const deltaCents = Math.ceil(delta * 100);
  const now = new Date();
  const monthlyKey = `ai:platform:cost:${monthKey(now)}`;

  try {
    await client.incrby(monthlyKey, deltaCents);
  } catch (err: any) {
    console.warn('[PlatformCostCap] Failed to record actual cost:', err?.message ?? err);
  }
}
