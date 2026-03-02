import { Redis } from '@upstash/redis';
import { estimateInputTokens } from './pricing';
import { getTokenPricing } from './pricing';
import { Message } from './types';

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

export interface CostCapResult {
  allowed: boolean;
  currentCostCents: number;
  capCents: number;
  message?: string;
}

export async function checkMonthlyCostCap(
  orgId: string,
  model: string,
  messages: Message[],
  monthlyCostCap: number
): Promise<CostCapResult> {
  const client = getRedisClient();
  if (!client) return { allowed: true, currentCostCents: 0, capCents: Math.round(monthlyCostCap * 100) };

  const now = new Date();
  const key = `ai:cost:${orgId}:${now.getFullYear()}:${now.getMonth() + 1}`;
  const capCents = Math.round(monthlyCostCap * 100);

  try {
    const estimatedTokens = estimateInputTokens(messages);
    const pricing = getTokenPricing(model);
    const estimatedCostCents = Math.ceil(estimatedTokens * pricing.input * 100);

    const newTotal = await client.incrby(key, estimatedCostCents);

    if (newTotal === estimatedCostCents) {
      await client.expire(key, 35 * 24 * 60 * 60);
    }

    if (newTotal > capCents) {
      await client.decrby(key, estimatedCostCents);
      const currentDollars = ((newTotal - estimatedCostCents) / 100).toFixed(2);
      const capDollars = monthlyCostCap.toFixed(2);
      return {
        allowed: false,
        currentCostCents: newTotal - estimatedCostCents,
        capCents,
        message: `Monthly AI budget reached ($${currentDollars}/$${capDollars}). An admin can increase the limit in Organization Settings > AI Configuration.`,
      };
    }

    return { allowed: true, currentCostCents: newTotal, capCents };
  } catch (err: any) {
    console.warn('[CostCap] Redis error:', err.message);
    return { allowed: true, currentCostCents: 0, capCents };
  }
}

export async function recordActualCost(
  orgId: string,
  model: string,
  inputTokens: number,
  outputTokens: number,
  estimatedInputCostCents: number
): Promise<void> {
  const client = getRedisClient();
  if (!client) return;

  const now = new Date();
  const key = `ai:cost:${orgId}:${now.getFullYear()}:${now.getMonth() + 1}`;

  try {
    const pricing = getTokenPricing(model);
    const actualCostCents = Math.ceil((inputTokens * pricing.input + outputTokens * pricing.output) * 100);
    const delta = actualCostCents - estimatedInputCostCents;
    if (delta > 0) {
      await client.incrby(key, delta);
    }
  } catch (err: any) {
    console.warn('[CostCap] Failed to record actual cost:', err.message);
  }
}

export async function checkSSEConcurrency(orgId: string): Promise<{ allowed: boolean; count: number }> {
  const client = getRedisClient();
  if (!client) return { allowed: true, count: 0 };

  const MAX_CONCURRENT = 5;
  const key = `ai:sse:${orgId}`;

  try {
    const count = await client.incr(key);
    if (count === 1) {
      await client.expire(key, 300);
    }
    if (count > MAX_CONCURRENT) {
      await client.decr(key);
      return { allowed: false, count: count - 1 };
    }
    return { allowed: true, count };
  } catch (err: any) {
    console.warn('[SSE] Redis error:', err.message);
    return { allowed: true, count: 0 };
  }
}

export async function decrementSSECounter(orgId: string): Promise<void> {
  const client = getRedisClient();
  if (!client) return;

  try {
    const key = `ai:sse:${orgId}`;
    const val = await client.decr(key);
    if (val <= 0) await client.del(key);
  } catch (err: any) {
    console.warn('[SSE] Failed to decrement counter:', err.message);
  }
}
