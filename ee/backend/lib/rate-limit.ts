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

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds?: number;
}

/**
 * Sliding-window rate limiter backed by Redis INCR + EXPIRE.
 *
 * If Redis is unavailable the request is allowed (fail-open)
 * so that rate limiting never blocks core functionality.
 */
export async function checkRateLimit(
  key: string,
  maxRequests: number,
  windowSeconds: number
): Promise<RateLimitResult> {
  const client = getRedisClient();
  if (!client) {
    return { allowed: true, remaining: maxRequests };
  }

  try {
    const fullKey = `rl:${key}`;
    const count = await client.incr(fullKey);

    if (count === 1) {
      await client.expire(fullKey, windowSeconds);
    }

    if (count > maxRequests) {
      const ttl = await client.ttl(fullKey);
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: ttl > 0 ? ttl : windowSeconds,
      };
    }

    return { allowed: true, remaining: maxRequests - count };
  } catch (error: any) {
    console.warn(`[RateLimit] Redis error for key ${key}:`, error.message);
    return { allowed: true, remaining: maxRequests };
  }
}
