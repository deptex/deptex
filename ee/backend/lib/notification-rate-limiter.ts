import crypto from 'crypto';
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

export interface NotificationRateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

/**
 * Sliding-window rate limiter using a Redis sorted set.
 *
 * Each request is stored as a member scored by its timestamp.
 * Expired members are pruned, then the set cardinality is checked
 * against the limit before adding a new member.
 *
 * Fail-open: if Redis is unavailable the request is allowed.
 */
export async function checkNotificationRateLimit(
  scope: string,
  limit: number,
  windowMs: number
): Promise<NotificationRateLimitResult> {
  const client = getRedisClient();
  if (!client) {
    return { allowed: true, remaining: limit, resetAt: Date.now() + windowMs };
  }

  const key = `ratelimit:notif:${scope}`;
  const now = Date.now();
  const windowStart = now - windowMs;
  const resetAt = now + windowMs;

  try {
    await client.zremrangebyscore(key, 0, windowStart);

    const count = await client.zcard(key);

    if (count >= limit) {
      return { allowed: false, remaining: 0, resetAt };
    }

    const member = `${now}:${crypto.randomUUID()}`;
    await client.zadd(key, { score: now, member });

    const expireSeconds = Math.ceil(windowMs / 1000) + 10;
    await client.expire(key, expireSeconds);

    return { allowed: true, remaining: limit - count - 1, resetAt };
  } catch (err: any) {
    console.warn(`[NotifRateLimit] Redis error for scope ${scope}:`, err.message);
    return { allowed: true, remaining: limit, resetAt };
  }
}

/** 200 notifications per hour per organization. */
export function checkOrgRateLimit(
  orgId: string
): Promise<NotificationRateLimitResult> {
  return checkNotificationRateLimit(`org:${orgId}`, 200, 60 * 60 * 1000);
}

/** Per-destination limit: 30/hour (10/hour for ticketing providers). */
export function checkDestinationRateLimit(
  destId: string,
  isTicketing: boolean
): Promise<NotificationRateLimitResult> {
  const limit = isTicketing ? 10 : 30;
  return checkNotificationRateLimit(`dest:${destId}`, limit, 60 * 60 * 1000);
}
