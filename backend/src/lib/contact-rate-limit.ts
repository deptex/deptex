/**
 * In-memory rate limiter for public contact forms (demo-request, enterprise-contact).
 * Limits by IP to prevent spam. No auth on these endpoints, so we rely on:
 * - Rate limit: 5 requests per hour per IP per endpoint
 * - Honeypot: bot trap field (handled in route)
 * - Optional Referer check (handled in route)
 *
 * For multi-instance deployments, consider Redis-backed rate limiting later.
 */

const WINDOW_MS = 60 * 60 * 1000; // 1 hour
const MAX_REQUESTS_PER_WINDOW = 5;

const store = new Map<string, { count: number; resetAt: number }>();

function getClientIp(req: { ip?: string; headers: Record<string, string | string[] | undefined> }): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0];
    return (first ?? '').trim();
  }
  return req.ip ?? 'unknown';
}

export type RequestLike = { ip?: string; headers: Record<string, string | string[] | undefined> };

/**
 * Returns true if the request is within limit (and increments). Returns false if over limit (429 should be sent).
 */
export function checkContactRateLimit(req: RequestLike, type: 'demo' | 'enterprise'): { allowed: boolean; ip: string } {
  const ip = getClientIp(req);
  const key = `contact:${type}:${ip}`;
  const now = Date.now();
  const entry = store.get(key);

  if (!entry) {
    store.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return { allowed: true, ip };
  }

  if (now > entry.resetAt) {
    store.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return { allowed: true, ip };
  }

  entry.count++;
  if (entry.count > MAX_REQUESTS_PER_WINDOW) {
    return { allowed: false, ip };
  }
  return { allowed: true, ip };
}
