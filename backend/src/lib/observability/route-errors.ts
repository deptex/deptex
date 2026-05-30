/**
 * Phase 1 of route-error observability: a breadth-net that captures every HTTP
 * 5xx response to Sentry.
 *
 * Nearly all Deptex route handlers swallow their errors
 * (`try { ... } catch (e) { console.error(...); res.status(500).json(...) }`)
 * and never call `next(err)`, so they never reach `Sentry.setupExpressErrorHandler`.
 * This `res.on('finish')` hook is the only way to see those 500s without editing
 * 600+ catch blocks.
 *
 * It captures a MESSAGE (status + route pattern + method) only — it never reads
 * the response body or an Error object, so it is the lowest-PII surface and
 * carries no stack trace. Full stacks come from the Phase-2 `fail()` responder
 * (see ../responders.ts), which sets `res.locals.sentryCaptured` so this net
 * skips responses that were already captured with a stack.
 *
 * Quota defense: an in-process per-(status, route-pattern) rate guard caps a
 * single failing endpoint at MAX_PER_WINDOW events/hour, so a 500-storm from one
 * broken route can't burn the whole monthly Sentry quota. Counters are in-memory
 * and reset on each serverless cold start, so the cap is sized conservatively.
 */
import * as Sentry from '@sentry/node';
import type { Request, Response, NextFunction } from 'express';

const WINDOW_MS = 60 * 60 * 1000; // 1 hour
const MAX_PER_WINDOW = 20; // events per (status, route-pattern) per window

interface Bucket {
  count: number;
  windowStart: number;
}
const buckets = new Map<string, Bucket>();

/**
 * Low-cardinality route identifier: the router mount path + the matched route
 * path (e.g. `/api/organizations/:id/projects`), NEVER the raw URL — the raw URL
 * embeds org/project/finding IDs and would explode Sentry tag cardinality and
 * break grouping. Falls back to `unmatched` when no route matched (404s,
 * pre-routing errors) so cardinality stays bounded.
 *
 * `req.route` is populated once a handler matches and persists on the request
 * through `res.on('finish')`, so this is reliable at capture time.
 */
const ID_SEGMENT =
  /\/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|\d+)(?=\/|$)/gi;

/** Collapse ID-shaped path segments (UUIDs, long hex, pure numeric) to `:id`. */
function sanitizePattern(p: string): string {
  return p.replace(ID_SEGMENT, '/:id');
}

export function routePattern(req: Request | undefined): string {
  if (!req) return 'unknown';
  const route = req.route as { path?: unknown } | undefined;
  if (typeof route?.path === 'string') {
    // Matched route: mount path + parameterized handler path — already low
    // cardinality (e.g. `/api/organizations/:id/projects`). sanitize() also
    // guards the latent case of a router mounted on a parameterized path, where
    // req.baseUrl would carry a resolved id.
    return sanitizePattern(`${req.baseUrl || ''}${route.path}`);
  }
  // Unmatched (404 / pre-routing error): no req.route. Use the actual path
  // (never the query string) with ids collapsed, so we keep routing context
  // without exploding tag cardinality.
  const raw = `${req.baseUrl || ''}${req.path || ''}`;
  return raw ? sanitizePattern(raw) : 'unmatched';
}

/**
 * Per-(status, pattern) rate cap. Returns whether to capture this event and
 * whether this is the event that just hit the cap (so we tag it `rate_capped`
 * and stop emitting further events for this key until the window resets).
 */
function withinRateCap(statusCode: number, pattern: string): { capture: boolean; capJustHit: boolean } {
  const key = `${statusCode}:${pattern}`;
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now - b.windowStart >= WINDOW_MS) {
    b = { count: 0, windowStart: now };
    buckets.set(key, b);
  }
  b.count += 1;
  if (b.count < MAX_PER_WINDOW) return { capture: true, capJustHit: false };
  if (b.count === MAX_PER_WINDOW) return { capture: true, capJustHit: true };
  return { capture: false, capJustHit: false };
}

/**
 * Express middleware. On response finish, capture any `res.statusCode >= 500` to
 * Sentry as a message — unless a Phase-2 `fail()` / the global error handler
 * already captured it (`res.locals.sentryCaptured`).
 *
 * Register this BEFORE the route mounts (so the `finish` listener is attached
 * for every request); the listener reads `req.route` at finish time, by which
 * point routing has populated it. No-ops entirely when Sentry is uninitialized.
 */
export function routeErrorCaptureMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.on('finish', () => {
    if (res.statusCode < 500) return;
    if (res.locals?.sentryCaptured) return; // already captured with a stack
    const pattern = routePattern(req);
    const { capture, capJustHit } = withinRateCap(res.statusCode, pattern);
    if (!capture) return;
    const userId = (req as { user?: { id?: string } }).user?.id;
    Sentry.captureMessage(`HTTP ${res.statusCode} ${req.method} ${pattern}`, {
      level: 'error',
      tags: {
        kind: 'route_5xx',
        method: req.method,
        route: pattern,
        status_code: res.statusCode,
        ...(capJustHit ? { rate_capped: 'true' } : {}),
      },
      user: userId ? { id: userId } : undefined,
    });
  });
  next();
}
