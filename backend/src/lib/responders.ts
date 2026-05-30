/**
 * Phase 2 of route-error observability: the `fail()` route responder.
 *
 * Use it INSIDE a route handler's catch block in place of
 * `console.error(...); res.status(500).json({ error })`. Unlike the Phase-1
 * breadth-net (which only sees the HTTP status after the fact), `fail()` runs
 * inside the catch and so can capture the real Error WITH its stack trace.
 *
 * It:
 *   1. sets `res.locals.sentryCaptured` so the finish-net does NOT also capture
 *      this response (no double-counting against the Sentry quota),
 *   2. captures the exception tagged by route pattern + method (so it groups
 *      with the Phase-1 events for the same endpoint), scrubbed by the shared
 *      `beforeSend`,
 *   3. logs a concise console line for local-dev parity, and
 *   4. sends the same JSON error response the handler used to send.
 *
 * `Sentry.captureException` is a safe no-op when `SENTRY_DSN` is unset, so call
 * sites need no guard. The request is read from `res.req` (Express always sets
 * it), so callers don't pass `req` — sidestepping handlers that name it `_req`.
 */
import * as Sentry from '@sentry/node';
import type { Response } from 'express';
import { routePattern } from './observability/route-errors';
import { scrubString } from './observability/scrub';

export function fail(
  res: Response,
  err: unknown,
  message = 'Internal server error',
  status = 500,
): void {
  res.locals.sentryCaptured = true;
  const req = res.req;
  const pattern = routePattern(req);
  const userId = (req as { user?: { id?: string } } | undefined)?.user?.id;
  Sentry.captureException(err, {
    tags: { component: 'route', method: req?.method, route: pattern },
    user: userId ? { id: userId } : undefined,
  });
  // Local-dev parity: Sentry replaces this in prod, but local dev (no DSN) still
  // wants the error on the console. Scrub it first — an Error's message/stack can
  // echo a secret (a DB or auth driver error), and console output bypasses
  // Sentry's beforeSend redactor.
  const safeErr = scrubString(err instanceof Error ? (err.stack ?? err.message) : String(err));
  console.error(`[route] ${req?.method ?? '?'} ${pattern}: ${safeErr}`);
  res.status(status).json({ error: message });
}
