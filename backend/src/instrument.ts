/**
 * Sentry initialization for the backend API.
 *
 * MUST be the first import in index.ts so the SDK patches http / express / pg
 * before they are required. It loads dotenv itself (rather than relying on
 * index.ts) because under tsx/ESM all `import` statements are hoisted above the
 * `dotenv.config()` *statement* in index.ts — so at the point this module runs
 * we cannot assume process.env is populated yet.
 *
 * No-ops entirely when SENTRY_DSN is unset (local dev, CI, pre-launch), so this
 * can ship and merge before the Sentry project exists — set the Fly secret and
 * it activates with zero further code change.
 */
import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(__dirname, '../.env') });

import * as Sentry from '@sentry/node';
import { buildBeforeSend } from './lib/observability/scrub';

const dsn = process.env.SENTRY_DSN;
if (dsn) {
  Sentry.init({
    dsn,
    environment: process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || 'production',
    release: process.env.SENTRY_RELEASE,
    // Errors-only for now: no performance tracing, no profiling (free-tier quota + minimal PII).
    tracesSampleRate: 0,
    // Defense-in-depth: SDK default already drops PII; this is our explicit guarantee.
    sendDefaultPii: false,
    beforeSend: buildBeforeSend(),
    initialScope: { tags: { service: 'backend' } },
  });
  // eslint-disable-next-line no-console
  console.log('[sentry] backend error tracking initialized');
}
