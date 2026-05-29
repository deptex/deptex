/**
 * Sentry init for the Aegis fix-worker.
 *
 * Imported immediately after `import 'dotenv/config'` in index.ts so process.env
 * is populated before init. No-ops without SENTRY_DSN. The worker compiles to
 * dist and runs `node dist/index.js` in prod (tsx in dev).
 */
import * as Sentry from '@sentry/node';
import { buildBeforeSend } from './observability/scrub';

const dsn = process.env.SENTRY_DSN;
if (dsn) {
  Sentry.init({
    dsn,
    environment: process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || 'production',
    release: process.env.SENTRY_RELEASE,
    tracesSampleRate: 0,
    sendDefaultPii: false,
    beforeSend: buildBeforeSend(),
    initialScope: { tags: { service: 'fix-worker' } },
  });
  // eslint-disable-next-line no-console
  console.log('[sentry] fix-worker error tracking initialized');
}
