/**
 * Sentry init for the frontend (browser).
 *
 * MUST be the first import in main.tsx. No-ops without VITE_SENTRY_DSN, so the
 * code ships before the Sentry project exists. Errors-only: no performance
 * tracing, no session replay (free-tier quota + minimal PII for a billing/
 * security app). Sentry's default globalHandlers integration captures uncaught
 * errors + unhandled promise rejections automatically; route render/loader
 * errors are captured by the router errorElement (see app/routes.tsx), and 5xx
 * API failures are captured in lib/api.ts.
 */
import * as Sentry from '@sentry/react';
import { buildBeforeSend } from './observability/scrub';

const dsn = import.meta.env.VITE_SENTRY_DSN as string | undefined;
if (dsn) {
  Sentry.init({
    dsn,
    environment: import.meta.env.MODE,
    release: import.meta.env.VITE_SENTRY_RELEASE as string | undefined,
    tracesSampleRate: 0,
    sendDefaultPii: false,
    beforeSend: buildBeforeSend(),
    initialScope: { tags: { service: 'frontend' } },
  });
}
