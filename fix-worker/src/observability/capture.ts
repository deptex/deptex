/**
 * Helpers for capturing errors that originate OUTSIDE the Express request
 * lifecycle — job-queue adapters, crons, background side-effects. Those never
 * reach `Sentry.setupExpressErrorHandler`, so without an explicit capture they
 * are lost to console-only logging on Fly's ephemeral log stream.
 *
 * All helpers no-op safely when Sentry is not initialized (SENTRY_DSN unset),
 * so call sites don't need to guard.
 */
import * as Sentry from '@sentry/node';

/** Capture an exception from infrastructure code, tagged by component. */
export function captureInfraError(
  err: unknown,
  component: string,
  extra?: Record<string, unknown>,
): void {
  Sentry.captureException(err, {
    tags: { component },
    contexts: extra ? { infra: extra } : undefined,
  });
}

/** Capture a message-level infra failure where there is no Error object. */
export function captureInfraMessage(
  message: string,
  component: string,
  extra?: Record<string, unknown>,
): void {
  Sentry.captureMessage(message, {
    level: 'error',
    tags: { component },
    contexts: extra ? { infra: extra } : undefined,
  });
}
