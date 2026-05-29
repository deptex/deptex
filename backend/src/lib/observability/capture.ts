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

/**
 * Capture a billing money-path failure with org correlation. These are the
 * caught-and-swallowed / caught-and-returned-success sites the billing audit
 * flagged: without an explicit capture they are invisible (a 3am auto-recharge
 * failure pages nobody). `reason` is a stable slug (e.g. 'auto_recharge_email_failed')
 * so the same failure mode groups into one Sentry issue. Backend-only helper.
 */
export function captureBillingError(
  err: unknown,
  reason: string,
  opts?: { orgId?: string; extra?: Record<string, unknown> },
): void {
  Sentry.captureException(err, {
    tags: { component: 'billing', billing_reason: reason },
    user: opts?.orgId ? { id: opts.orgId } : undefined,
    contexts: opts?.extra ? { billing: opts.extra } : undefined,
  });
}
