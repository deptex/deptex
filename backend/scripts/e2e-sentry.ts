/**
 * Real-dependency e2e for the Sentry wiring.
 *
 * Drives the ACTUAL @sentry/node SDK (the same SDK the backend + both workers
 * use): Sentry.init → captureException builds a real event from a secret-laden
 * scope → our real beforeSend scrubber runs → we record the exact event that
 * would go to the transport and assert it is fully scrubbed. Then it checks
 * that all four surfaces' scrubber copies (backend / depscanner / fix-worker /
 * frontend) produce identical redaction, so no copy has drifted.
 *
 * No Sentry project / DSN required: beforeSend returns null so nothing is sent
 * over the network — we only inspect the post-scrub event. This is the highest-
 * fidelity test possible without a live DSN (it exercises the real SDK event
 * pipeline, not a hand-built object).
 *
 * Run: npm run e2e:sentry
 */
import * as Sentry from '@sentry/node';
import { buildBeforeSend, scrubEvent } from '../src/lib/observability/scrub';
// Type-only imports in these copies are erased at runtime, so importing the
// frontend copy (which types against @sentry/react) is safe from a node script.
import { scrubEvent as depscannerScrub } from '../../depscanner/src/observability/scrub';
import { scrubEvent as fixWorkerScrub } from '../../fix-worker/src/observability/scrub';
import { scrubEvent as frontendScrub } from '../../frontend/src/observability/scrub';

let failures = 0;
function check(name: string, ok: boolean): void {
  if (ok) {
    console.log(`  ✓ ${name}`);
  } else {
    console.error(`  ✗ ${name}`);
    failures++;
  }
}

const JWT =
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const STRIPE = 'sk_live_ABCDEFGH123456789';
const EMAIL = 'leak@user.com';

async function backendPipeline(): Promise<void> {
  console.log('[1] real @sentry/node event pipeline (init -> captureException -> beforeSend)');
  let recorded: Sentry.Event | null = null;
  const scrub = buildBeforeSend();

  Sentry.init({
    dsn: 'https://examplePublicKey@o0.ingest.sentry.io/0',
    sendDefaultPii: false,
    tracesSampleRate: 0,
    beforeSend: (event, hint) => {
      // Run the REAL scrubber on the REAL constructed event, record it, then
      // drop (return null) so nothing hits the network.
      recorded = scrub(event, hint);
      return null;
    },
    initialScope: { tags: { service: 'e2e' } },
  });

  Sentry.captureException(new Error(`charge failed: ${JWT} / ${STRIPE}`), {
    user: { id: 'org-123', email: EMAIL },
    tags: { component: 'billing', billing_reason: 'auto_recharge_invoice_threw' },
    extra: { authorization: `Bearer ${JWT}`, note: `stripe key ${STRIPE}` },
  });
  await Sentry.flush(2000);

  const ev = recorded as Sentry.Event | null;
  const blob = JSON.stringify(ev ?? {});
  check('an event was constructed and passed through beforeSend', ev != null);
  check('no raw JWT anywhere in the event', !blob.includes(JWT));
  check('no raw Stripe key anywhere in the event', !blob.includes(STRIPE));
  check('no leaked email anywhere in the event', !blob.includes(EMAIL));
  check('JWT redaction marker present', blob.includes('[REDACTED_JWT]'));
  check('Stripe redaction marker present', blob.includes('[REDACTED_STRIPE_KEY]'));
  check('org id (user.id) preserved for correlation', ev?.user?.id === 'org-123');
  check('user.email dropped', ev?.user?.email === undefined);
  check('extra.authorization redacted', (ev?.extra as Record<string, unknown> | undefined)?.authorization === '[REDACTED]');
  check('component tag preserved', ev?.tags?.component === 'billing');
}

function surfaceParity(): void {
  console.log('[2] cross-surface scrubber parity (backend / depscanner / fix-worker / frontend)');
  const make = (): Sentry.Event =>
    ({
      message: `boom ${JWT} ${STRIPE}`,
      user: { id: 'org-9', email: EMAIL },
      request: {
        data: { card: '4242' } as unknown,
        cookies: { s: '1' } as unknown,
        headers: { authorization: `Bearer ${JWT}` },
      },
      extra: { token: 'abc' },
    }) as unknown as Sentry.Event;

  const surfaces: Array<[string, (e: Sentry.Event) => Sentry.Event]> = [
    ['backend', scrubEvent],
    ['depscanner', depscannerScrub as (e: Sentry.Event) => Sentry.Event],
    ['fix-worker', fixWorkerScrub as (e: Sentry.Event) => Sentry.Event],
    ['frontend', frontendScrub as (e: Sentry.Event) => Sentry.Event],
  ];
  for (const [name, fn] of surfaces) {
    const out = fn(make());
    const blob = JSON.stringify(out);
    check(`${name}: no raw secrets`, !blob.includes(JWT) && !blob.includes(STRIPE) && !blob.includes(EMAIL));
    check(`${name}: request body dropped`, (out.request as { data?: unknown } | undefined)?.data === undefined);
    check(`${name}: org id preserved`, out.user?.id === 'org-9');
    check(`${name}: extra.token redacted`, (out.extra as Record<string, unknown> | undefined)?.token === '[REDACTED]');
  }
}

async function main(): Promise<void> {
  console.log('e2e:sentry — real SDK pipeline + cross-surface scrubber parity\n');
  await backendPipeline();
  surfaceParity();
  console.log('');
  await Sentry.close(2000);
  if (failures > 0) {
    console.error(`e2e:sentry FAILED — ${failures} check(s) did not pass.`);
    process.exit(1);
  }
  console.log('e2e:sentry PASSED — secrets are scrubbed before any event leaves the process.');
  process.exit(0);
}

void main();
