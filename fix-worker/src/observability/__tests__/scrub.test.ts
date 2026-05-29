import { scrubString, scrubEvent } from '../scrub';
import type { Event } from '@sentry/node';

// Smoke test for the fix-worker copy of the canonical backend scrubber.
// Full coverage lives in backend/src/lib/observability/__tests__/scrub.test.ts;
// this proves the copy is present + wired in the fix-worker package.
describe('fix-worker scrub (copy of backend canonical)', () => {
  it('redacts secret-shaped strings', () => {
    expect(scrubString('sk_live_abcdEFGH12345678')).toBe('[REDACTED_STRIPE_KEY]');
    expect(scrubString('ghp_0123456789abcdefABCDEF0123456789abcd')).toBe('[REDACTED_GH_TOKEN]');
  });

  it('drops request body + user PII from events, keeps org id', () => {
    const e = scrubEvent({
      request: { data: { card: '4242' } as unknown } as Event['request'],
      user: { id: 'org-1', email: 'a@b.com' },
    } as Event);
    expect((e.request as { data?: unknown }).data).toBeUndefined();
    expect(e.user!.id).toBe('org-1');
    expect(e.user!.email).toBeUndefined();
  });
});
