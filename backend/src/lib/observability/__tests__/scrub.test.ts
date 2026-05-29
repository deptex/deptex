import { scrubString, redactValue, scrubEvent, buildBeforeSend } from '../scrub';
import type { Event } from '@sentry/node';

describe('scrubString', () => {
  it('redacts JWTs', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    expect(scrubString(`token=${jwt} done`)).toBe('token=[REDACTED_JWT] done');
  });

  it('redacts Stripe secret/restricted/publishable keys', () => {
    expect(scrubString('sk_live_abcdEFGH12345678 tail')).toBe('[REDACTED_STRIPE_KEY] tail');
    expect(scrubString('rk_test_ZZZZ99998888aaaa')).toBe('[REDACTED_STRIPE_KEY]');
  });

  it('redacts GitHub tokens', () => {
    expect(scrubString('ghp_0123456789abcdefABCDEF0123456789abcd')).toBe('[REDACTED_GH_TOKEN]');
    expect(scrubString('ghs_0123456789abcdefABCDEF0123456789abcd')).toBe('[REDACTED_GH_TOKEN]');
  });

  it('redacts Google API keys', () => {
    expect(scrubString('AIzaSyA1234567890abcdefghijklmnopqrstuv')).toBe('[REDACTED_GOOGLE_KEY]');
  });

  it('redacts Anthropic keys before OpenAI keys', () => {
    expect(scrubString('sk-ant-api03-abcdefghijklmnopqrstuvwxyz')).toBe('[REDACTED_ANTHROPIC_KEY]');
  });

  it('redacts OpenAI keys', () => {
    expect(scrubString('sk-proj1234567890abcdefghijklmnop')).toBe('[REDACTED_OPENAI_KEY]');
  });

  it('redacts Bearer header values', () => {
    expect(scrubString('Authorization: Bearer abc.def-ghi_123')).toBe('Authorization: Bearer [REDACTED]');
  });

  it('redacts PEM private keys (multi-line)', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIB...lines...\nABC=\n-----END RSA PRIVATE KEY-----';
    expect(scrubString(`key: ${pem}`)).toBe('key: [REDACTED_PRIVATE_KEY]');
  });

  it('leaves benign strings untouched', () => {
    expect(scrubString('extraction failed for project 42')).toBe('extraction failed for project 42');
  });
});

describe('redactValue', () => {
  it('wholesale-redacts values under sensitive keys', () => {
    const out = redactValue({
      authorization: 'Bearer xyz',
      cookie: 'session=1',
      access_token: 'plain',
      api_key: 'k',
      private_key: 'p',
      'x-internal-api-key': 'i',
      password: 'hunter2',
      webhook_secret: 'whsec_x',
      dsn: 'https://abc@sentry.io/1',
      normalField: 'kept',
    }) as Record<string, string>;
    expect(out.authorization).toBe('[REDACTED]');
    expect(out.cookie).toBe('[REDACTED]');
    expect(out.access_token).toBe('[REDACTED]');
    expect(out.api_key).toBe('[REDACTED]');
    expect(out.private_key).toBe('[REDACTED]');
    expect(out['x-internal-api-key']).toBe('[REDACTED]');
    expect(out.password).toBe('[REDACTED]');
    expect(out.webhook_secret).toBe('[REDACTED]');
    expect(out.dsn).toBe('[REDACTED]');
    expect(out.normalField).toBe('kept');
  });

  it('scrubs secret substrings inside nested non-sensitive keys', () => {
    const out = redactValue({ note: 'charge with sk_live_abcdEFGH12345678 failed' }) as { note: string };
    expect(out.note).toBe('charge with [REDACTED_STRIPE_KEY] failed');
  });

  it('recurses into arrays and objects', () => {
    const out = redactValue({ items: [{ token: 'a' }, { ok: 'b' }] }) as { items: Array<Record<string, string>> };
    expect(out.items[0].token).toBe('[REDACTED]');
    expect(out.items[1].ok).toBe('b');
  });

  it('bounds recursion depth', () => {
    let deep: any = 'leaf';
    for (let i = 0; i < 10; i++) deep = { next: deep };
    const out = redactValue(deep) as any;
    // Walk to the depth cap; it should terminate in the depth sentinel.
    let cur = out;
    let hops = 0;
    while (cur && typeof cur === 'object' && cur.next !== undefined && hops < 20) {
      cur = cur.next;
      hops++;
    }
    expect(JSON.stringify(out)).toContain('[REDACTED_DEPTH]');
  });

  it('caps array length', () => {
    const big = Array.from({ length: 200 }, (_, i) => i);
    const out = redactValue(big) as number[];
    expect(out.length).toBe(50);
  });
});

describe('scrubEvent / buildBeforeSend', () => {
  function baseEvent(): Event {
    return {
      message: 'failed with Bearer abc.def.ghi',
      exception: { values: [{ type: 'Error', value: 'token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.ZZZ leaked' }] },
      breadcrumbs: [
        { message: 'POST with sk_live_abcdEFGH12345678', data: { authorization: 'Bearer t' } },
      ],
      extra: { apiKey: 'should-not-key-match', note: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' },
      request: {
        url: 'https://api.deptex.dev/billing?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.ZZZ',
        headers: { authorization: 'Bearer secret', 'content-type': 'application/json' },
        cookies: { session: 'abc' } as any,
        data: { card: '4242' } as any,
      },
      user: { id: 'org-123', email: 'a@b.com', ip_address: '1.2.3.4', username: 'alice' },
    } as Event;
  }

  it('scrubs message, exception value, breadcrumbs, request, and user', () => {
    const e = scrubEvent(baseEvent());
    expect(e.message).toBe('failed with Bearer [REDACTED]');
    expect(e.exception!.values![0].value).toContain('[REDACTED_JWT]');
    expect(e.breadcrumbs![0].message).toContain('[REDACTED_STRIPE_KEY]');
    expect((e.breadcrumbs![0].data as any).authorization).toBe('[REDACTED]');
    expect((e.extra as any).note).toBe('[REDACTED_ANTHROPIC_KEY]');
    // request body + cookies dropped entirely
    expect((e.request as any).data).toBeUndefined();
    expect(e.request!.cookies).toBeUndefined();
    // headers redacted, url scrubbed
    expect((e.request!.headers as any).authorization).toBe('[REDACTED]');
    expect(e.request!.url).toContain('[REDACTED_JWT]');
    // user: id kept (org correlation), PII dropped
    expect(e.user!.id).toBe('org-123');
    expect(e.user!.email).toBeUndefined();
    expect(e.user!.ip_address).toBeUndefined();
    expect(e.user!.username).toBeUndefined();
  });

  it('buildBeforeSend returns a function that scrubs', () => {
    const before = buildBeforeSend();
    const e = before(baseEvent(), {} as any);
    expect(e.message).toBe('failed with Bearer [REDACTED]');
  });

  it('handles a minimal event without throwing', () => {
    expect(() => scrubEvent({} as Event)).not.toThrow();
  });

  it('scrubs local variables attached to stack frames', () => {
    const e = scrubEvent({
      exception: {
        values: [
          {
            type: 'Error',
            value: 'boom',
            stacktrace: {
              frames: [
                { filename: 'a.ts', vars: { apiKey: 'sk_live_abcdEFGH12345678', token: 'x', note: 'ghp_0123456789abcdefABCDEF0123456789abcd', safe: 'ok' } },
              ],
            },
          },
        ],
      },
    } as Event);
    const vars = e.exception!.values![0].stacktrace!.frames![0].vars as Record<string, string>;
    expect(vars.apiKey).toBe('[REDACTED]'); // key matches sensitive-key list
    expect(vars.token).toBe('[REDACTED]');
    expect(vars.note).toBe('[REDACTED_GH_TOKEN]'); // value scrubbed by pattern
    expect(vars.safe).toBe('ok');
  });

  it('scrubs event.tags (sensitive keys + secret-shaped values)', () => {
    const e = scrubEvent({
      tags: { component: 'billing', secret: 'x', note: 'sk_live_abcdEFGH12345678' },
    } as unknown as Event);
    const tags = e.tags as Record<string, string>;
    expect(tags.component).toBe('billing'); // controlled tag preserved
    expect(tags.secret).toBe('[REDACTED]'); // sensitive key
    expect(tags.note).toBe('[REDACTED_STRIPE_KEY]'); // secret-shaped value
  });

  it('scrubs exception mechanism.data', () => {
    const e = scrubEvent({
      exception: {
        values: [
          { type: 'Error', value: 'x', mechanism: { type: 'generic', data: { apiKey: 'k', note: 'sk_live_abcdEFGH12345678' } } },
        ],
      },
    } as unknown as Event);
    const data = e.exception!.values![0].mechanism!.data as Record<string, string>;
    expect(data.apiKey).toBe('[REDACTED]'); // sensitive key
    expect(data.note).toBe('[REDACTED_STRIPE_KEY]'); // secret-shaped value
  });
});
