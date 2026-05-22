// Privacy canary tests — stdout/stderr stubbing + JWT-regex sweep + GET
// summary canary (Patch E broadened per the plan).
//
// Why stub process.stdout.write + process.stderr.write directly rather than
// just `console.*`: Pino / Datadog / Vercel log forwarders bypass console and
// write to the underlying streams; a console-only stub would miss leaks
// emitted via those forwarders. This file is the load-bearing canary that
// catches a future regression where a logger gets wired into the parser
// or validator without redaction.
//
// Coverage in M1 (this file):
//   - 3 canary classes (literal bearer / base64 / urlencoded) — none appears
//     anywhere in stdout/stderr across parser + validator runs
//   - JWT-shape regex sweep — no eyJxxx.yyy.zzz substring across captures
//   - GET-summary canary — validator's summarizePayload output never carries
//     the cookie value
//
// Deferred to M2 (added when the routes land):
//   - body-cap canary: POST 2MB body with canary in first 200 bytes → 413
//     with no canary in the response
//   - global error handler trigger: POST malformed JSON whose bytes contain
//     a canary → backend/src/index.ts:186-189 console.error does NOT echo
//     err.body
//   - Patch G test-job lifecycle: after successful test-replay, GET
//     scan_jobs/:id returns error_payload.diagnostic_responses === null
// These are commented placeholders below; M2 step 7 fills them in.

import { parseHar } from '../dast-har-parse';
import { validateAndPrepareCredential } from '../dast-credential-validate';
import type { ReplayCredentialPayload } from '../../types/dast';

// ---------------------------------------------------------------------------
// stdout/stderr capture helper
// ---------------------------------------------------------------------------

interface Capture {
  stdout: string[];
  stderr: string[];
  restore: () => void;
}

function captureStdio(): Capture {
  const cap: Capture = {
    stdout: [],
    stderr: [],
    restore: () => undefined,
  };
  const originalOut = process.stdout.write.bind(process.stdout);
  const originalErr = process.stderr.write.bind(process.stderr);

  // Replace with intercepting variants. Cast through `any` because the
  // overloaded signature of `write` is hostile to typing the spy directly.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.stdout.write as any) = (chunk: any, encOrCb?: any, cb?: any): boolean => {
    cap.stdout.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return originalOut(chunk, encOrCb, cb);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.stderr.write as any) = (chunk: any, encOrCb?: any, cb?: any): boolean => {
    cap.stderr.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return originalErr(chunk, encOrCb, cb);
  };

  // Also intercept console.* — many of the existing libs use console.error;
  // those funnel into process.stderr.write but capture them explicitly so
  // a future fork that bypasses the underlying write is caught.
  const originalConsoleError = console.error;
  const originalConsoleLog = console.log;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (console.error as any) = (...args: any[]) => {
    cap.stderr.push(args.map(String).join(' ') + '\n');
    return originalConsoleError(...args);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (console.log as any) = (...args: any[]) => {
    cap.stdout.push(args.map(String).join(' ') + '\n');
    return originalConsoleLog(...args);
  };

  cap.restore = () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stdout.write as any) = originalOut;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stderr.write as any) = originalErr;
    console.error = originalConsoleError;
    console.log = originalConsoleLog;
  };
  return cap;
}

// ---------------------------------------------------------------------------
// Three canary classes
// ---------------------------------------------------------------------------

const CANARY_LITERAL = 'CANARY_BEARER_DO_NOT_LOG_xyz123abc';
const CANARY_BASE64 = Buffer.from(CANARY_LITERAL, 'utf8').toString('base64'); // Q0FOQVJZ...
const CANARY_URLENC = encodeURIComponent(CANARY_LITERAL);

// Real JWT.io test-vector token. Catches a "naïve substring grep skipped a
// JWT" regression — the JWT-shape regex below is the assertion that
// matters.
const JWT_FIXTURE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

const JWT_SHAPE_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/;

function harWithCanaries(): unknown {
  return {
    log: {
      entries: [
        {
          request: {
            method: 'POST',
            url: 'https://app.example.com/login',
            headers: [
              { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
              { name: 'Authorization', value: `Bearer ${JWT_FIXTURE}` },
              { name: 'Cookie', value: `session=${CANARY_LITERAL}` },
            ],
            postData: {
              mimeType: 'application/x-www-form-urlencoded',
              text: `username=alice&password=${CANARY_LITERAL}&token=${CANARY_BASE64}&also=${CANARY_URLENC}`,
            },
          },
          response: {
            status: 302,
            headers: [{ name: 'Set-Cookie', value: `session=${CANARY_LITERAL}; HttpOnly` }],
          },
        },
      ],
    },
  };
}

function fullCaptureText(c: Capture): string {
  return c.stdout.join('') + c.stderr.join('');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('dast-har-parse + dast-credential-validate — privacy canary suite', () => {
  let cap: Capture;
  beforeEach(() => {
    cap = captureStdio();
  });
  afterEach(() => {
    cap.restore();
  });

  it('parseHar happy path leaks no canary class to stdout/stderr', () => {
    const r = parseHar(harWithCanaries());
    expect(r.requests).toHaveLength(1);
    const captured = fullCaptureText(cap);
    expect(captured).not.toContain(CANARY_LITERAL);
    expect(captured).not.toContain(CANARY_BASE64);
    expect(captured).not.toContain(CANARY_URLENC);
  });

  it('parseHar happy path emits no JWT-shape substring', () => {
    parseHar(harWithCanaries());
    const captured = fullCaptureText(cap);
    expect(JWT_SHAPE_RE.test(captured)).toBe(false);
  });

  it('parseHar rejection paths leak no canary (header > cap)', () => {
    const fx = {
      log: {
        entries: [
          {
            request: {
              method: 'POST',
              url: 'https://app.example.com/login',
              headers: [{ name: 'Cookie', value: CANARY_LITERAL + 'A'.repeat(5_000) }],
            },
            response: { status: 200, headers: [] },
          },
        ],
      },
    };
    try {
      parseHar(fx);
    } catch {
      /* expected — header value > cap */
    }
    const captured = fullCaptureText(cap);
    expect(captured).not.toContain(CANARY_LITERAL);
  });

  it('parseHar shape-rejection error detail does NOT echo body content', () => {
    try {
      parseHar({
        log: {
          entries: [
            {
              request: {
                method: 'POST',
                url: 'http://insecure.example.com/login', // non-https rejection
                headers: [],
                postData: { text: `secret=${CANARY_LITERAL}` },
              },
              response: { status: 200, headers: [] },
            },
          ],
        },
      });
    } catch (e) {
      const detail = (e as { detail?: string }).detail ?? '';
      expect(detail).not.toContain(CANARY_LITERAL);
    }
    const captured = fullCaptureText(cap);
    expect(captured).not.toContain(CANARY_LITERAL);
  });

  it('validateAndPrepareCredential happy path leaks no canary', async () => {
    const payload: ReplayCredentialPayload = {
      kind: 'replay',
      requests: [
        {
          method: 'POST',
          url: 'https://app.example.com/login',
          headers: [
            { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
            { name: 'Cookie', value: `session=${CANARY_LITERAL}` },
          ],
          body: `username=alice&password=${CANARY_LITERAL}`,
        },
      ],
      origins_observed: ['app.example.com'],
    };
    const result = await validateAndPrepareCredential(
      { auth_strategy: 'replay', payload },
      { scanTimeoutMinutes: 30, runReplaySsrfGuard: false },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // serializedPlaintext intentionally CONTAINS the canary — that's the
    // value we're about to AES-256-GCM-encrypt. What must NOT leak is the
    // stdout/stderr capture + the public summary.
    expect(JSON.stringify(result.summary)).not.toContain(CANARY_LITERAL);
    const captured = fullCaptureText(cap);
    expect(captured).not.toContain(CANARY_LITERAL);
    expect(JWT_SHAPE_RE.test(captured)).toBe(false);
  });

  it('GET summary path: canary cookie value never appears in the summary shape', async () => {
    const payload: ReplayCredentialPayload = {
      kind: 'replay',
      requests: [
        {
          method: 'GET',
          url: 'https://app.example.com/dashboard',
          headers: [{ name: 'Cookie', value: `session=${CANARY_LITERAL}` }],
        },
      ],
      origins_observed: ['app.example.com'],
      label: 'has cookies',
    };
    const result = await validateAndPrepareCredential(
      { auth_strategy: 'replay', payload },
      { scanTimeoutMinutes: 30, runReplaySsrfGuard: false },
    );
    if (!result.ok) throw new Error(result.error.error_code);
    const summaryJson = JSON.stringify(result.summary);
    expect(summaryJson).not.toContain(CANARY_LITERAL);
    expect(summaryJson).not.toMatch(/Bearer\s/i);
  });
});

// ---------------------------------------------------------------------------
// M2 placeholders — these tests get implemented when POST /replay/preview +
// PUT /credentials + GET /credentials lands at M2 step 2.
// ---------------------------------------------------------------------------
describe.skip('M2 — route-layer privacy canaries', () => {
  it.skip('body-cap canary — 2MB body with canary returns 413 without echoing canary', () => {
    /* M2 step 7 */
  });
  it.skip('global error handler — POST malformed JSON with canary bytes does not echo them', () => {
    /* M2 step 7 */
  });
  it.skip('Patch G test-job lifecycle — diagnostic_responses === null after success', () => {
    /* M3 step 7b(e) */
  });
});
