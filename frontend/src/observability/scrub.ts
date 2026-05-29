/**
 * Shared Sentry `beforeSend` secret/PII scrubber.
 *
 * Deptex is a security product — we MUST NOT ship secrets or PII to Sentry.
 * `sendDefaultPii` is left false (the SDK default already drops IPs / cookies /
 * auth headers), and this redactor is the defense-in-depth second gate: it
 * walks the event and strips secret-shaped strings + values under sensitive
 * keys from the message, exception values, breadcrumbs, extra, contexts, and
 * request.
 *
 * The same logic is intentionally DUPLICATED (not imported) into the worker
 * and frontend packages — they have no shared lib with the backend. This is
 * the canonical, unit-tested copy; keep the copies in sync. See
 * `feature-brief-observability-sentry.md`.
 */
import type { Event, EventHint } from '@sentry/react';

const REDACTED = '[REDACTED]';
const MAX_DEPTH = 6;
const MAX_ARRAY = 50;

// Keys whose *values* are redacted wholesale, regardless of content.
const SENSITIVE_KEY_RE =
  /(authorization|cookie|set-cookie|token|secret|passwo?rd|api[-_]?key|private[-_]?key|encryption[-_]?key|x[-_]?internal[-_]?api[-_]?key|client[-_]?secret|webhook[-_]?secret|signing[-_]?key|dsn|jwt|bearer|credential|service[-_]?role)/i;

// Secret-shaped substrings redacted anywhere they appear inside a string.
// Order matters: more specific patterns (anthropic) precede broader ones (openai).
const PATTERNS: Array<[RegExp, string]> = [
  // PEM private keys (multi-line)
  [/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]'],
  // JSON Web Tokens (header.payload.signature)
  [/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[REDACTED_JWT]'],
  // Stripe secret / restricted / publishable keys
  [/\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}/g, '[REDACTED_STRIPE_KEY]'],
  // GitHub tokens (PAT, OAuth, app, refresh, server-to-server)
  [/\bgh[posru]_[A-Za-z0-9]{20,}\b/g, '[REDACTED_GH_TOKEN]'],
  // Google API keys
  [/\bAIza[0-9A-Za-z_-]{20,}\b/g, '[REDACTED_GOOGLE_KEY]'],
  // Anthropic keys (before the generic OpenAI sk- pattern)
  [/\bsk-ant-[A-Za-z0-9_-]{20,}/g, '[REDACTED_ANTHROPIC_KEY]'],
  // OpenAI keys
  [/\bsk-[A-Za-z0-9]{20,}/g, '[REDACTED_OPENAI_KEY]'],
  // Bearer header values
  [/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED]'],
];

/** Redact secret-shaped substrings from a single string. */
export function scrubString(input: string): string {
  let out = input;
  for (const [re, repl] of PATTERNS) out = out.replace(re, repl);
  return out;
}

/**
 * Recursively redact a value: wholesale-redact values under sensitive keys,
 * scrub secret substrings from strings, bound depth + array length so a
 * pathological payload can't blow up the scrub pass.
 */
export function redactValue(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return scrubString(value);
  if (typeof value !== 'object') return value;
  if (depth >= MAX_DEPTH) return '[REDACTED_DEPTH]';
  if (Array.isArray(value)) {
    return value.slice(0, MAX_ARRAY).map((v) => redactValue(v, depth + 1));
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SENSITIVE_KEY_RE.test(k) ? REDACTED : redactValue(v, depth + 1);
  }
  return out;
}

/** Scrub a Sentry event in place (and return it). Generic so it stays
 *  assignable to Sentry's `beforeSend` (ErrorEvent -> ErrorEvent). */
export function scrubEvent<T extends Event>(event: T): T {
  if (typeof event.message === 'string') event.message = scrubString(event.message);
  if (event.logentry?.message) event.logentry.message = scrubString(event.logentry.message);

  if (event.exception?.values) {
    for (const ex of event.exception.values) {
      if (ex.value) ex.value = scrubString(ex.value);
      // Sentry's localVariables integration (on by default in @sentry/node) can
      // attach local variable VALUES to stack frames — a `token`/`key`/`password`
      // local would leak. Redact frame vars the same way we redact extra/contexts.
      const frames = ex.stacktrace?.frames;
      if (frames) {
        for (const f of frames) {
          if (f.vars) f.vars = redactValue(f.vars) as Record<string, unknown>;
        }
      }
      // mechanism.data carries arbitrary integration/handler context — scrub it.
      if (ex.mechanism?.data) ex.mechanism.data = redactValue(ex.mechanism.data) as { [key: string]: string | boolean };
    }
  }

  if (event.breadcrumbs) {
    for (const bc of event.breadcrumbs) {
      if (typeof bc.message === 'string') bc.message = scrubString(bc.message);
      if (bc.data) bc.data = redactValue(bc.data) as Record<string, unknown>;
    }
  }

  if (event.extra) event.extra = redactValue(event.extra) as Record<string, unknown>;
  if (event.contexts) event.contexts = redactValue(event.contexts) as Event['contexts'];
  if (event.tags) event.tags = redactValue(event.tags) as Event['tags'];

  if (event.request) {
    delete event.request.cookies;
    delete (event.request as { data?: unknown }).data; // request body
    if (event.request.headers) {
      event.request.headers = redactValue(event.request.headers) as Record<string, string>;
    }
    if (typeof event.request.query_string === 'string') {
      event.request.query_string = scrubString(event.request.query_string);
    }
    if (typeof event.request.url === 'string') event.request.url = scrubString(event.request.url);
  }

  if (event.user) {
    // Keep `id` (we set it to organization_id for correlation); drop PII.
    delete event.user.email;
    delete event.user.ip_address;
    delete event.user.username;
  }

  return event;
}

/** Build the `beforeSend` hook for Sentry.init. */
export function buildBeforeSend() {
  return <T extends Event>(event: T, _hint?: EventHint): T => scrubEvent(event);
}
