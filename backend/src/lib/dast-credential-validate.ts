// Helpers for the credential PUT route: shape validation, JWT exp check,
// optional form login probe, and the redacted payload summary returned by
// GET /credentials.

import safeRegex from 'safe-regex2';

import {
  DastAuthStrategy,
  DastCredentialPayloadSummary,
  DastCredentialUpsertDTO,
  DastCredentialUpsertPayload,
} from '../types/dast';
import { validateExternalUrl } from './url-guard';

// Login-probe bounds. Each is independently load-bearing:
//   - timeout defends against slow-loris upstreams holding the Express handler
//   - body cap prevents OOM via huge upstream response
//   - safe-regex pre-check on indicators prevents ReDoS via attacker-controlled
//     pattern + attacker-controlled body (the user picks the indicator AND
//     stands up the login_url).
const PROBE_TIMEOUT_MS = 10_000;
const PROBE_MAX_REDIRECTS = 3;
const PROBE_MAX_BODY_BYTES = 1_000_000;
const INDICATOR_MAX_LENGTH = 256;

export type CredentialValidateError =
  | { error_code: 'invalid_credential_shape'; detail: string }
  | { error_code: 'jwt_decode_failed'; detail: string }
  | { error_code: 'jwt_expired_too_soon'; detail: string }
  | { error_code: 'login_url_invalid'; detail: string }
  | { error_code: 'login_probe_failed'; detail: string }
  | { error_code: 'login_probe_failed_indicator_collision'; detail: string };

export interface CredentialValidateOk {
  ok: true;
  payload: DastCredentialUpsertPayload;
  // The plaintext JSON we encrypt and store in encrypted_payload.
  serializedPlaintext: string;
  // The redacted summary returned to the client.
  summary: DastCredentialPayloadSummary;
}

export type CredentialValidateResult = CredentialValidateOk | { ok: false; error: CredentialValidateError };

const VALID_STRATEGIES: ReadonlySet<DastAuthStrategy> = new Set(['form', 'jwt', 'cookie']);

// ---------------------------------------------------------------------------
// Shape + summary
// ---------------------------------------------------------------------------

function maskUsername(u: string): string {
  if (!u) return '';
  const at = u.indexOf('@');
  if (at < 0) {
    // Not an email — just first-char + ***.
    return `${u.charAt(0)}***`;
  }
  const local = u.slice(0, at);
  const domain = u.slice(at + 1);
  const masked = `${local.charAt(0)}***@${domain}`;
  return masked.slice(0, 24);
}

function jwtPrefix(token: string): string {
  // First 8 chars + '…' (NOT 10/12 — JWT prefix 'eyJhbGciOi' is 10 chars and
  // exposes the algorithm choice).
  return `${token.slice(0, 8)}…`;
}

function summarizePayload(p: DastCredentialUpsertPayload): DastCredentialPayloadSummary {
  switch (p.kind) {
    case 'form':
      return { kind: 'form', username_masked: maskUsername(p.username) };
    case 'jwt':
      return {
        kind: 'jwt',
        token_prefix: jwtPrefix(p.token),
        token_length: p.token.length,
        expires_in_minutes: jwtExpiresInMinutes(p.token) ?? -1,
      };
    case 'cookie':
      return {
        kind: 'cookie',
        cookie_count: p.cookies.length,
        // Cap at 10 names, each truncated to 32 chars.
        cookie_names: p.cookies.slice(0, 10).map((c) => c.name.slice(0, 32)),
      };
  }
}

function isPlainString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

function checkShape(input: unknown): CredentialValidateResult | { ok: 'continue'; dto: DastCredentialUpsertDTO } {
  if (input == null || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: { error_code: 'invalid_credential_shape', detail: 'request body required' } };
  }
  const body = input as Record<string, unknown>;
  const strategy = body.auth_strategy as DastAuthStrategy;
  if (!VALID_STRATEGIES.has(strategy)) {
    return {
      ok: false,
      error: { error_code: 'invalid_credential_shape', detail: 'auth_strategy must be form|jwt|cookie' },
    };
  }
  const payload = body.payload as DastCredentialUpsertPayload | undefined;
  if (!payload || typeof payload !== 'object' || (payload as any).kind !== strategy) {
    return {
      ok: false,
      error: { error_code: 'invalid_credential_shape', detail: 'payload.kind must match auth_strategy' },
    };
  }

  if (payload.kind === 'form') {
    const required: (keyof typeof payload)[] = [
      'login_url',
      'username_field',
      'password_field',
      'username',
      'password',
    ];
    for (const k of required) {
      if (!isPlainString((payload as any)[k])) {
        return {
          ok: false,
          error: { error_code: 'invalid_credential_shape', detail: `form payload missing ${String(k)}` },
        };
      }
    }
  } else if (payload.kind === 'jwt') {
    if (!isPlainString(payload.token)) {
      return {
        ok: false,
        error: { error_code: 'invalid_credential_shape', detail: 'jwt payload.token required' },
      };
    }
  } else if (payload.kind === 'cookie') {
    if (!Array.isArray(payload.cookies) || payload.cookies.length === 0) {
      return {
        ok: false,
        error: { error_code: 'invalid_credential_shape', detail: 'cookie payload.cookies must be non-empty' },
      };
    }
    for (const c of payload.cookies) {
      if (!c || typeof c !== 'object' || !isPlainString(c.name) || !isPlainString(c.value)) {
        return {
          ok: false,
          error: { error_code: 'invalid_credential_shape', detail: 'cookies require non-empty name + value' },
        };
      }
    }
  }

  const dto: DastCredentialUpsertDTO = {
    auth_strategy: strategy,
    payload,
    logged_in_indicator: isPlainString(body.logged_in_indicator)
      ? (body.logged_in_indicator as string)
      : undefined,
    logged_out_indicator: isPlainString(body.logged_out_indicator)
      ? (body.logged_out_indicator as string)
      : undefined,
  };
  return { ok: 'continue', dto };
}

// ---------------------------------------------------------------------------
// JWT exp validation
// ---------------------------------------------------------------------------

export function jwtExpiresInMinutes(token: string): number | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const payloadJson = Buffer.from(parts[1], 'base64').toString('utf8');
    const claim = JSON.parse(payloadJson);
    if (typeof claim.exp !== 'number') return null;
    const nowSecs = Math.floor(Date.now() / 1000);
    return Math.floor((claim.exp - nowSecs) / 60);
  } catch {
    return null;
  }
}

function validateJwtExp(token: string, scanTimeoutMinutes: number): CredentialValidateError | null {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { error_code: 'jwt_decode_failed', detail: 'token is not a 3-segment JWT' };
  }
  let claim: any;
  try {
    claim = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
  } catch (e: any) {
    // Generic detail — Node's JSON.parse messages embed an excerpt of the
    // input ('Unexpected token \'o\', "not-actuall"...') which would echo
    // ~11 chars of the user's pasted token to the API response.
    // eslint-disable-next-line no-console
    console.error('[dast-credential-validate] JWT payload decode failed:', e?.message ?? e);
    return { error_code: 'jwt_decode_failed', detail: 'jwt payload is not valid base64-encoded JSON' };
  }
  if (typeof claim.exp !== 'number') {
    return { error_code: 'jwt_expired_too_soon', detail: 'JWT missing `exp` claim' };
  }
  const nowSecs = Math.floor(Date.now() / 1000);
  const remaining = claim.exp - nowSecs;
  const threshold = 1.5 * scanTimeoutMinutes * 60;
  if (remaining < threshold) {
    return {
      error_code: 'jwt_expired_too_soon',
      detail: `JWT expires in ${Math.floor(remaining / 60)} min; scan_timeout is ${scanTimeoutMinutes} — token must last ≥${Math.ceil(threshold / 60)} min.`,
    };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Form login probe (heavyweight — caller decides when to run it)
// ---------------------------------------------------------------------------

export interface LoginProbeOptions {
  fetchImpl?: typeof fetch;
  // SSRF / DNS-rebind guard. Defaults to `validateExternalUrl` so route
  // callers don't have to pass it; tests inject a stub to avoid real DNS.
  validateUrl?: typeof validateExternalUrl;
  // Caller passes the validated indicators (already shape-checked).
  loggedInIndicator?: string;
  loggedOutIndicator?: string;
}

function checkIndicatorRegex(
  raw: string,
  fieldName: 'logged_in_indicator' | 'logged_out_indicator',
): CredentialValidateError | null {
  if (raw.length > INDICATOR_MAX_LENGTH) {
    return {
      error_code: 'login_probe_failed',
      detail: `${fieldName} exceeds ${INDICATOR_MAX_LENGTH} chars`,
    };
  }
  try {
    new RegExp(raw);
  } catch {
    return {
      error_code: 'login_probe_failed',
      detail: `${fieldName} is not a valid regex`,
    };
  }
  if (!safeRegex(raw)) {
    return {
      error_code: 'login_probe_failed',
      detail: `${fieldName} regex is unsafe (potential catastrophic backtracking)`,
    };
  }
  return null;
}

async function readBodyCapped(res: Response, capBytes: number): Promise<string> {
  const cl = res.headers?.get?.('content-length');
  if (cl) {
    const declared = parseInt(cl, 10);
    if (!isNaN(declared) && declared > capBytes) {
      // Don't even start streaming — refuse a too-large response upfront.
      return '';
    }
  }
  // Prefer streaming so we abort midway on a chunked/no-CL response that
  // exceeds the cap. Fallback to .text() for environments / mocks that don't
  // expose a streaming body (jest fetch mocks).
  const reader = (res as any).body?.getReader?.();
  if (!reader) {
    const text = await res.text();
    return text.slice(0, capBytes);
  }
  const decoder = new TextDecoder('utf-8');
  let total = 0;
  let out = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > capBytes) {
      try { await reader.cancel(); } catch { /* ignore */ }
      // Decode whatever we collected before the cap. A partial body still
      // produces a correct match for the indicator regex when it's near the
      // top of the page.
      out += decoder.decode(value.slice(0, Math.max(0, capBytes - (total - value.byteLength))), { stream: false });
      break;
    }
    out += decoder.decode(value, { stream: true });
  }
  out += decoder.decode();
  return out;
}

export async function probeFormLogin(
  payload: Extract<DastCredentialUpsertPayload, { kind: 'form' }>,
  opts: LoginProbeOptions = {},
): Promise<CredentialValidateError | null> {
  const guardFn = opts.validateUrl ?? validateExternalUrl;
  const guard = await guardFn(payload.login_url);
  if (guard.valid === false) {
    return { error_code: 'login_url_invalid', detail: guard.reason };
  }

  // ReDoS pre-check on user-supplied indicators. We compile against an
  // attacker-controlled response below, so an unsafe pattern combined with a
  // chosen body would peg the event loop.
  if (opts.loggedInIndicator) {
    const err = checkIndicatorRegex(opts.loggedInIndicator, 'logged_in_indicator');
    if (err) return err;
  }
  if (opts.loggedOutIndicator) {
    const err = checkIndicatorRegex(opts.loggedOutIndicator, 'logged_out_indicator');
    if (err) return err;
  }

  const fetchImpl = opts.fetchImpl ?? ((globalThis as any).fetch as typeof fetch);
  if (typeof fetchImpl !== 'function') {
    return { error_code: 'login_probe_failed', detail: 'fetch_unavailable' };
  }
  const body = new URLSearchParams();
  body.set(payload.username_field, payload.username);
  body.set(payload.password_field, payload.password);

  // AbortSignal.timeout caps total wall-time across the redirect loop; a
  // slow-loris upstream cannot starve Express threads.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);

  try {
    let currentUrl = payload.login_url;
    let res: Response | null = null;

    for (let i = 0; i <= PROBE_MAX_REDIRECTS; i++) {
      const isInitial = i === 0;
      try {
        res = await fetchImpl(currentUrl, {
          method: isInitial ? 'POST' : 'GET',
          headers: isInitial
            ? { 'Content-Type': 'application/x-www-form-urlencoded' }
            : {},
          body: isInitial ? body.toString() : undefined,
          redirect: 'manual',
          signal: controller.signal,
        } as any);
      } catch (e: any) {
        // Map raw fetch errors to opaque detail. Node fetch errors embed
        // resolved IPs/ports (e.g. `connect ECONNREFUSED 169.254.169.254:80`)
        // which would let a tenant probe internal services via the 422
        // response. Real cause goes to console.error for operator visibility.
        // eslint-disable-next-line no-console
        console.error('[dast-credential-validate] login probe fetch failed:', e?.message ?? e);
        return { error_code: 'login_probe_failed', detail: 'login endpoint did not respond' };
      }

      // Manual redirect handling — re-validate every redirect destination
      // against the SSRF guard so attacker.com cannot 302 to IMDS.
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers?.get?.('location');
        if (!loc) break;
        try {
          currentUrl = new URL(loc, currentUrl).toString();
        } catch {
          return { error_code: 'login_url_invalid', detail: 'malformed redirect Location header' };
        }
        const r2 = await guardFn(currentUrl);
        if (r2.valid === false) {
          return { error_code: 'login_url_invalid', detail: 'redirect destination rejected by SSRF guard' };
        }
        continue;
      }
      break;
    }

    if (!res) {
      return { error_code: 'login_probe_failed', detail: 'login endpoint did not respond' };
    }
    if (!res.ok && res.status >= 500) {
      return { error_code: 'login_probe_failed', detail: `login endpoint returned ${res.status}` };
    }

    const html = await readBodyCapped(res, PROBE_MAX_BODY_BYTES);

    const inMatch = opts.loggedInIndicator
      ? new RegExp(opts.loggedInIndicator).test(html)
      : true;
    const outMatch = opts.loggedOutIndicator
      ? new RegExp(opts.loggedOutIndicator).test(html)
      : false;

    if (opts.loggedInIndicator && !inMatch) {
      return {
        error_code: 'login_probe_failed',
        detail: 'logged_in_indicator did not match the post-login response.',
      };
    }
    if (opts.loggedInIndicator && opts.loggedOutIndicator && inMatch && outMatch) {
      return {
        error_code: 'login_probe_failed_indicator_collision',
        detail: 'logged_out_indicator also matched the post-login response — fix your regex.',
      };
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Public: unified validator used by PUT /credentials
// ---------------------------------------------------------------------------

export interface ValidateAndPrepareOptions {
  scanTimeoutMinutes: number;
  // Whether to run the login probe synchronously. Default true; tests pass
  // false to skip the network round-trip.
  runFormProbe?: boolean;
  fetchImpl?: typeof fetch;
}

export async function validateAndPrepareCredential(
  input: unknown,
  opts: ValidateAndPrepareOptions,
): Promise<CredentialValidateResult> {
  const shaped = checkShape(input);
  if ('ok' in shaped && shaped.ok === false) return shaped;
  if (!('dto' in shaped)) return shaped as CredentialValidateResult;
  const dto = shaped.dto;

  // Strategy-specific validation.
  if (dto.payload.kind === 'jwt') {
    const err = validateJwtExp(dto.payload.token, opts.scanTimeoutMinutes);
    if (err) return { ok: false, error: err };
  } else if (dto.payload.kind === 'form' && opts.runFormProbe !== false) {
    const err = await probeFormLogin(dto.payload, {
      fetchImpl: opts.fetchImpl,
      loggedInIndicator: dto.logged_in_indicator,
      loggedOutIndicator: dto.logged_out_indicator,
    });
    if (err) return { ok: false, error: err };
  }

  return {
    ok: true,
    payload: dto.payload,
    serializedPlaintext: JSON.stringify(dto.payload),
    summary: summarizePayload(dto.payload),
  };
}

export { summarizePayload };
