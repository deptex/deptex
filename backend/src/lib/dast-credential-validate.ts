// Helpers for the credential PUT route: shape validation, JWT exp check,
// optional form login probe, and the redacted payload summary returned by
// GET /credentials.

import {
  DastAuthStrategy,
  DastCredentialPayloadSummary,
  DastCredentialUpsertDTO,
  DastCredentialUpsertPayload,
} from '../types/dast';
import { validateExternalUrl } from './url-guard';

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
    return { error_code: 'jwt_decode_failed', detail: e?.message ?? 'payload b64 decode failed' };
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
  // Caller passes the validated indicators (already shape-checked).
  loggedInIndicator?: string;
  loggedOutIndicator?: string;
}

export async function probeFormLogin(
  payload: Extract<DastCredentialUpsertPayload, { kind: 'form' }>,
  opts: LoginProbeOptions = {},
): Promise<CredentialValidateError | null> {
  const guard = await validateExternalUrl(payload.login_url);
  if (guard.valid === false) {
    return { error_code: 'login_url_invalid', detail: guard.reason };
  }
  const fetchImpl = opts.fetchImpl ?? ((globalThis as any).fetch as typeof fetch);
  if (typeof fetchImpl !== 'function') {
    return { error_code: 'login_probe_failed', detail: 'fetch_unavailable' };
  }
  const body = new URLSearchParams();
  body.set(payload.username_field, payload.username);
  body.set(payload.password_field, payload.password);

  let res: Response;
  try {
    res = await fetchImpl(payload.login_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    } as any);
  } catch (e: any) {
    return { error_code: 'login_probe_failed', detail: e?.message ?? 'fetch_error' };
  }
  if (!res.ok && res.status >= 500) {
    return { error_code: 'login_probe_failed', detail: `login endpoint returned ${res.status}` };
  }
  const html = await res.text();

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
