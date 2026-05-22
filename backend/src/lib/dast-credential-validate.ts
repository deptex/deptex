// Helpers for the credential PUT route: shape validation, JWT exp check,
// optional form login probe, and the redacted payload summary returned by
// GET /credentials.

import safeRegex from 'safe-regex2';

import {
  DastAuthStrategy,
  DastCredentialPayloadSummary,
  DastCredentialUpsertDTO,
  DastCredentialUpsertPayload,
  DastJobPayloadSchema,
  RecordedCredentialPayload,
  RecordedStep,
  RecordedStepAction,
  ReplayCredentialPayload,
} from '../types/dast';
import {
  HAR_MAX_SERIALIZED_PLAINTEXT_BYTES,
  JS_LINE_TERMINATOR_RE,
  TOTP_BASE32_RE as REPLAY_TOTP_BASE32_RE,
  TOTP_MAX_SECRET_LEN,
} from './dast-har-constants';
import { extractOriginsObserved, parseHar } from './dast-har-parse';
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
  | { error_code: 'login_probe_failed_indicator_collision'; detail: string }
  // Phase 36 (v1.1) — assembled replay payload exceeded
  // HAR_MAX_SERIALIZED_PLAINTEXT_BYTES (1MB) at the validator's final cap.
  // Mirrors the route-scoped body-parser 413 path which emits the same code.
  | { error_code: 'replay_payload_too_large'; detail: string };

export interface CredentialValidateOk {
  ok: true;
  payload: DastCredentialUpsertPayload;
  // The plaintext JSON we encrypt and store in encrypted_payload.
  serializedPlaintext: string;
  // The redacted summary returned to the client.
  summary: DastCredentialPayloadSummary;
}

export type CredentialValidateResult = CredentialValidateOk | { ok: false; error: CredentialValidateError };

const VALID_STRATEGIES: ReadonlySet<DastAuthStrategy> = new Set([
  'form',
  'jwt',
  'cookie',
  'recorded',
  // Phase 36 (v1.1) — HAR-derived replay auth strategy.
  'replay',
]);

// ---------------------------------------------------------------------------
// v2.1d — Recorded-login validator bounds. Each is independently load-bearing:
//   - step count cap defends the encrypted_payload TEXT column size
//   - selector length cap defends the encrypted_payload TEXT column size + the
//     ZAP browser-auth step shape (long selectors are almost always wrong)
//   - timeout / wait_ms ranges defend the worker wall-clock against runaway
//     authoring (e.g. wait_ms=86400000 is almost certainly a typo)
//   - serialized plaintext cap defends the encryption + storage layer
//   - TOTP regex enforces RFC 6238 base32 alphabet (A-Z, 2-7) + length bounds
// ---------------------------------------------------------------------------
const RECORDED_MAX_STEPS = 50;
const RECORDED_MAX_SELECTOR_LEN = 1024;
const RECORDED_MIN_TIMEOUT_MS = 100;
const RECORDED_MAX_TIMEOUT_MS = 30_000;
const RECORDED_MIN_WAIT_MS = 0;
const RECORDED_MAX_WAIT_MS = 30_000;
const RECORDED_MAX_LOGIN_PAGE_WAIT_MS = 30_000;
const RECORDED_MAX_STEP_DELAY_MS = 5_000;
const RECORDED_MAX_LABEL_LEN = 80;
const RECORDED_MAX_SSO_ORIGINS = 5;
const RECORDED_MAX_PLAINTEXT_BYTES = 64 * 1024;
const TOTP_BASE32_RE = /^[A-Z2-7]{16,256}$/;

const VALID_ACTIONS: ReadonlySet<RecordedStepAction> = new Set([
  'goto',
  'click',
  'type_username',
  'type_password',
  'type_totp',
  'type_custom',
  'wait',
  'return',
  'escape',
]);

// Selector-requiring actions. `goto` carries a `value` (URL) instead;
// `wait` / `return` / `escape` need neither selector nor value.
const ACTIONS_REQUIRING_SELECTOR: ReadonlySet<RecordedStepAction> = new Set([
  'click',
  'type_username',
  'type_password',
  'type_totp',
  'type_custom',
]);

// CR/LF/control characters in a selector or value would let a malicious org
// member inject log lines (and the browser-auth replay step types them raw
// into the page, which is benign but unparseable on the wire).
// eslint-disable-next-line no-control-regex
const CONTROL_OR_CRLF = /[\x00-\x1f\x7f]/;

function isIntegerInRange(v: unknown, min: number, max: number): v is number {
  return (
    typeof v === 'number' &&
    Number.isFinite(v) &&
    Number.isInteger(v) &&
    v >= min &&
    v <= max
  );
}

/**
 * Strictly validates the recorded credential payload shape + step list. The
 * route invokes this BEFORE encrypting + storing; the worker re-decrypts at
 * scan time and trusts the shape that was stored. Validator decisions
 * therefore lock the schema permanently per row.
 */
export function validateRecordedSteps(
  payload: RecordedCredentialPayload,
): CredentialValidateError | null {
  // login_page_url
  if (!isPlainString(payload.login_page_url)) {
    return {
      error_code: 'invalid_credential_shape',
      detail: 'recorded payload missing login_page_url',
    };
  }
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(payload.login_page_url);
  } catch {
    return {
      error_code: 'invalid_credential_shape',
      detail: 'login_page_url is not a valid URL',
    };
  }
  if (parsedUrl.protocol !== 'https:') {
    return {
      error_code: 'invalid_credential_shape',
      detail: 'login_page_url must be https',
    };
  }

  // credentials block
  if (!isPlainString(payload.username)) {
    return { error_code: 'invalid_credential_shape', detail: 'recorded payload missing username' };
  }
  if (!isPlainString(payload.password)) {
    return { error_code: 'invalid_credential_shape', detail: 'recorded payload missing password' };
  }
  if (payload.totp_secret !== undefined) {
    if (typeof payload.totp_secret !== 'string' || !TOTP_BASE32_RE.test(payload.totp_secret)) {
      return {
        error_code: 'invalid_credential_shape',
        detail: 'totp_secret must be RFC 6238 base32 (A-Z, 2-7), 16-256 chars',
      };
    }
  }

  // timing knobs
  if (
    payload.login_page_wait_ms !== undefined &&
    !isIntegerInRange(payload.login_page_wait_ms, 0, RECORDED_MAX_LOGIN_PAGE_WAIT_MS)
  ) {
    return {
      error_code: 'invalid_credential_shape',
      detail: `login_page_wait_ms must be integer in [0, ${RECORDED_MAX_LOGIN_PAGE_WAIT_MS}]`,
    };
  }
  if (
    payload.step_delay_ms !== undefined &&
    !isIntegerInRange(payload.step_delay_ms, 0, RECORDED_MAX_STEP_DELAY_MS)
  ) {
    return {
      error_code: 'invalid_credential_shape',
      detail: `step_delay_ms must be integer in [0, ${RECORDED_MAX_STEP_DELAY_MS}]`,
    };
  }

  // optional metadata
  if (payload.label !== undefined) {
    if (typeof payload.label !== 'string' || payload.label.length > RECORDED_MAX_LABEL_LEN) {
      return {
        error_code: 'invalid_credential_shape',
        detail: `label must be string ≤${RECORDED_MAX_LABEL_LEN} chars`,
      };
    }
    if (CONTROL_OR_CRLF.test(payload.label)) {
      return {
        error_code: 'invalid_credential_shape',
        detail: 'label contains control characters',
      };
    }
  }
  if (payload.sso_origins !== undefined) {
    if (!Array.isArray(payload.sso_origins) || payload.sso_origins.length > RECORDED_MAX_SSO_ORIGINS) {
      return {
        error_code: 'invalid_credential_shape',
        detail: `sso_origins must be array of ≤${RECORDED_MAX_SSO_ORIGINS} https URLs`,
      };
    }
    for (const o of payload.sso_origins) {
      if (typeof o !== 'string') {
        return {
          error_code: 'invalid_credential_shape',
          detail: 'sso_origins entries must be strings',
        };
      }
      try {
        const u = new URL(o);
        if (u.protocol !== 'https:') {
          return {
            error_code: 'invalid_credential_shape',
            detail: 'sso_origins entries must be https',
          };
        }
      } catch {
        return {
          error_code: 'invalid_credential_shape',
          detail: 'sso_origins entries must be valid URLs',
        };
      }
    }
  }

  // steps[]
  if (!Array.isArray(payload.steps) || payload.steps.length === 0) {
    return {
      error_code: 'invalid_credential_shape',
      detail: 'recorded payload requires steps array with ≥1 entry',
    };
  }
  if (payload.steps.length > RECORDED_MAX_STEPS) {
    return {
      error_code: 'invalid_credential_shape',
      detail: `recorded payload steps capped at ${RECORDED_MAX_STEPS}`,
    };
  }

  let sawUsernameStep = false;
  let sawPasswordStep = false;
  let sawTotpStep = false;

  for (let i = 0; i < payload.steps.length; i++) {
    const step = payload.steps[i] as RecordedStep | undefined;
    if (!step || typeof step !== 'object') {
      return {
        error_code: 'invalid_credential_shape',
        detail: `step ${i} must be an object`,
      };
    }
    if (!VALID_ACTIONS.has(step.action)) {
      return {
        error_code: 'invalid_credential_shape',
        detail: `step ${i} action ${String(step.action)} is not a valid RecordedStepAction`,
      };
    }

    // goto is special — only valid as steps[0].
    if (step.action === 'goto') {
      if (i !== 0) {
        return {
          error_code: 'invalid_credential_shape',
          detail: `step ${i} goto only valid as the first step; intermediate navigation must use click`,
        };
      }
      if (!isPlainString(step.value)) {
        return {
          error_code: 'invalid_credential_shape',
          detail: `step ${i} goto requires a value (target URL)`,
        };
      }
      // The goto URL is verified the same way as login_page_url — https only.
      try {
        const u = new URL(step.value);
        if (u.protocol !== 'https:') {
          return {
            error_code: 'invalid_credential_shape',
            detail: `step ${i} goto value must be https`,
          };
        }
      } catch {
        return {
          error_code: 'invalid_credential_shape',
          detail: `step ${i} goto value is not a valid URL`,
        };
      }
      continue;
    }

    if (ACTIONS_REQUIRING_SELECTOR.has(step.action)) {
      if (!isPlainString(step.selector)) {
        return {
          error_code: 'invalid_credential_shape',
          detail: `step ${i} ${step.action} requires a selector`,
        };
      }
      if (step.selector.length > RECORDED_MAX_SELECTOR_LEN) {
        return {
          error_code: 'invalid_credential_shape',
          detail: `step ${i} selector exceeds ${RECORDED_MAX_SELECTOR_LEN} chars`,
        };
      }
      if (CONTROL_OR_CRLF.test(step.selector)) {
        return {
          error_code: 'invalid_credential_shape',
          detail: `step ${i} selector contains control characters`,
        };
      }
      if (step.selector_kind !== undefined && step.selector_kind !== 'css' && step.selector_kind !== 'xpath') {
        return {
          error_code: 'invalid_credential_shape',
          detail: `step ${i} selector_kind must be 'css' or 'xpath'`,
        };
      }
    }

    if (step.action === 'type_custom') {
      if (!isPlainString(step.value)) {
        return {
          error_code: 'invalid_credential_shape',
          detail: `step ${i} type_custom requires a value`,
        };
      }
      if (CONTROL_OR_CRLF.test(step.value)) {
        return {
          error_code: 'invalid_credential_shape',
          detail: `step ${i} type_custom value contains control characters`,
        };
      }
    }

    if (step.action === 'wait') {
      if (!isIntegerInRange(step.wait_ms, RECORDED_MIN_WAIT_MS, RECORDED_MAX_WAIT_MS)) {
        return {
          error_code: 'invalid_credential_shape',
          detail: `step ${i} wait requires wait_ms integer in [${RECORDED_MIN_WAIT_MS}, ${RECORDED_MAX_WAIT_MS}]`,
        };
      }
    }

    if (step.timeout_ms !== undefined) {
      if (!isIntegerInRange(step.timeout_ms, RECORDED_MIN_TIMEOUT_MS, RECORDED_MAX_TIMEOUT_MS)) {
        return {
          error_code: 'invalid_credential_shape',
          detail: `step ${i} timeout_ms must be integer in [${RECORDED_MIN_TIMEOUT_MS}, ${RECORDED_MAX_TIMEOUT_MS}]`,
        };
      }
    }

    if (step.action === 'type_username') sawUsernameStep = true;
    if (step.action === 'type_password') sawPasswordStep = true;
    if (step.action === 'type_totp') sawTotpStep = true;
  }

  // If the user authored a type_totp step, totp_secret is required.
  if (sawTotpStep && !payload.totp_secret) {
    return {
      error_code: 'invalid_credential_shape',
      detail: 'steps contain type_totp but payload.totp_secret is missing',
    };
  }
  // type_username / type_password require username / password respectively —
  // already enforced above (both required unconditionally) but documenting the
  // intent. A future refactor that makes username optional must revisit this.
  void sawUsernameStep;
  void sawPasswordStep;

  // Serialized plaintext size cap (defense for encrypted_payload column).
  const serializedLen = JSON.stringify(payload).length;
  if (serializedLen > RECORDED_MAX_PLAINTEXT_BYTES) {
    return {
      error_code: 'invalid_credential_shape',
      detail: `recorded payload serializes to ${serializedLen} bytes; cap is ${RECORDED_MAX_PLAINTEXT_BYTES}`,
    };
  }

  return null;
}

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
    case 'recorded': {
      // Host-only (NEVER path/query/fragment) per the multi-tenant redaction
      // posture. URL parse already validated upstream; defensive fallback
      // here in case the function is ever called with an unvalidated payload.
      let host = '';
      try {
        host = new URL(p.login_page_url).host;
      } catch {
        host = '';
      }
      return {
        kind: 'recorded',
        step_count: p.steps.length,
        has_totp: typeof p.totp_secret === 'string' && p.totp_secret.length > 0,
        login_page_url_host: host,
        ...(typeof p.label === 'string' && p.label.length > 0 ? { label: p.label } : {}),
      };
    }
    case 'replay': {
      // Phase 36 (v1.1) — same hostname-only posture. No URL paths, no header
      // values, no body content in the summary.
      const hasNonReplayable = p.requests.some((r) => {
        try {
          const u = new URL(r.url);
          // Mirrors HAR_NON_REPLAYABLE_PATTERNS but only used here for the
          // boolean — the detailed warning list lives on the preview-route
          // response, not on the stored credential.
          return /\/(?:webauthn|fido|passkey|sms\/verify|sms\/code)\b/i.test(u.pathname);
        } catch {
          return false;
        }
      });
      return {
        kind: 'replay',
        request_count: p.requests.length,
        origins_observed: Array.isArray(p.origins_observed) ? p.origins_observed.slice(0, 10) : [],
        totp_detected: p.totp_step !== undefined,
        has_totp_secret: typeof p.totp_secret === 'string' && p.totp_secret.length > 0,
        has_non_replayable_pattern: hasNonReplayable,
        ...(typeof p.label === 'string' && p.label.length > 0 ? { label: p.label } : {}),
      };
    }
  }
}

function isPlainString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

// ---------------------------------------------------------------------------
// Phase 36 (v1.1) — Replay-auth (HAR import) validator
// ---------------------------------------------------------------------------

/**
 * Strictly validates an assembled ReplayCredentialPayload before encrypt +
 * store. Called from `checkShape` AFTER `payload.kind === 'replay'` is
 * confirmed; the parser at `dast-har-parse.parseHar()` already did the per-
 * entry shape work for the `POST /replay/preview` route, but the PUT
 * route's payload arrives as the assembled list (the FE strips response
 * fields + reassembles `requests[]`). This function is the LAST gate before
 * we commit the row.
 *
 * Patch I-6 disciplines:
 *   - `totp_secret` must match TOTP_BASE32_RE (strict A-Z + 2-7 + optional
 *     `=` padding) AND be ≤ TOTP_MAX_SECRET_LEN. Lowercase / whitespace /
 *     hyphens / non-alphabet chars → reject. Keeps the inlined-script-body
 *     literal context safe under `JSON.stringify` substitution.
 *   - Every user-supplied string (URL, header values, body, label,
 *     totp_secret) is scanned for U+2028 / U+2029 via JS_LINE_TERMINATOR_RE;
 *     reject on any hit. Pre-ES2019 these chars broke out of JS string
 *     literals (historical templating CVE class); Graal.js is ES2020+ but
 *     defense-in-depth is cheap.
 *   - The full request list is re-run through `parseHar` (skipping the
 *     wrapping {log: {entries}} shape) so the same caps + private-IP-literal
 *     guard apply at PUT time, not just at preview time.
 */
export function validateReplayPayload(
  payload: ReplayCredentialPayload,
): CredentialValidateError | null {
  if (!Array.isArray(payload.requests) || payload.requests.length === 0) {
    return {
      error_code: 'invalid_credential_shape',
      detail: 'replay payload.requests must be a non-empty array',
    };
  }

  // Rebuild a HAR-shaped wrapper so we can reuse the parser's caps + private-
  // IP + line-terminator guard. The PUT-time list omits response shape; we
  // synthesise a minimal stub.
  const synthHar = {
    log: {
      entries: payload.requests.map((r) => ({
        request: {
          method: r.method,
          url: r.url,
          headers: r.headers ?? [],
          ...(r.body !== undefined
            ? {
                postData: {
                  mimeType:
                    (r.headers ?? []).find((h) => h.name.toLowerCase() === 'content-type')?.value
                    ?? 'application/octet-stream',
                  text: r.body,
                },
              }
            : {}),
        },
        response: { status: 0, headers: [] },
      })),
    },
  };
  try {
    parseHar(synthHar);
  } catch (e) {
    const code = (e as { error_code?: string }).error_code;
    if (code === 'har_too_large' || code === 'har_too_small') {
      return {
        error_code: 'invalid_credential_shape',
        detail: `replay payload rejected by parser cap: ${code}`,
      };
    }
    return {
      error_code: 'invalid_credential_shape',
      detail: `replay payload rejected: ${code ?? 'parse_failure'}`,
    };
  }

  // origins_observed must align with what the request list actually carries.
  // The FE computes this; we recompute and assert equality so a tampered
  // PUT body can't lie about reachable hosts (else the SSRF gate would only
  // see the declared list, not the actual ones).
  const observed = extractOriginsObserved(payload.requests);
  if (!Array.isArray(payload.origins_observed)) {
    return {
      error_code: 'invalid_credential_shape',
      detail: 'replay payload.origins_observed must be an array',
    };
  }
  const declared = new Set(payload.origins_observed.map((s) => s.toLowerCase()));
  for (const o of observed) {
    if (!declared.has(o)) {
      return {
        error_code: 'invalid_credential_shape',
        detail: 'replay payload.origins_observed missing a hostname present in requests',
      };
    }
  }

  // TOTP secret discipline (Patch I-6).
  if (payload.totp_secret !== undefined) {
    if (typeof payload.totp_secret !== 'string') {
      return {
        error_code: 'invalid_credential_shape',
        detail: 'replay payload.totp_secret must be a string when present',
      };
    }
    if (payload.totp_secret.length > TOTP_MAX_SECRET_LEN) {
      return {
        error_code: 'invalid_credential_shape',
        detail: `replay payload.totp_secret exceeds ${TOTP_MAX_SECRET_LEN} chars`,
      };
    }
    if (!REPLAY_TOTP_BASE32_RE.test(payload.totp_secret)) {
      return {
        error_code: 'invalid_credential_shape',
        detail: 'replay payload.totp_secret must be canonical RFC 4648 base32 (A-Z + 2-7, optional `=` padding)',
      };
    }
    if (JS_LINE_TERMINATOR_RE.test(payload.totp_secret)) {
      return {
        error_code: 'invalid_credential_shape',
        detail: 'replay payload.totp_secret contains U+2028 / U+2029',
      };
    }
  }

  // totp_step shape validation when present. The parser detects it; here we
  // sanity-check the FE didn't tamper with the index/field.
  if (payload.totp_step !== undefined) {
    const ts = payload.totp_step;
    if (
      typeof ts !== 'object' ||
      ts === null ||
      typeof ts.entry_index !== 'number' ||
      ts.entry_index < 0 ||
      ts.entry_index >= payload.requests.length ||
      typeof ts.body_field !== 'string' ||
      (ts.body_kind !== 'form' && ts.body_kind !== 'json')
    ) {
      return {
        error_code: 'invalid_credential_shape',
        detail: 'replay payload.totp_step shape invalid',
      };
    }
  }

  if (payload.label !== undefined) {
    if (typeof payload.label !== 'string') {
      return { error_code: 'invalid_credential_shape', detail: 'replay payload.label must be a string when present' };
    }
    if (payload.label.length > 80) {
      return { error_code: 'invalid_credential_shape', detail: 'replay payload.label exceeds 80 chars' };
    }
    if (JS_LINE_TERMINATOR_RE.test(payload.label)) {
      return { error_code: 'invalid_credential_shape', detail: 'replay payload.label contains U+2028 / U+2029' };
    }
  }

  // Final cap: serialized plaintext bytes (encryption layer's effective
  // ceiling). The parser caps the input HAR at 1MB; the assembled payload
  // is smaller post-extraction, but defense-in-depth.
  const serializedSize = JSON.stringify(payload).length;
  if (serializedSize > HAR_MAX_SERIALIZED_PLAINTEXT_BYTES) {
    return {
      // Phase 36 / criticalreview PD-1: the canonical error_code is
      // `replay_payload_too_large` (mirrors the route-scoped body-parser 413).
      // Original code emitted `invalid_credential_shape` here, which made
      // the documented `replay_payload_too_large` unreachable.
      error_code: 'replay_payload_too_large',
      detail: `replay payload serialized ${serializedSize} bytes > ${HAR_MAX_SERIALIZED_PLAINTEXT_BYTES}`,
    };
  }

  return null;
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
      error: { error_code: 'invalid_credential_shape', detail: 'auth_strategy must be form|jwt|cookie|recorded|replay' },
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
  } else if (payload.kind === 'recorded') {
    const err = validateRecordedSteps(payload as RecordedCredentialPayload);
    if (err) return { ok: false, error: err };
  } else if (payload.kind === 'replay') {
    // Phase 36 (v1.1) — HAR-derived replay auth. Structural caps + TOTP
    // base32 strictness + JS line-terminator rejection.
    const err = validateReplayPayload(payload as ReplayCredentialPayload);
    if (err) return { ok: false, error: err };
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
  // Whether to run the recorded-strategy SSRF/IMDS guard on login_page_url +
  // goto step values + sso_origins. Default true; tests pass false to skip
  // DNS round-trips. Mirrors runFormProbe's posture for the form path.
  runRecordedSsrfGuard?: boolean;
  // Phase 36 (v1.1) — whether to run the replay-strategy SSRF/IMDS guard on
  // every distinct origin in the captured request list. Default true;
  // tests pass false to skip DNS.
  runReplaySsrfGuard?: boolean;
  // Override for the SSRF helper — defaults to validateExternalUrl from
  // ./url-guard. Tests stub it to avoid hitting real DNS.
  validateUrl?: typeof validateExternalUrl;
  fetchImpl?: typeof fetch;
}

/**
 * v2.1d SSRF/IMDS guard for the recorded strategy. The structural
 * validateRecordedSteps check passes URL.parse + protocol=='https:' on
 * login_page_url, each goto step's value, and each sso_origins entry — but
 * does NOT resolve hostnames against the private-IP block list. Without this
 * second pass a tenant member can point Firefox at 169.254.169.254, fdaa::/16
 * (Fly internal mesh), 127.0.0.1, or any RFC1918 host from inside the
 * depscanner container when Test-login or a real scan runs.
 *
 * This helper runs once at PUT-credential time (route layer); the worker
 * re-runs the same check at scan time against the credential's effective
 * loginPageUrl as defense-in-depth for DNS rebinding.
 */
export async function validateRecordedSsrf(
  payload: RecordedCredentialPayload,
  guard: typeof validateExternalUrl = validateExternalUrl,
): Promise<CredentialValidateError | null> {
  // login_page_url
  const loginGuard = await guard(payload.login_page_url);
  if (loginGuard.valid === false) {
    return {
      error_code: 'login_url_invalid',
      detail: `login_page_url rejected: ${loginGuard.reason}`,
    };
  }

  // Every `goto` step's value (today only valid at steps[0], per
  // validateRecordedSteps; the auth-config layer collapses it into
  // loginPageUrl). Validate defensively so a future relaxation of the
  // goto-only-at-0 rule doesn't open a hole.
  for (let i = 0; i < payload.steps.length; i++) {
    const step = payload.steps[i];
    if (step.action === 'goto' && typeof step.value === 'string') {
      const r = await guard(step.value);
      if (r.valid === false) {
        return {
          error_code: 'login_url_invalid',
          detail: `step ${i} goto value rejected: ${r.reason}`,
        };
      }
    }
  }

  // sso_origins are reserved for forward-compat (M0 Spike-2 yellow path —
  // see the runbook). Validate them anyway so an operator who later wires
  // them into the AF context's includePaths can't smuggle a private host.
  if (Array.isArray(payload.sso_origins)) {
    for (const o of payload.sso_origins) {
      if (typeof o !== 'string') continue;
      const r = await guard(o);
      if (r.valid === false) {
        return {
          error_code: 'login_url_invalid',
          detail: `sso_origins entry rejected: ${r.reason}`,
        };
      }
    }
  }

  return null;
}

/**
 * Phase 36 (v1.1) — DNS-resolving SSRF guard for the replay strategy.
 * Runs validateExternalUrl on EVERY distinct origin observed in the
 * captured request list (the parser caps at HAR_MAX_ORIGINS = 10 so this
 * is bounded). Belt-and-suspenders alongside the literal-IP guard the
 * parser already runs at extractEntry().
 *
 * Worker re-runs the same check at scan time (M3 step 7) — DNS-rebind
 * between PUT and scan dispatch can re-point a benign-at-create-time
 * hostname at IMDS / Fly internal mesh / RFC 1918.
 */
export async function validateReplaySsrf(
  payload: ReplayCredentialPayload,
  guard: typeof validateExternalUrl = validateExternalUrl,
): Promise<CredentialValidateError | null> {
  // Iterate origins, not raw requests — the parser already capped origins
  // at 10 so this is O(10) DNS lookups, not O(requests).
  const origins = extractOriginsObserved(payload.requests);
  for (const host of origins) {
    // validateExternalUrl wants a full URL; synthesize https://<host>/.
    const r = await guard(`https://${host}/`);
    if (r.valid === false) {
      return {
        error_code: 'login_url_invalid',
        detail: `replay origin rejected: ${r.reason}`,
      };
    }
  }
  return null;
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
  } else if (dto.payload.kind === 'recorded' && opts.runRecordedSsrfGuard !== false) {
    const err = await validateRecordedSsrf(
      dto.payload as RecordedCredentialPayload,
      opts.validateUrl ?? validateExternalUrl,
    );
    if (err) return { ok: false, error: err };
  } else if (dto.payload.kind === 'replay' && opts.runReplaySsrfGuard !== false) {
    const err = await validateReplaySsrf(
      dto.payload as ReplayCredentialPayload,
      opts.validateUrl ?? validateExternalUrl,
    );
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

// ---------------------------------------------------------------------------
// v2.1d — Job-payload schema validator (typo defense for dry_run dispatch)
// ---------------------------------------------------------------------------

export type DastJobPayloadValidateError =
  | { error_code: 'invalid_job_payload'; detail: string };

/**
 * Validates scan_jobs.payload at queue time AND on worker reload. The worker
 * branches on `payload.dry_run === true` to enter the recorded-login probe;
 * a typo (`dryRun`, `dry-run`) would silently route a Test-login through the
 * full spider/scan path — false→full-scan is the unsafe direction. This
 * validator rejects unknown keys to surface typos at the boundary.
 *
 * Returns the validated payload on success, or an error envelope on failure.
 * Tolerates `null`/`undefined` (the existing /scan route sometimes inserts
 * empty payloads); only rejects payloads that ARE objects but contain
 * invalid keys/values.
 */
export function validateDastJobPayload(
  input: unknown,
): { ok: true; payload: DastJobPayloadSchema } | { ok: false; error: DastJobPayloadValidateError } {
  if (input == null) return { ok: true, payload: {} };
  if (typeof input !== 'object' || Array.isArray(input)) {
    return {
      ok: false,
      error: { error_code: 'invalid_job_payload', detail: 'payload must be an object' },
    };
  }
  const obj = input as Record<string, unknown>;
  const out: DastJobPayloadSchema = {};

  const KNOWN_KEYS = new Set([
    'target_url',
    'scan_profile',
    'scan_timeout_minutes',
    'detected_runtime',
    'source',
    'dry_run',
    'engine',
  ]);

  for (const k of Object.keys(obj)) {
    if (!KNOWN_KEYS.has(k)) {
      return {
        ok: false,
        error: {
          error_code: 'invalid_job_payload',
          detail: `unknown payload key ${JSON.stringify(k)} — likely a typo (e.g. dryRun → dry_run)`,
        },
      };
    }
  }

  if (obj.target_url !== undefined) {
    if (typeof obj.target_url !== 'string') {
      return { ok: false, error: { error_code: 'invalid_job_payload', detail: 'target_url must be string' } };
    }
    out.target_url = obj.target_url;
  }
  if (obj.scan_profile !== undefined) {
    if (
      obj.scan_profile !== 'auto' &&
      obj.scan_profile !== 'quick' &&
      obj.scan_profile !== 'full' &&
      obj.scan_profile !== 'api'
    ) {
      return { ok: false, error: { error_code: 'invalid_job_payload', detail: 'scan_profile must be auto|quick|full|api' } };
    }
    out.scan_profile = obj.scan_profile;
  }
  if (obj.scan_timeout_minutes !== undefined) {
    if (typeof obj.scan_timeout_minutes !== 'number' || !Number.isFinite(obj.scan_timeout_minutes)) {
      return { ok: false, error: { error_code: 'invalid_job_payload', detail: 'scan_timeout_minutes must be number' } };
    }
    out.scan_timeout_minutes = obj.scan_timeout_minutes;
  }
  if (obj.detected_runtime !== undefined) {
    if (
      obj.detected_runtime !== 'unknown' &&
      obj.detected_runtime !== 'classic' &&
      obj.detected_runtime !== 'spa'
    ) {
      return { ok: false, error: { error_code: 'invalid_job_payload', detail: 'detected_runtime must be unknown|classic|spa' } };
    }
    out.detected_runtime = obj.detected_runtime;
  }
  if (obj.source !== undefined) {
    const sources = new Set(['manual_dast_scan', 'credential_test', 'webhook', 'scheduled', 'on_deploy', 'aegis']);
    if (typeof obj.source !== 'string' || !sources.has(obj.source)) {
      return { ok: false, error: { error_code: 'invalid_job_payload', detail: `source must be one of: ${[...sources].join('|')}` } };
    }
    out.source = obj.source as DastJobPayloadSchema['source'];
  }
  if (obj.dry_run !== undefined) {
    if (typeof obj.dry_run !== 'boolean') {
      return { ok: false, error: { error_code: 'invalid_job_payload', detail: 'dry_run must be boolean' } };
    }
    out.dry_run = obj.dry_run;
  }
  if (obj.engine !== undefined) {
    if (obj.engine !== 'zap' && obj.engine !== 'nuclei') {
      return { ok: false, error: { error_code: 'invalid_job_payload', detail: 'engine must be zap|nuclei' } };
    }
    out.engine = obj.engine;
  }

  return { ok: true, payload: out };
}

// validateRecordedSteps is exported at its definition above.
