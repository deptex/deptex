// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DO NOT EDIT — synced from backend/src/lib/dast-har-constants.ts via
//   scripts/sync-dast-har.ts
// Edit the backend source and re-run the sync script. CI fails if this file
// drifts.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// DAST HAR import — caps, detector patterns, error codes, and header allowlist.
//
// Phase 36 / v1.1 — paired with backend/src/lib/dast-har-parse.ts and
// (via scripts/sync-dast-har.ts at M3 step 1) the worker-side copy at
// depscanner/src/dast/har-constants.ts. CI `git diff --exit-code` guards
// against drift between the two copies.
//
// "Cap" rationale: every value below derives from a concrete failure mode
// — JSON parse cost, encrypted-payload byte budget, AF YAML emit time,
// privacy posture (URL-query token scrubber, header allowlist). Bumping
// one requires re-deriving the others; the plan's Threat Model + 1MB
// encryption-payload-size risk capture the trade-offs.

/**
 * Hard caps on incoming HAR shape. Anything over these limits is rejected
 * at `POST /replay/preview` with the matching HAR_ERROR_CODE — the parser
 * never holds an oversized payload in memory beyond the validator's reject
 * path.
 */
export const HAR_MAX_ENTRIES = 100;
export const HAR_MAX_TOTAL_BYTES = 1_048_576;          // 1MB raw HAR JSON
export const HAR_MAX_BODY_BYTES = 51_200;              // per-request body cap
export const HAR_MAX_HEADER_VALUE_LEN = 4_096;
export const HAR_MAX_HEADERS_PER_REQUEST = 50;
export const HAR_MAX_ORIGINS = 10;

/**
 * Cap on the SERIALIZED (post-extraction, pre-encryption) plaintext
 * payload bytes the validator emits. Pads against an attacker stuffing
 * the HAR with the maximum legal shape and pushing past the encrypted-
 * column ceiling. Roughly 1MB; encryption overhead is ~36 bytes
 * (IV + auth tag + base64 expansion) so the encrypted blob stays
 * comfortably under typical Supabase row limits.
 */
export const HAR_MAX_SERIALIZED_PLAINTEXT_BYTES = 1_048_576;

/**
 * Patterns + body-field heuristics for auto-detecting a TOTP step within
 * the captured HAR. Order: path match first (high specificity), then
 * body-field match within candidate entries. Both apply to entries with
 * method=POST + Content-Type either form-encoded or JSON.
 */
export const HAR_TOTP_PATHS: RegExp[] = [
  /\/verify[-_]?(?:totp|otp|mfa|2fa)\b/i,
  /\/mfa\/verify\b/i,
  /\/totp\b/i,
  /\/otp\b/i,
  /\/2fa\/verify\b/i,
];
export const HAR_TOTP_BODY_FIELDS: string[] = [
  'code',
  'otp',
  'token',
  'mfa_code',
  'verification_code',
  'totp',
  'one_time_code',
];

/**
 * Non-replayable auth patterns. Flagged in the preview response so the
 * user sees ahead of time that their HAR contains a step we can't reproduce
 * (single-use SMS code, hardware-backed WebAuthn challenge, etc.). Replay
 * still SAVES — the warning is informational — but the dogfood runbook
 * spells out which IdPs to avoid.
 */
export const HAR_NON_REPLAYABLE_PATTERNS: { regex: RegExp; hint: string }[] = [
  { regex: /\/webauthn\b/i, hint: 'WebAuthn (hardware key required)' },
  { regex: /\/fido\b/i, hint: 'FIDO authenticator required' },
  { regex: /\/passkey\b/i, hint: 'Passkey (hardware key required)' },
  { regex: /\/sms\/verify\b/i, hint: 'SMS code (single-use)' },
  { regex: /\/sms\/code\b/i, hint: 'SMS code (single-use)' },
];

/**
 * URL query-string parameter names whose VALUES are stripped (replaced with
 * `[REDACTED]`) before the URL appears in a `preview` response, log line, or
 * audit row. Keys remain present so the user can still see which params the
 * captured request carried.
 */
export const HAR_TOKEN_QUERY_KEYS = new Set<string>([
  'access_token',
  'id_token',
  'refresh_token',
  'token',
  'code',
  'state',
  'nonce',
  'session',
  'sid',
  'jwt',
  'bearer',
  'auth',
  'key',
  'secret',
  'password',
  'pwd',
]);

/**
 * Headers we preserve from HAR entries when building the replay request
 * list. Everything else is dropped — most are telemetry / fingerprinting /
 * device-identification (User-Agent variants, Sec-CH-UA-*, Datadog headers,
 * etc.) that doesn't materially affect auth and would bloat the encrypted
 * payload + leak privacy. Authorization / Cookie / Set-Cookie are core to
 * the replay. Sec-Fetch-* matter for sites that gate on browser-context
 * signals (Vercel anti-bot, Cloudflare TCP fingerprint heuristics, etc.).
 *
 * Lowercased; comparison at parse time is case-insensitive.
 */
export const HAR_KEEP_HEADERS = new Set<string>([
  'authorization',
  'cookie',
  'content-type',
  'content-length',
  'accept',
  'sec-fetch-site',
  'sec-fetch-mode',
  'sec-fetch-dest',
  'sec-fetch-user',
  'x-csrf-token',
  'x-xsrf-token',
  'x-requested-with',
  'origin',
  'referer',
]);

// ---------------------------------------------------------------------------
// Patch I-6 — Triple-defense against script-injection via TOTP secret.
// ---------------------------------------------------------------------------

/**
 * Canonical RFC 4648 base32 alphabet (A-Z + 2-7) with optional `=` padding.
 * Strict by design: lowercase, whitespace, hyphens, mixed case, and `0`/`O`
 * substitutions are all REJECTED. The user must paste canonical form. This
 * lets the inlined script body assemble the secret literal as
 * `JSON.stringify(secret)` without worrying about embedded delimiters
 * surviving the JS string-literal context.
 */
export const TOTP_BASE32_RE = /^[A-Z2-7]+={0,6}$/;

/** Upper bound on the base32 secret length. Anything bigger is a DoS surface
 *  or a buggy paste; legitimate IdP secrets are 16-32 base32 chars (80-160 bits). */
export const TOTP_MAX_SECRET_LEN = 256;

/**
 * U+2028 LINE SEPARATOR + U+2029 PARAGRAPH SEPARATOR. Valid JSON, but pre-
 * ES2019 these characters broke out of JS string literals; ZAP's Graal.js
 * engine is ES2020+ so this is defense-in-depth, but a historical templating
 * CVE class. Rejected in ALL user-supplied string fields routed through the
 * inlined script body (header values, body, URL, label, totp_secret).
 */
// Note: escape sequences `\u2028` / `\u2029` MUST be used here — embedding
// the literal characters terminates the JS regex literal mid-source (the
// very failure mode this regex defends against).
export const JS_LINE_TERMINATOR_RE = /[\u2028\u2029]/;

// ---------------------------------------------------------------------------
// Error codes — duplicated verbatim in frontend/src/lib/dast-error-codes.ts.
// CI `scripts/check-dast-error-codes-match.sh` fails PRs on drift.
// ---------------------------------------------------------------------------

export const HAR_ERROR_CODES = [
  'invalid_har_shape',
  'har_too_large',
  'har_too_small',
  'har_entry_too_large',
  'har_non_https_entry',
  'har_private_ip_entry',
  'har_origin_count_exceeded',
  'har_no_replayable_requests',
  'har_totp_secret_invalid',
  'replay_payload_too_large',
  'dast_encryption_not_configured',
] as const;
export type HarErrorCode = typeof HAR_ERROR_CODES[number];
