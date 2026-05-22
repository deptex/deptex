// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DO NOT EDIT — synced from backend/src/lib/dast-har-parse.ts via
//   scripts/sync-dast-har.ts
//
// The depscanner can't `import` from `backend/src/lib/` (separate package
// boundary in CI + Fly). This duplicate is enforced byte-identical via a CI
// step that re-runs the sync script and fails on `git diff --exit-code`.
// To change parser caps / detectors / scrubbers, edit the backend source and
// re-run the sync script.
//
// Import path differences:
//   backend:    import { ... } from '../types/dast';
//   depscanner: import { ... } from './auth-config'; // hand mirror
// The sync rewrites the import line below.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// DAST HAR parser — pure functions over the HTTP Archive 1.2 shape.
//
// Phase 36 / v1.1 — paired with dast-har-constants.ts and, via M3 step 1's
// scripts/sync-dast-har.ts, the worker-side copy at
// depscanner/src/dast/har-parse.ts. Keep changes in lock-step: CI runs
// `git diff --exit-code` on the synced copy.
//
// This module has THREE callers:
//   1. backend/src/routes/dast.ts — POST /replay/preview (stateless preview)
//   2. backend/src/lib/dast-credential-validate.ts — PUT /credentials
//      (validates the assembled ReplayCredentialPayload before encrypt-and-store)
//   3. depscanner/src/dast/har-parse.ts — worker side, defense-in-depth
//      revalidation just before yaml-builder consumes the payload
//
// PRIVACY: every helper is pure / no I/O. No logger calls (the route layer
// owns logging and pins the canary-test discipline). Throwing for invalid
// input is fine; the message MUST NOT echo body content — only error_code +
// minimal shape metadata (index, header count, etc.).

import ipaddr from 'ipaddr.js';

import {
  HAR_MAX_BODY_BYTES,
  HAR_MAX_ENTRIES,
  HAR_MAX_HEADERS_PER_REQUEST,
  HAR_MAX_HEADER_VALUE_LEN,
  HAR_MAX_ORIGINS,
  HAR_MAX_TOTAL_BYTES,
  HAR_KEEP_HEADERS,
  HAR_NON_REPLAYABLE_PATTERNS,
  HAR_TOKEN_QUERY_KEYS,
  HAR_TOTP_BODY_FIELDS,
  HAR_TOTP_PATHS,
  JS_LINE_TERMINATOR_RE,
  type HarErrorCode,
} from './har-constants';
import type { HarTotpStep, ReplayedRequest } from './auth-config';

// ---------------------------------------------------------------------------
// Result shapes (internal to the parser — route + validator re-pack as needed)
// ---------------------------------------------------------------------------

export interface HarParseRejection {
  error_code: HarErrorCode;
  detail: string;
}

export interface NonReplayableWarning {
  entry_index: number;
  pattern_hint: string;
}

/**
 * Compact per-entry shape for the `POST /replay/preview` response. The route
 * layer is the only thing that uses it; the validator + worker work off the
 * full `ReplayedRequest`.
 */
export interface HarEntryPreview {
  index: number;
  method: string;
  url_scrubbed: string;
  response_status: number;
  has_auth_header: boolean;
  has_cookie_header: boolean;
  has_password_body: boolean;
  body_size: number;
  flag_chips: HarFlagChip[];
}

export type HarFlagChip =
  | 'auth_header'
  | 'set_cookie'
  | 'password_body'
  | 'totp_detected'
  | 'non_replayable_pattern';

export interface HarPreviewSummary {
  request_count: number;
  origins: string[];
  cookies_set: number;
  auth_headers_observed: number;
  dropped_header_count: number;
  dropped_bytes: number;
  kept_header_count: number;
}

export interface HarParseResult {
  entries: HarEntryPreview[];
  requests: ReplayedRequest[];
  summary: HarPreviewSummary;
  totp_detected: HarTotpStep | null;
  non_replayable_warnings: NonReplayableWarning[];
}

// ---------------------------------------------------------------------------
// Top-level entry point
// ---------------------------------------------------------------------------

/**
 * Validate + extract the HAR. Throws a HarParseRejection-shaped Error when
 * the input is structurally bad OR fails a hard cap. Returns the fully
 * scrubbed preview + the extracted requests on success.
 */
export function parseHar(
  raw: unknown,
  options: { rawByteSize?: number } = {},
): HarParseResult {
  // 0. byte cap — defense against the JSON body being already-parsed but
  // sourced from an oversized stream (the route's express.json caps at
  // 1.5MB; this is a belt-and-suspenders check the validator can also
  // call with `rawByteSize` derived from JSON.stringify(payload).length).
  if (options.rawByteSize !== undefined && options.rawByteSize > HAR_MAX_TOTAL_BYTES) {
    throw rejection('har_too_large', `${options.rawByteSize} bytes > ${HAR_MAX_TOTAL_BYTES}`);
  }

  // 1. shape — HAR 1.2 has a top-level `log: {entries: []}` wrapper. Some
  // tools (Cloudflare HAR Sanitizer output, Firefox Network export) wrap
  // identically; Chrome DevTools export DOES use the wrapper.
  if (!raw || typeof raw !== 'object') {
    throw rejection('invalid_har_shape', 'top-level value is not an object');
  }
  const top = raw as Record<string, unknown>;
  const log = top.log && typeof top.log === 'object' ? (top.log as Record<string, unknown>) : top;
  const rawEntries = log.entries;
  if (!Array.isArray(rawEntries)) {
    throw rejection('invalid_har_shape', 'log.entries is missing or not an array');
  }
  if (rawEntries.length === 0) {
    throw rejection('har_too_small', 'log.entries is empty');
  }
  if (rawEntries.length > HAR_MAX_ENTRIES) {
    throw rejection(
      'har_entry_too_large',
      `entry count ${rawEntries.length} > ${HAR_MAX_ENTRIES}`,
    );
  }

  // 2. per-entry walk — accumulate previews + extracted requests in lock-step
  // so the indices line up between the response shape and the encrypted
  // payload the worker eventually replays.
  const entries: HarEntryPreview[] = [];
  const requests: ReplayedRequest[] = [];
  let droppedHeaderCount = 0;
  let droppedBytes = 0;
  let keptHeaderCount = 0;
  let cookiesSetTotal = 0;
  let authHeadersObserved = 0;

  for (let i = 0; i < rawEntries.length; i++) {
    const extracted = extractEntry(rawEntries[i], i);
    entries.push(extracted.preview);
    requests.push(extracted.request);
    droppedHeaderCount += extracted.droppedHeaderCount;
    droppedBytes += extracted.droppedBytes;
    keptHeaderCount += extracted.keptHeaderCount;
    if (extracted.cookiesSet) cookiesSetTotal += extracted.cookiesSet;
    if (extracted.hasAuthHeader) authHeadersObserved += 1;
  }

  // 3. origin count — capped both because the encrypted payload size grows
  // with the number of distinct hosts the script must traverse AND because
  // each origin is its own SSRF gate at PUT time.
  const origins = extractOriginsObserved(requests);
  if (origins.length > HAR_MAX_ORIGINS) {
    throw rejection(
      'har_origin_count_exceeded',
      `${origins.length} distinct hosts > ${HAR_MAX_ORIGINS}`,
    );
  }

  // 4. detector passes — non-replayable warnings get attached to the
  // matching previews via flag_chips; the standalone array also surfaces in
  // the preview response so the FE renders a single combined alert.
  const warnings = detectNonReplayablePatterns(requests);
  for (const w of warnings) {
    entries[w.entry_index]?.flag_chips.push('non_replayable_pattern');
  }

  const totp = detectTotpStep(requests);
  if (totp) {
    entries[totp.entry_index]?.flag_chips.push('totp_detected');
  }

  // 5. at-least-one-replayable check — if NO entry survived (all GETs to
  // non-app domains, all OPTIONS preflights, etc.), reject so the user
  // captures a more useful HAR before going further.
  if (requests.length === 0) {
    throw rejection('har_no_replayable_requests', 'no replayable entries after extraction');
  }

  const summary: HarPreviewSummary = {
    request_count: requests.length,
    origins,
    cookies_set: cookiesSetTotal,
    auth_headers_observed: authHeadersObserved,
    dropped_header_count: droppedHeaderCount,
    dropped_bytes: droppedBytes,
    kept_header_count: keptHeaderCount,
  };

  return {
    entries,
    requests,
    summary,
    totp_detected: totp,
    non_replayable_warnings: warnings,
  };
}

// ---------------------------------------------------------------------------
// Per-entry extraction
// ---------------------------------------------------------------------------

interface EntryExtraction {
  preview: HarEntryPreview;
  request: ReplayedRequest;
  droppedHeaderCount: number;
  droppedBytes: number;
  keptHeaderCount: number;
  cookiesSet: number;
  hasAuthHeader: boolean;
}

function extractEntry(entry: unknown, index: number): EntryExtraction {
  if (!entry || typeof entry !== 'object') {
    throw rejection('invalid_har_shape', `entry[${index}] not an object`);
  }
  const e = entry as Record<string, unknown>;
  const req = e.request && typeof e.request === 'object'
    ? (e.request as Record<string, unknown>)
    : null;
  const resp = e.response && typeof e.response === 'object'
    ? (e.response as Record<string, unknown>)
    : {};
  if (!req) {
    throw rejection('invalid_har_shape', `entry[${index}].request missing`);
  }

  // --- method + URL ---
  const method = typeof req.method === 'string' ? req.method.toUpperCase() : '';
  const rawUrl = typeof req.url === 'string' ? req.url : '';
  if (!method || !rawUrl) {
    throw rejection('invalid_har_shape', `entry[${index}] missing method or url`);
  }
  // Generic line-terminator rejection across all user-supplied strings
  // (Patch I-6 defense-in-depth — these chars are valid JSON but historically
  // broke out of pre-ES2019 JS string literals).
  if (JS_LINE_TERMINATOR_RE.test(rawUrl)) {
    throw rejection('invalid_har_shape', `entry[${index}].url contains U+2028 / U+2029`);
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    throw rejection('invalid_har_shape', `entry[${index}].url not a valid URL`);
  }
  if (parsedUrl.protocol !== 'https:') {
    throw rejection(
      'har_non_https_entry',
      `entry[${index}] uses ${parsedUrl.protocol}; only https is replayable`,
    );
  }
  if (isPrivateOrLoopbackLiteral(parsedUrl.hostname)) {
    throw rejection(
      'har_private_ip_entry',
      `entry[${index}].url hostname is a literal private / loopback IP`,
    );
  }

  // --- headers (allowlist + cap) ---
  const rawHeaders = Array.isArray(req.headers) ? req.headers : [];
  if (rawHeaders.length > HAR_MAX_HEADERS_PER_REQUEST) {
    throw rejection(
      'har_entry_too_large',
      `entry[${index}] has ${rawHeaders.length} headers > ${HAR_MAX_HEADERS_PER_REQUEST}`,
    );
  }
  const keptHeaders: { name: string; value: string }[] = [];
  let droppedHeaderCount = 0;
  let droppedBytes = 0;
  let hasAuthHeader = false;
  let hasCookieHeader = false;
  for (const h of rawHeaders) {
    if (!h || typeof h !== 'object') continue;
    const name = typeof (h as { name?: unknown }).name === 'string'
      ? ((h as { name: string }).name)
      : '';
    const value = typeof (h as { value?: unknown }).value === 'string'
      ? ((h as { value: string }).value)
      : '';
    if (!name) continue;
    const lower = name.toLowerCase();
    if (value.length > HAR_MAX_HEADER_VALUE_LEN) {
      throw rejection(
        'har_entry_too_large',
        `entry[${index}] header "${lower}" value > ${HAR_MAX_HEADER_VALUE_LEN} bytes`,
      );
    }
    if (JS_LINE_TERMINATOR_RE.test(value) || JS_LINE_TERMINATOR_RE.test(name)) {
      throw rejection(
        'invalid_har_shape',
        `entry[${index}] header "${lower}" contains U+2028 / U+2029`,
      );
    }
    if (HAR_KEEP_HEADERS.has(lower)) {
      keptHeaders.push({ name, value });
      if (lower === 'authorization') hasAuthHeader = true;
      if (lower === 'cookie') hasCookieHeader = true;
    } else {
      droppedHeaderCount += 1;
      droppedBytes += name.length + value.length;
    }
  }

  // --- request body ---
  let body: string | undefined;
  let bodyEncoding: 'utf8' | 'base64' | undefined;
  let bodySize = 0;
  let hasPasswordBody = false;
  if (req.postData && typeof req.postData === 'object') {
    const pd = req.postData as Record<string, unknown>;
    if (typeof pd.text === 'string') {
      body = pd.text;
      bodyEncoding = 'utf8';
    } else if (typeof pd.params === 'object' && Array.isArray(pd.params)) {
      // Some HAR exporters provide params separately instead of text — collapse
      // back to x-www-form-urlencoded.
      body = (pd.params as { name?: unknown; value?: unknown }[])
        .filter((p) => typeof p.name === 'string')
        .map((p) => {
          const n = encodeURIComponent(p.name as string);
          const v = typeof p.value === 'string' ? encodeURIComponent(p.value) : '';
          return `${n}=${v}`;
        })
        .join('&');
      bodyEncoding = 'utf8';
    }
    if (body !== undefined) {
      // The plan caps body at 50KB; reject oversize bodies entirely rather
      // than truncating — truncated bodies break auth replay invisibly.
      if (body.length > HAR_MAX_BODY_BYTES) {
        throw rejection(
          'har_entry_too_large',
          `entry[${index}] body ${body.length} bytes > ${HAR_MAX_BODY_BYTES}`,
        );
      }
      if (JS_LINE_TERMINATOR_RE.test(body)) {
        throw rejection(
          'invalid_har_shape',
          `entry[${index}].postData.text contains U+2028 / U+2029`,
        );
      }
      bodySize = body.length;
      // Detect password-like fields in the body for the preview flag-chip.
      hasPasswordBody = /(?:^|[&{,"])\s*(password|pwd|passwd|secret)\s*[":=]/i.test(body);
    }
  }

  // --- response side (informational only — never replayed) ---
  const respStatus = typeof resp.status === 'number' ? resp.status : 0;
  const respHeaders = Array.isArray(resp.headers) ? resp.headers : [];
  let cookiesSet = 0;
  for (const h of respHeaders) {
    if (!h || typeof h !== 'object') continue;
    const name = typeof (h as { name?: unknown }).name === 'string'
      ? ((h as { name: string }).name)
      : '';
    if (name && name.toLowerCase() === 'set-cookie') cookiesSet += 1;
  }

  // --- preview shape ---
  const flagChips: HarFlagChip[] = [];
  if (hasAuthHeader) flagChips.push('auth_header');
  if (cookiesSet > 0) flagChips.push('set_cookie');
  if (hasPasswordBody) flagChips.push('password_body');
  // 'totp_detected' / 'non_replayable_pattern' added by the parser's
  // post-extraction detector passes (parseHar() does this).

  const preview: HarEntryPreview = {
    index,
    method,
    url_scrubbed: scrubUrlQueryParams(rawUrl),
    response_status: respStatus,
    has_auth_header: hasAuthHeader,
    has_cookie_header: hasCookieHeader,
    has_password_body: hasPasswordBody,
    body_size: bodySize,
    flag_chips: flagChips,
  };

  const request: ReplayedRequest = {
    method,
    url: rawUrl,
    headers: keptHeaders,
    ...(body !== undefined ? { body } : {}),
    ...(bodyEncoding !== undefined ? { body_encoding: bodyEncoding } : {}),
  };

  return {
    preview,
    request,
    droppedHeaderCount,
    droppedBytes,
    keptHeaderCount: keptHeaders.length,
    cookiesSet,
    hasAuthHeader,
  };
}

// ---------------------------------------------------------------------------
// Privacy scrubbers
// ---------------------------------------------------------------------------

/**
 * Replace the VALUES of token-keyed query-string params with `[REDACTED]`,
 * leaving keys + non-token params untouched. Returns the URL string as it
 * should appear in preview responses, audit logs, and any other surface
 * where the URL leaves the parse boundary.
 *
 * Defensive: if the URL doesn't parse, return the literal `[INVALID_URL]`
 * rather than echoing the input — the caller should already have rejected
 * the entry at extractEntry(), but a fallback is cheaper than a leak.
 */
export function scrubUrlQueryParams(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return '[INVALID_URL]';
  }
  const params = parsed.searchParams;
  // Iterate over a snapshot — URLSearchParams.set during iteration is
  // implementation-defined.
  const keys = Array.from(params.keys());
  for (const k of keys) {
    if (HAR_TOKEN_QUERY_KEYS.has(k.toLowerCase())) {
      params.set(k, '[REDACTED]');
    }
  }
  parsed.search = params.toString();
  return parsed.toString();
}

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

/**
 * Find the first request whose path or body matches our TOTP heuristics.
 * Returns null if none — the validator + script-emitter treat null as
 * "no TOTP step; don't inline a code regenerator." Caller is responsible
 * for whether `totp_secret` is required (it isn't — many TOTP flows
 * authenticate by reusing a captured code at replay time, which fails
 * after 30s; the user is told to add a secret for proper freshness).
 */
export function detectTotpStep(requests: ReplayedRequest[]): HarTotpStep | null {
  for (let i = 0; i < requests.length; i++) {
    const r = requests[i];
    if (r.method !== 'POST') continue;
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(r.url);
    } catch {
      continue;
    }
    const pathMatches = HAR_TOTP_PATHS.some((re) => re.test(parsedUrl.pathname));
    if (!pathMatches) continue;

    // Determine body kind from Content-Type.
    const ct = r.headers.find((h) => h.name.toLowerCase() === 'content-type')?.value ?? '';
    const isJson = /application\/(?:json|.*\+json)/i.test(ct);
    const isForm = /application\/x-www-form-urlencoded/i.test(ct);
    if (!isJson && !isForm) continue;

    const body = r.body ?? '';
    if (!body) continue;

    // Find the first matching body field.
    for (const field of HAR_TOTP_BODY_FIELDS) {
      if (isForm) {
        // Match `field=...` either at the start of the body or following an &.
        const re = new RegExp(`(?:^|&)${escapeRegExp(field)}=`, 'i');
        if (re.test(body)) {
          return { entry_index: i, body_field: field, body_kind: 'form' };
        }
      } else if (isJson) {
        // Naive JSON-key match — we don't parse to avoid throwing on partial
        // bodies. Matches `"field"\s*:` to disambiguate from value content.
        const re = new RegExp(`"${escapeRegExp(field)}"\\s*:`, 'i');
        if (re.test(body)) {
          return { entry_index: i, body_field: field, body_kind: 'json' };
        }
      }
    }
  }
  return null;
}

/**
 * Surface any captured request that matches a known non-replayable pattern
 * (WebAuthn / passkey / SMS code). Preview UI combines all matches into a
 * single banner so the user can decide whether to recapture the HAR with
 * a different IdP setting (e.g. backup TOTP instead of passkey).
 */
export function detectNonReplayablePatterns(
  requests: ReplayedRequest[],
): NonReplayableWarning[] {
  const out: NonReplayableWarning[] = [];
  for (let i = 0; i < requests.length; i++) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(requests[i].url);
    } catch {
      continue;
    }
    for (const { regex, hint } of HAR_NON_REPLAYABLE_PATTERNS) {
      if (regex.test(parsedUrl.pathname)) {
        out.push({ entry_index: i, pattern_hint: hint });
        break; // one hint per entry is enough
      }
    }
  }
  return out;
}

/**
 * Unique hostnames across the request list. Used for the credential's
 * `origins_observed` field + the SSRF revalidation at PUT time.
 *
 * Path / query / fragment intentionally excluded — origins are the only
 * thing safe to expose in the credential summary GET.
 */
export function extractOriginsObserved(requests: ReplayedRequest[]): string[] {
  const out = new Set<string>();
  for (const r of requests) {
    try {
      const u = new URL(r.url);
      if (u.hostname) out.add(u.hostname.toLowerCase());
    } catch {
      // Already rejected at extractEntry, but defense-in-depth: skip silently.
    }
  }
  return Array.from(out);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Convenience builder for the thrown-rejection convention. The route layer
 * catches and re-emits as a 422 with the matching `error_code`.
 */
export function rejection(code: HarErrorCode, detail: string): Error {
  const err = new Error(`har_parse_rejection: ${code}`) as Error & HarParseRejection;
  err.error_code = code;
  err.detail = detail;
  return err;
}

/**
 * True if the literal `host` portion of a URL parses to an IPv4 or IPv6
 * address inside a private / loopback / link-local / IMDS range. Hostnames
 * that look like domains pass through here; DNS-level SSRF is the
 * validateReplaySsrf step's job (M1 step 8).
 */
function isPrivateOrLoopbackLiteral(host: string): boolean {
  let addr: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    addr = ipaddr.parse(host);
  } catch {
    return false; // not a literal IP — domain, will be DNS-resolved at PUT
  }
  const range = addr.range();
  // ipaddr range names: 'private', 'loopback', 'linkLocal', 'uniqueLocal',
  // 'reserved', 'carrierGradeNat', 'broadcast', 'multicast' — block all
  // non-'unicast' literals.
  return range !== 'unicast';
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
