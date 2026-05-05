// Structured-log scrub for DAST credential fixtures + production plaintexts.
//
// Architectural invariant (test-enforced): decrypted DAST credential plaintexts
// MUST NEVER appear in scan_jobs.payload, scan_jobs.error_details,
// extraction_logs/dast_logs rows, worker stderr/stdout, QStash payloads, or
// crash trace dumps. This file provides:
//
//   1. `scanLogRowForPlaintext` — runs in tests; checks any structured log row
//      for the synthetic fixtures used in the credential-leak smoke run.
//      Synthetic fixtures are intentional: they're indistinguishable from
//      real credentials by the regexes below, but their literal values let
//      tests assert "we wrote X into the encrypt path; did X leak anywhere?"
//
//   2. `scrubLogValue` — runtime helper used by `dast-logger.ts` (Task 7) to
//      scrub *any* string before it reaches a log sink. Catches JWT-shaped
//      tokens, password-key-shaped JSON values, cookie names with values, etc.

// ---------------------------------------------------------------------------
// Synthetic fixtures (used by the credential-leak test smoke run)
// ---------------------------------------------------------------------------

export const SYNTHETIC_PASSWORD_FIXTURE = 's3cr3t-fixture';
export const SYNTHETIC_JWT_FIXTURE = 'eyJhbGciOiJIUzI1NiJ9.testpayload.testsig';
export const SYNTHETIC_COOKIE_FIXTURE = 'session=fixture-cookie-value-7f3e';

export const SYNTHETIC_FIXTURES = [
  SYNTHETIC_PASSWORD_FIXTURE,
  SYNTHETIC_JWT_FIXTURE,
  SYNTHETIC_COOKIE_FIXTURE,
] as const;

// ---------------------------------------------------------------------------
// Generic plaintext scrubbers
// ---------------------------------------------------------------------------

// Three-segment dot-separated base64url: header.payload.signature.
// Anchored to base64url charset to avoid catching version strings ("1.2.3").
const JWT_REGEX = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

// Common credential JSON shape: "password":"value", "token":"value", etc.
// Anchored to keys we know our own DTOs use; intentionally narrow to keep
// false-positive rate low.
const CREDENTIAL_JSON_REGEX =
  /("(?:password|token|access_token|refresh_token|api_key|apikey|secret|client_secret)"\s*:\s*")([^"\\]+)(")/gi;

// Cookie header values: `Set-Cookie: name=value; …` — preserve the name, scrub
// the value.
const COOKIE_HEADER_REGEX = /\b(set-cookie|cookie)\s*:\s*([^=\s]+)\s*=\s*([^;,\s]+)/gi;

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

export interface ScrubMatch {
  fixture: string;
  excerpt: string; // ~80 chars of surrounding context for failure messages
  occurrence_count: number;
}

/**
 * Scans a single structured log row (or any string) for any of the synthetic
 * credential fixtures. Returns an array of matches; the empty array means the
 * row is safe.
 *
 * Used in tests:
 *   const matches = scanLogRowForPlaintext(logRow);
 *   expect(matches).toEqual([]);
 */
export function scanLogRowForPlaintext(serializedRow: string | object): ScrubMatch[] {
  const haystack =
    typeof serializedRow === 'string' ? serializedRow : safeStringify(serializedRow);
  const matches: ScrubMatch[] = [];

  for (const fixture of SYNTHETIC_FIXTURES) {
    let from = 0;
    let count = 0;
    let firstIdx = -1;
    while (true) {
      const idx = haystack.indexOf(fixture, from);
      if (idx === -1) break;
      if (firstIdx === -1) firstIdx = idx;
      count += 1;
      from = idx + fixture.length;
    }
    if (count > 0) {
      const excerptStart = Math.max(0, firstIdx - 32);
      const excerptEnd = Math.min(haystack.length, firstIdx + fixture.length + 32);
      matches.push({
        fixture,
        excerpt: haystack.slice(excerptStart, excerptEnd),
        occurrence_count: count,
      });
    }
  }

  return matches;
}

/**
 * Runtime scrubber. Replaces JWT tokens, credential JSON values, and cookie
 * values with `[REDACTED]`. Idempotent and safe to call on any string. Used
 * by `dast-logger.ts` (Task 7) before any log sink write.
 */
export function scrubLogValue(value: string): string {
  if (typeof value !== 'string' || value.length === 0) return value;
  let out = value;
  out = out.replace(JWT_REGEX, '[REDACTED_JWT]');
  out = out.replace(CREDENTIAL_JSON_REGEX, '$1[REDACTED]$3');
  out = out.replace(COOKIE_HEADER_REGEX, (_m, header, name) => `${header}: ${name}=[REDACTED]`);
  return out;
}

/**
 * Recursively scrub an object's string values. Used by structured-log
 * helpers that emit JSON to QStash / Supabase.
 */
export function scrubLogObject<T>(obj: T): T {
  if (obj == null) return obj;
  if (typeof obj === 'string') return scrubLogValue(obj) as unknown as T;
  if (Array.isArray(obj)) return obj.map((v) => scrubLogObject(v)) as unknown as T;
  if (typeof obj === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      out[k] = scrubLogObject(v);
    }
    return out as unknown as T;
  }
  return obj;
}

function safeStringify(o: unknown): string {
  try {
    return JSON.stringify(o);
  } catch {
    return String(o);
  }
}
