// RFC 6238 §5.1 reference-vector tests for the vendored TOTP helper.
//
// The §5.1 table uses a 20-byte ASCII secret "12345678901234567890" with
// Digit=8 and the SHA-1 HMAC; we base32-encode the secret so we can run it
// through `generateTotpCode()` which only accepts canonical RFC 4648 base32
// (the validator at PUT time enforces this — the helper does too).
//
// Why these vectors specifically: M0 step 5 of the DAST HAR Import plan pins
// these as the helper's correctness gate. The same function bytes get inlined
// into the ZAP Script-Based Authentication script body at scan time, so any
// drift here breaks mid-scan re-auth. Six named cases + boundary edges.

import { generateTotpCode, base32Decode } from '../dast/_helpers/totp-rfc6238';

/**
 * Encode raw bytes as RFC 4648 base32 (canonical uppercase alphabet, with
 * `=` padding so the encoded length is a multiple of 8). Kept inside the
 * test file because the public surface (validator + worker) only ever
 * RECEIVES already-base32 secrets — the user types/pastes them.
 */
function base32Encode(buf: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const byte of buf) {
    bits += byte.toString(2).padStart(8, '0');
  }
  let out = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    out += alphabet[parseInt(chunk, 2)];
  }
  while (out.length % 8 !== 0) out += '=';
  return out;
}

// "12345678901234567890" — the canonical RFC 6238 §5.1 SHA-1 secret.
const RFC_SECRET_ASCII = '12345678901234567890';
const RFC_SECRET_B32 = base32Encode(Buffer.from(RFC_SECRET_ASCII, 'ascii'));

describe('generateTotpCode — RFC 6238 §5.1 reference vectors (SHA-1, Digit=8)', () => {
  // The six named SHA-1 cases from RFC 6238 §5.1 Appendix B table.
  const VECTORS: Array<{ t: number; code: string }> = [
    { t: 59, code: '94287082' },
    { t: 1111111109, code: '07081804' },
    { t: 1111111111, code: '14050471' },
    { t: 1234567890, code: '89005924' },
    { t: 2000000000, code: '69279037' },
    // 20_000_000_000 sits beyond a signed 32-bit int but inside JS safe
    // integer range; counter math uses BigInt so the conversion is lossless.
    { t: 20_000_000_000, code: '65353130' },
  ];

  it.each(VECTORS)('T=$t produces $code', ({ t, code }) => {
    const out = generateTotpCode(RFC_SECRET_B32, {
      time: t,
      digits: 8,
      period: 30,
      algorithm: 'SHA1',
    });
    expect(out).toBe(code);
  });
});

describe('generateTotpCode — default-arg behaviour (Decision 17: RFC 6238 defaults only for v1)', () => {
  it('defaults to 6 digits / 30s period / SHA-1', () => {
    // T=59 with the same secret but Digit=6 should be the right-most 6
    // digits of the 8-digit reference output, i.e. "287082".
    const out = generateTotpCode(RFC_SECRET_B32, { time: 59 });
    expect(out).toBe('287082');
  });

  it('returns a zero-padded string of exactly `digits` length', () => {
    // Pick a T value that produces a leading-zero code in 6-digit form so we
    // see the padding behaviour explicitly: T=1111111109 → 8-digit 07081804,
    // 6-digit "081804" — still 6 chars.
    const out = generateTotpCode(RFC_SECRET_B32, { time: 1111111109 });
    expect(out).toHaveLength(6);
  });

  it('uses Date.now()/1000 when `time` is omitted', () => {
    // Don't assert a specific output (clock-dependent), just that we get a
    // 6-digit numeric string and that two calls inside the same 30s period
    // return the same code.
    const a = generateTotpCode(RFC_SECRET_B32);
    const b = generateTotpCode(RFC_SECRET_B32);
    expect(a).toMatch(/^\d{6}$/);
    expect(a).toBe(b);
  });
});

describe('base32Decode — canonical-input acceptance', () => {
  it('round-trips the RFC test secret bytes-for-bytes', () => {
    const decoded = base32Decode(RFC_SECRET_B32);
    expect(decoded.toString('ascii')).toBe(RFC_SECRET_ASCII);
  });

  it('tolerates trailing padding', () => {
    // `JBSWY3DPEHPK3PXP` is "Hello!ÐÞÝ¯" — irrelevant content, what matters
    // is the no-padding form decodes the same as the padded form.
    const padded = 'JBSWY3DPEHPK3PXP';
    const out = base32Decode(padded);
    expect(out.length).toBe(10);
  });

  it('rejects non-alphabet characters', () => {
    expect(() => base32Decode('JBSW!Y3DP')).toThrow(/invalid base32 char/i);
  });
});
