// Vendored RFC 6238 TOTP helper for DAST HAR replay auth (Patch A / Decision 18).
//
// This file is referenced TWICE:
//   1. As a normal TS module — the worker calls `generateTotpCode()` at
//      script-render-time validation paths and tests.
//   2. The function bodies (base32 decode + HOTP + TOTP) are STRING-INLINED
//      into the ZAP Script-Based Authentication JS body at scan-time, so the
//      ZAP-side script can regenerate fresh codes on every auth invocation
//      (initial + indicator-miss re-auth) without a network call back to us.
//
// Why vendored (no `otplib` / `speakeasy` dep): TOTP is a security primitive,
// and the npm supply chain has burned us once already. ~30 LOC of RFC 6238 is
// cheap to own; the test suite covers all six RFC 6238 §5.1 reference vectors.
//
// Algorithm: HOTP(K, T) where T = floor(unixSeconds / period) and K is the
// base32-decoded secret. Dynamic-truncation digit extraction per RFC 4226 §5.3.

import { createHmac } from 'crypto';

export interface TotpOptions {
  /** Unix epoch in SECONDS (NOT milliseconds). Default: Date.now()/1000. */
  time?: number;
  /** Step size in seconds. RFC 6238 default = 30. */
  period?: number;
  /** Number of digits emitted. RFC 6238 default = 6. */
  digits?: number;
  /** HMAC variant. RFC 6238 default = SHA1; SHA256/SHA512 supported by §5.1. */
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
}

/**
 * Decode an RFC 4648 base32 string (canonical alphabet `A-Z2-7`, optional
 * `=` padding) into raw bytes. Whitespace and lowercase are rejected — the
 * validator at PUT time enforces canonical form before this helper ever
 * runs. Returns a Buffer.
 */
export function base32Decode(b32: string): Buffer {
  // Strip optional `=` padding; the alphabet has no `=` value.
  const stripped = b32.replace(/=+$/, '');
  // Build bit-stream and pack into bytes.
  let bits = '';
  for (const ch of stripped) {
    const v = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(ch);
    if (v < 0) throw new Error(`invalid base32 char: ${ch}`);
    bits += v.toString(2).padStart(5, '0');
  }
  // Truncate trailing partial byte (per RFC 4648 §6: the partial bits
  // produced when padding was dropped are zero-pad and discarded).
  const fullBytes = Math.floor(bits.length / 8);
  const out = Buffer.alloc(fullBytes);
  for (let i = 0; i < fullBytes; i++) {
    out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return out;
}

/**
 * Generate an RFC 6238 TOTP code. Returns a zero-padded string of length
 * `digits` (default 6). Pure function; no I/O.
 */
export function generateTotpCode(secret: string, opts: TotpOptions = {}): string {
  const period = opts.period ?? 30;
  const digits = opts.digits ?? 6;
  const algorithm = opts.algorithm ?? 'SHA1';
  const time = opts.time ?? Math.floor(Date.now() / 1000);
  const counter = Math.floor(time / period);

  // RFC 4226: counter is encoded big-endian as 8 bytes.
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));

  const key = base32Decode(secret);
  // RFC 6238 §5.1 explicitly notes the reference vectors use SECRETS of
  // different lengths for SHA-256 / SHA-512 (20 / 32 / 64 bytes). The
  // RFC 4226 HMAC construction does the key padding itself; we hand the
  // raw decoded bytes to Node's HMAC.
  const hmac = createHmac(algorithm.toLowerCase(), key).update(counterBuf).digest();

  // RFC 4226 §5.3 dynamic truncation: low nibble of last byte is the
  // offset into the HMAC output; read 4 bytes starting there, mask high
  // bit of first byte, mod 10^digits.
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (code % 10 ** digits).toString().padStart(digits, '0');
}
