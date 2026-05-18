// DAST credential encryption — depscanner copy.
//
// Mirrors `backend/src/lib/dast-encryption.ts` (the canonical implementation
// the API uses). The two copies must stay in sync — same algorithm constants,
// same key-rotation fallback semantics. Duplication exists because each
// package has rootDir: ./src and forbids cross-package production imports;
// the cross-package shared lib is on the v2.1b cleanup list.
//
// This is the depscanner-side runtime: the worker calls decryptCredential at
// scan-spawn time, hands the plaintext to buildAutomationYaml, and relies on
// (a) Fly machine isolation (one tenant per scan, machine destroyed at end)
// and (b) GC of the JS strings holding the plaintext after the spawn returns.
// We previously zero-filled a Buffer copy of the plaintext via wipePlaintext;
// that was security theater because the actual plaintext lives in immutable
// V8 strings (the decrypted return value, the JSON.parse'd payload object's
// .password/.token/.cookies[].value fields, and the YAML written to disk
// before unlink). Removing the buffer dance avoids creating false confidence.
// The real safety properties remain: plaintext is NEVER written to
// scan_jobs.payload, error_details, dast_logs, stderr, or QStash payload
// (test-enforced via dast-log-scrub).

import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const NONCE_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;

/**
 * Thrown when the encrypted credential is structurally malformed (bad base64,
 * wrong nonce/tag length) or the configured key is the wrong length. These are
 * operator/config errors, distinct from a stale-key auth-tag verification
 * failure — they must NOT be misreported as `dast_credential_key_stale`.
 */
export class DastCredentialFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DastCredentialFormatError';
  }
}

function getCurrentKey(): Buffer | null {
  const hex = process.env.DAST_CREDENTIAL_KEY;
  if (!hex) return null;
  return Buffer.from(hex, 'hex');
}

function getPreviousKey(): Buffer | null {
  const hex = process.env.DAST_CREDENTIAL_KEY_PREV;
  if (!hex) return null;
  return Buffer.from(hex, 'hex');
}

function getCurrentKeyVersion(): number {
  return parseInt(process.env.DAST_CREDENTIAL_KEY_VERSION || '1', 10);
}

export function isDastEncryptionConfigured(): boolean {
  return !!process.env.DAST_CREDENTIAL_KEY;
}

export function decryptCredential(encrypted: string, storedVersion: number): string {
  const parts = encrypted.split(':');
  if (parts.length !== 3) {
    throw new DastCredentialFormatError('Invalid encrypted credential format');
  }

  const nonce = Buffer.from(parts[0], 'base64');
  const ciphertext = Buffer.from(parts[1], 'base64');
  const authTag = Buffer.from(parts[2], 'base64');

  // Validate structure UP FRONT so a genuinely corrupt credential (bad base64,
  // truncated nonce/tag) is reported distinctly instead of being swallowed by
  // the current-key catch and misreported as a stale-key problem. Buffer.from
  // with 'base64' silently drops invalid characters, so a length check after
  // decode catches both malformed base64 and wrong-length fields.
  if (nonce.length !== NONCE_LENGTH) {
    throw new DastCredentialFormatError(
      `Invalid encrypted credential: nonce must decode to ${NONCE_LENGTH} bytes`,
    );
  }
  if (authTag.length !== AUTH_TAG_LENGTH) {
    throw new DastCredentialFormatError(
      `Invalid encrypted credential: auth tag must decode to ${AUTH_TAG_LENGTH} bytes`,
    );
  }
  if (ciphertext.length === 0) {
    throw new DastCredentialFormatError('Invalid encrypted credential: empty ciphertext');
  }

  const currentKey = getCurrentKey();
  if (currentKey) {
    if (currentKey.length !== KEY_LENGTH) {
      throw new DastCredentialFormatError(
        `DAST_CREDENTIAL_KEY must be ${KEY_LENGTH} bytes (64 hex chars)`,
      );
    }
    try {
      const decipher = crypto.createDecipheriv(ALGORITHM, currentKey, nonce, {
        authTagLength: AUTH_TAG_LENGTH,
      });
      decipher.setAuthTag(authTag);
      // Concatenate buffers FIRST then decode as UTF-8 once. The previous code
      // (`decipher.update(ciphertext) + decipher.final('utf8')`) coerces the
      // update Buffer to a string via implicit toString(), then concatenates.
      // If a multi-byte UTF-8 codepoint straddles the update/final boundary,
      // each half decodes independently and yields U+FFFD replacement chars,
      // corrupting credentials with non-ASCII passwords/cookies.
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return plaintext.toString('utf8');
    } catch (e) {
      // Only an auth-tag verification failure means "wrong key, try previous".
      // Any other failure (corrupt ciphertext, OpenSSL internal error) is NOT a
      // stale-key problem — let it propagate so the operator sees the real cause.
      const msg = (e as Error)?.message ?? '';
      const isAuthTagFailure =
        /unable to authenticate|auth(?:entication)? tag/i.test(msg);
      if (!isAuthTagFailure) {
        throw new DastCredentialFormatError(
          `DAST credential decrypt failed (not a key-version issue): ${msg}`,
        );
      }
      // Auth-tag mismatch — fall through to previous if version older.
    }
  }

  if (storedVersion < getCurrentKeyVersion()) {
    const prevKey = getPreviousKey();
    if (prevKey) {
      if (prevKey.length !== KEY_LENGTH) {
        throw new DastCredentialFormatError(
          `DAST_CREDENTIAL_KEY_PREV must be ${KEY_LENGTH} bytes (64 hex chars)`,
        );
      }
      const decipher = crypto.createDecipheriv(ALGORITHM, prevKey, nonce, {
        authTagLength: AUTH_TAG_LENGTH,
      });
      decipher.setAuthTag(authTag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return plaintext.toString('utf8');
    }
  }

  throw new Error('Unable to decrypt DAST credential — no valid encryption key available');
}
