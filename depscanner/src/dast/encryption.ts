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
  if (parts.length !== 3) throw new Error('Invalid encrypted credential format');

  const nonce = Buffer.from(parts[0], 'base64');
  const ciphertext = Buffer.from(parts[1], 'base64');
  const authTag = Buffer.from(parts[2], 'base64');

  const currentKey = getCurrentKey();
  if (currentKey) {
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
    } catch {
      // Current key failed — fall through to previous if version older.
    }
  }

  if (storedVersion < getCurrentKeyVersion()) {
    const prevKey = getPreviousKey();
    if (prevKey) {
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
