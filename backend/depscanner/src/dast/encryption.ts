// DAST credential encryption — depscanner copy.
//
// Mirrors `backend/src/lib/dast-encryption.ts` (the canonical implementation
// the API uses). The two copies must stay in sync — same algorithm constants,
// same key-rotation fallback semantics, same wipePlaintext signature.
// Duplication exists because each package has rootDir: ./src and forbids
// cross-package production imports; the cross-package shared lib is on the
// v2.1b cleanup list.
//
// This is the depscanner-side runtime: the worker calls decryptCredential at
// scan-spawn time, hands the plaintext to buildAutomationYaml, then invokes
// wipePlaintext on the buffer immediately after. The plaintext is NEVER
// written to scan_jobs.payload, error_details, dast_logs, stderr, or QStash
// payload (test-enforced via dast-log-scrub).

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
      return decipher.update(ciphertext) + decipher.final('utf8');
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
      return decipher.update(ciphertext) + decipher.final('utf8');
    }
  }

  throw new Error('Unable to decrypt DAST credential — no valid encryption key available');
}

export function wipePlaintext(buf: Buffer): void {
  buf.fill(0);
}
