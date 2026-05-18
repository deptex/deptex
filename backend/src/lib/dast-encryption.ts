import crypto from 'crypto';

// Per-target DAST credential encryption. Mirrors backend/src/lib/ai/encryption.ts
// against DAST_CREDENTIAL_KEY (depscanner Fly env). Decryption is worker-side
// only; the API never decrypts. See plan-2.1a-engine §"Cred storage rules".

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

export function encryptCredential(
  plaintext: string,
  keyVersion?: number,
): { encrypted: string; version: number } {
  const key = getCurrentKey();
  if (!key) throw new Error('DAST_CREDENTIAL_KEY not configured');

  const version = keyVersion ?? getCurrentKeyVersion();
  const nonce = crypto.randomBytes(NONCE_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, nonce, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const encrypted = `${nonce.toString('base64')}:${ciphertext.toString('base64')}:${authTag.toString('base64')}`;
  return { encrypted, version };
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
