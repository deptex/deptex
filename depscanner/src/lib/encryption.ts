// AUTO-GENERATED — DO NOT EDIT.
// Synced from backend/src/lib/ai/encryption.ts via scripts/sync-encryption.ts.
// CI (.github/workflows/encryption-sync-check.yml) fails when this file drifts.
// To change: edit the source file, then `npx tsx scripts/sync-encryption.ts`.

import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const NONCE_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

function getCurrentKey(): Buffer | null {
  const hex = process.env.AI_ENCRYPTION_KEY;
  if (!hex) return null;
  return Buffer.from(hex, 'hex');
}

function getPreviousKey(): Buffer | null {
  const hex = process.env.AI_ENCRYPTION_KEY_PREV;
  if (!hex) return null;
  return Buffer.from(hex, 'hex');
}

function getCurrentKeyVersion(): number {
  return parseInt(process.env.AI_ENCRYPTION_KEY_VERSION || '1', 10);
}

export function isEncryptionConfigured(): boolean {
  return !!process.env.AI_ENCRYPTION_KEY;
}

export function encryptApiKey(plaintext: string, keyVersion?: number): { encrypted: string; version: number } {
  const key = getCurrentKey();
  if (!key) throw new Error('AI_ENCRYPTION_KEY not configured');

  const version = keyVersion ?? getCurrentKeyVersion();
  const nonce = crypto.randomBytes(NONCE_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, nonce, { authTagLength: AUTH_TAG_LENGTH });

  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const encrypted = `${nonce.toString('base64')}:${ciphertext.toString('base64')}:${authTag.toString('base64')}`;
  return { encrypted, version };
}

export function decryptApiKey(encrypted: string, storedVersion: number): string {
  const parts = encrypted.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted key format');

  const nonce = Buffer.from(parts[0], 'base64');
  const ciphertext = Buffer.from(parts[1], 'base64');
  const authTag = Buffer.from(parts[2], 'base64');

  // Buffer.concat([update, final]).toString('utf8') is byte-stable across
  // Node versions and never splits a multi-byte sequence mid-character.
  // The previous `update + final('utf8')` form coerced update's Buffer to a
  // utf-8 string before concat, which could emit U+FFFD on a chunk boundary.
  const currentKey = getCurrentKey();
  if (currentKey) {
    try {
      const decipher = crypto.createDecipheriv(ALGORITHM, currentKey, nonce, { authTagLength: AUTH_TAG_LENGTH });
      decipher.setAuthTag(authTag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    } catch {
      // Current key failed — try previous (regardless of stored version, since
      // a partial rotation could leave the row's version bumped while the
      // ciphertext is still old).
    }
  }

  const prevKey = getPreviousKey();
  if (prevKey) {
    try {
      const decipher = crypto.createDecipheriv(ALGORITHM, prevKey, nonce, { authTagLength: AUTH_TAG_LENGTH });
      decipher.setAuthTag(authTag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    } catch {
      // fall through
    }
  }

  // storedVersion is no longer load-bearing — auth-tag verification is the
  // primary correctness check. Keep the parameter so existing callers don't
  // break, but reference it in the error to aid debugging.
  void storedVersion;
  throw new Error('Unable to decrypt API key — no valid encryption key available');
}
