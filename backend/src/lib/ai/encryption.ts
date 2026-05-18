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

// === DEPSCANNER-SYNC: STOP ABOVE THIS LINE ===
// Everything below uses the backend's Supabase client and is intentionally
// excluded from the depscanner copy. scripts/sync-encryption.ts truncates at
// the marker; .github/workflows/encryption-sync-check.yml fails the PR if the
// committed copy at depscanner/src/lib/encryption.ts diverges.

async function rotateEncryptedTable(
  supabase: any,
  tableName: string,
  encryptedColumn: string
): Promise<{ rotated: number; failed: number }> {
  const currentVersion = getCurrentKeyVersion();

  const { data: rows, error } = await supabase
    .from(tableName)
    .select(`id, ${encryptedColumn}, encryption_key_version`)
    .lt('encryption_key_version', currentVersion);

  if (error || !rows?.length) return { rotated: 0, failed: 0 };

  let rotated = 0;
  let failed = 0;
  const BATCH_SIZE = 50;

  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    for (const row of batch) {
      try {
        const ciphertext = row[encryptedColumn];
        const plaintext = decryptApiKey(ciphertext, row.encryption_key_version);
        const { encrypted, version } = encryptApiKey(plaintext, currentVersion);

        await supabase
          .from(tableName)
          .update({
            [encryptedColumn]: encrypted,
            encryption_key_version: version,
            updated_at: new Date().toISOString(),
          })
          .eq('id', row.id);

        rotated++;
      } catch (err: any) {
        console.error(`[Encryption] Failed to rotate key for ${tableName} ${row.id}:`, err.message);
        failed++;
      }
    }
  }

  return { rotated, failed };
}

export async function rotateEncryptionKeys(): Promise<{ rotated: number; failed: number }> {
  const { supabase } = await import('../supabase');

  // BYOK (organization_ai_providers) was dropped in phase29_drop_byok; the
  // only remaining encrypted-at-rest table is the IaC v2 registry creds.
  const creds = await rotateEncryptedTable(
    supabase,
    'organization_registry_credentials',
    'encrypted_credentials'
  );

  return {
    rotated: creds.rotated,
    failed: creds.failed,
  };
}
