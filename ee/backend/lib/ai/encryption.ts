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

  const currentKey = getCurrentKey();
  if (currentKey) {
    try {
      const decipher = crypto.createDecipheriv(ALGORITHM, currentKey, nonce, { authTagLength: AUTH_TAG_LENGTH });
      decipher.setAuthTag(authTag);
      return decipher.update(ciphertext) + decipher.final('utf8');
    } catch {
      // Current key failed — try previous if version mismatch
    }
  }

  if (storedVersion < getCurrentKeyVersion()) {
    const prevKey = getPreviousKey();
    if (prevKey) {
      const decipher = crypto.createDecipheriv(ALGORITHM, prevKey, nonce, { authTagLength: AUTH_TAG_LENGTH });
      decipher.setAuthTag(authTag);
      return decipher.update(ciphertext) + decipher.final('utf8');
    }
  }

  throw new Error('Unable to decrypt API key — no valid encryption key available');
}

export async function rotateEncryptionKeys(): Promise<{ rotated: number; failed: number }> {
  const { supabase } = await import('../../../../backend/src/lib/supabase');
  const currentVersion = getCurrentKeyVersion();

  const { data: rows, error } = await supabase
    .from('organization_ai_providers')
    .select('id, encrypted_api_key, encryption_key_version')
    .lt('encryption_key_version', currentVersion);

  if (error || !rows?.length) return { rotated: 0, failed: 0 };

  let rotated = 0;
  let failed = 0;
  const BATCH_SIZE = 50;

  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    for (const row of batch) {
      try {
        const plaintext = decryptApiKey(row.encrypted_api_key, row.encryption_key_version);
        const { encrypted, version } = encryptApiKey(plaintext, currentVersion);

        await supabase
          .from('organization_ai_providers')
          .update({ encrypted_api_key: encrypted, encryption_key_version: version, updated_at: new Date().toISOString() })
          .eq('id', row.id);

        rotated++;
      } catch (err: any) {
        console.error(`[Encryption] Failed to rotate key for provider ${row.id}:`, err.message);
        failed++;
      }
    }
  }

  return { rotated, failed };
}
