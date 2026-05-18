import * as fs from 'fs';
import * as path from 'path';

import { encryptApiKey, decryptApiKey, isEncryptionConfigured, rotateEncryptionKeys } from '../encryption';
import { setTableResponse, clearTableRegistry } from '../../../test/mocks/supabaseSingleton';

const FIXTURE = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'encryption-roundtrip.json'), 'utf8')
) as { key_hex: string; key_version: number; plaintext: string; encrypted: string };

describe('encryption helper (backend)', () => {
  const ORIG_ENV = { ...process.env };

  beforeEach(() => {
    process.env.AI_ENCRYPTION_KEY = FIXTURE.key_hex;
    process.env.AI_ENCRYPTION_KEY_VERSION = String(FIXTURE.key_version);
    delete process.env.AI_ENCRYPTION_KEY_PREV;
  });

  afterEach(() => {
    process.env = { ...ORIG_ENV };
    clearTableRegistry();
    jest.clearAllMocks();
  });

  it('reports configured when AI_ENCRYPTION_KEY is set', () => {
    expect(isEncryptionConfigured()).toBe(true);
  });

  it('round-trips the fixture plaintext through encryptApiKey + decryptApiKey', () => {
    const { encrypted, version } = encryptApiKey(FIXTURE.plaintext);
    expect(version).toBe(FIXTURE.key_version);
    expect(decryptApiKey(encrypted, version)).toBe(FIXTURE.plaintext);
  });

  it('decrypts the checked-in known ciphertext', () => {
    expect(decryptApiKey(FIXTURE.encrypted, FIXTURE.key_version)).toBe(FIXTURE.plaintext);
  });

  describe('rotateEncryptionKeys', () => {
    const NEW_KEY = '0000000000000000000000000000000000000000000000000000000000000099';

    beforeEach(() => {
      // Encrypt a payload under v1 first so we have stale ciphertext to walk.
      // (FIXTURE.key_hex acts as v1 / "previous" in this test.)
      process.env.AI_ENCRYPTION_KEY = FIXTURE.key_hex;
      process.env.AI_ENCRYPTION_KEY_VERSION = '1';
    });

    it('walks organization_registry_credentials (BYOK ai providers retired in phase29)', async () => {
      const credCipher = encryptApiKey('cred-secret', 1).encrypted;

      // Switch to v2; v1 key becomes the "previous" key for decryption fallback.
      process.env.AI_ENCRYPTION_KEY = NEW_KEY;
      process.env.AI_ENCRYPTION_KEY_PREV = FIXTURE.key_hex;
      process.env.AI_ENCRYPTION_KEY_VERSION = '2';

      setTableResponse('organization_registry_credentials', 'then', {
        data: [{ id: 'cred-1', encrypted_credentials: credCipher, encryption_key_version: 1 }],
        error: null,
      });

      const result = await rotateEncryptionKeys();

      expect(result).toEqual({ rotated: 1, failed: 0 });
    });

    it('returns zero counts when the registry creds table has no stale rows', async () => {
      process.env.AI_ENCRYPTION_KEY = NEW_KEY;
      process.env.AI_ENCRYPTION_KEY_VERSION = '2';

      setTableResponse('organization_registry_credentials', 'then', { data: [], error: null });

      const result = await rotateEncryptionKeys();

      expect(result).toEqual({ rotated: 0, failed: 0 });
    });

    it('counts decryption failures per row and continues', async () => {
      process.env.AI_ENCRYPTION_KEY = NEW_KEY;
      process.env.AI_ENCRYPTION_KEY_VERSION = '2';
      // No PREV set — old ciphertexts cannot be decrypted, all fail.

      // Right format, wrong key → auth-tag mismatch in decryptApiKey.
      const garbage = 'AQIDBAUGBwgJCgsM:Dhd21MVkwCKYnc/sHI5mfhz/xw==:aJFHZa2oQqQPpdmMcH1qXg==';

      setTableResponse('organization_registry_credentials', 'then', {
        data: [{ id: 'cred-broken', encrypted_credentials: garbage, encryption_key_version: 1 }],
        error: null,
      });

      const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const result = await rotateEncryptionKeys();
      errSpy.mockRestore();

      expect(result).toEqual({ rotated: 0, failed: 1 });
    });
  });
});
