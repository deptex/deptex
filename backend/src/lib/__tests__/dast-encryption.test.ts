import crypto from 'crypto';

const KEY_A = crypto.randomBytes(32).toString('hex');
const KEY_B = crypto.randomBytes(32).toString('hex');

const ORIGINAL_ENV = { ...process.env };

function loadFresh() {
  jest.resetModules();
  return require('../dast-encryption') as typeof import('../dast-encryption');
}

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
  delete process.env.DAST_CREDENTIAL_KEY;
  delete process.env.DAST_CREDENTIAL_KEY_PREV;
  delete process.env.DAST_CREDENTIAL_KEY_VERSION;
});

describe('dast-encryption — configuration gate', () => {
  it('isDastEncryptionConfigured returns false when env unset', () => {
    delete process.env.DAST_CREDENTIAL_KEY;
    const lib = loadFresh();
    expect(lib.isDastEncryptionConfigured()).toBe(false);
  });

  it('isDastEncryptionConfigured returns true when env set', () => {
    process.env.DAST_CREDENTIAL_KEY = KEY_A;
    const lib = loadFresh();
    expect(lib.isDastEncryptionConfigured()).toBe(true);
  });

  it('encryptCredential throws when env unset', () => {
    delete process.env.DAST_CREDENTIAL_KEY;
    const lib = loadFresh();
    expect(() => lib.encryptCredential('s3cr3t-fixture')).toThrow(/DAST_CREDENTIAL_KEY/);
  });
});

describe('dast-encryption — round-trip across all 3 v2.1a strategies', () => {
  const fixtures: Record<string, string> = {
    form_password: 's3cr3t-fixture',
    jwt_token: 'eyJhbGciOiJIUzI1NiJ9.testpayload.testsig',
    cookie_payload: JSON.stringify([
      { name: 'session', value: 'fixture-cookie-value-7f3e', domain: 'example.com', path: '/' },
      { name: 'csrf', value: 'fixture-csrf-token-9a82' },
    ]),
  };

  beforeEach(() => {
    process.env.DAST_CREDENTIAL_KEY = KEY_A;
    delete process.env.DAST_CREDENTIAL_KEY_PREV;
    process.env.DAST_CREDENTIAL_KEY_VERSION = '1';
  });

  it.each(Object.entries(fixtures))(
    'encrypts and decrypts %s strategy plaintext',
    (_label, plaintext) => {
      const lib = loadFresh();
      const { encrypted, version } = lib.encryptCredential(plaintext);
      expect(encrypted).not.toContain(plaintext);
      expect(version).toBe(1);
      const decrypted = lib.decryptCredential(encrypted, version);
      expect(decrypted).toBe(plaintext);
    },
  );

  it('produces a different ciphertext on every encrypt (random nonce)', () => {
    const lib = loadFresh();
    const a = lib.encryptCredential('s3cr3t-fixture');
    const b = lib.encryptCredential('s3cr3t-fixture');
    expect(a.encrypted).not.toBe(b.encrypted);
  });

  it('rejects tampered ciphertext (auth-tag failure)', () => {
    const lib = loadFresh();
    const { encrypted, version } = lib.encryptCredential('s3cr3t-fixture');
    const parts = encrypted.split(':');
    // Flip the high bit of the first ciphertext byte.
    const ct = Buffer.from(parts[1], 'base64');
    ct[0] ^= 0x80;
    const tampered = `${parts[0]}:${ct.toString('base64')}:${parts[2]}`;
    expect(() => lib.decryptCredential(tampered, version)).toThrow();
  });
});

describe('dast-encryption — key rotation with previous-key fallback', () => {
  it('decrypts a v1-ciphertext after promoting KEY_A → previous and KEY_B → current', () => {
    // 1. Encrypt with KEY_A as current, version 1.
    process.env.DAST_CREDENTIAL_KEY = KEY_A;
    process.env.DAST_CREDENTIAL_KEY_VERSION = '1';
    delete process.env.DAST_CREDENTIAL_KEY_PREV;
    let lib = loadFresh();
    const { encrypted, version } = lib.encryptCredential('s3cr3t-fixture');
    expect(version).toBe(1);

    // 2. Rotate: KEY_B becomes current at version 2; KEY_A is now previous.
    process.env.DAST_CREDENTIAL_KEY = KEY_B;
    process.env.DAST_CREDENTIAL_KEY_PREV = KEY_A;
    process.env.DAST_CREDENTIAL_KEY_VERSION = '2';
    lib = loadFresh();

    // 3. Old ciphertext (storedVersion=1) decrypts via the previous key.
    expect(lib.decryptCredential(encrypted, 1)).toBe('s3cr3t-fixture');

    // 4. New encrypts use version 2 with KEY_B.
    const fresh = lib.encryptCredential('eyJhbGciOiJIUzI1NiJ9.testpayload.testsig');
    expect(fresh.version).toBe(2);
    expect(lib.decryptCredential(fresh.encrypted, 2)).toBe(
      'eyJhbGciOiJIUzI1NiJ9.testpayload.testsig',
    );
  });

  it('refuses to decrypt when storedVersion is current but key is wrong (no fallback)', () => {
    process.env.DAST_CREDENTIAL_KEY = KEY_A;
    process.env.DAST_CREDENTIAL_KEY_VERSION = '1';
    delete process.env.DAST_CREDENTIAL_KEY_PREV;
    let lib = loadFresh();
    const { encrypted } = lib.encryptCredential('s3cr3t-fixture');

    // Now rotate but DON'T provide previous: old ciphertext is permanently lost.
    process.env.DAST_CREDENTIAL_KEY = KEY_B;
    process.env.DAST_CREDENTIAL_KEY_VERSION = '2';
    delete process.env.DAST_CREDENTIAL_KEY_PREV;
    lib = loadFresh();

    expect(() => lib.decryptCredential(encrypted, 1)).toThrow(/Unable to decrypt/);
  });

  it('rejects malformed encrypted format', () => {
    process.env.DAST_CREDENTIAL_KEY = KEY_A;
    const lib = loadFresh();
    expect(() => lib.decryptCredential('not-a-valid-format', 1)).toThrow(/Invalid encrypted/);
  });
});

describe('dast-encryption — UTF-8 multibyte boundary regression', () => {
  // Pre-fix bug: `decipher.update(ciphertext) + decipher.final('utf8')`
  // implicitly stringified the update Buffer with default toString('utf8'),
  // then concatenated. If a multi-byte UTF-8 codepoint crossed the
  // update/final chunk boundary, each half decoded independently and yielded
  // U+FFFD replacement chars — silently corrupting credentials with non-ASCII
  // characters (passwords with é/ñ, cookies with emoji-bearing values, etc.).
  // The fix concatenates the two Buffers FIRST, then decodes once.
  beforeEach(() => {
    process.env.DAST_CREDENTIAL_KEY = KEY_A;
    delete process.env.DAST_CREDENTIAL_KEY_PREV;
    process.env.DAST_CREDENTIAL_KEY_VERSION = '1';
  });

  it('round-trips a non-ASCII password (Latin-1 supplement)', () => {
    const lib = loadFresh();
    const plaintext = 'pässwörd-français-€-naïve';
    const { encrypted, version } = lib.encryptCredential(plaintext);
    expect(lib.decryptCredential(encrypted, version)).toBe(plaintext);
  });

  it('round-trips emoji + 4-byte UTF-8 sequences', () => {
    const lib = loadFresh();
    // 4-byte UTF-8: 🔐 (U+1F510), 🦄 (U+1F984), and CJK characters.
    const plaintext = '🔐s3cret🦄-中文-кириллица-日本語';
    const { encrypted, version } = lib.encryptCredential(plaintext);
    expect(lib.decryptCredential(encrypted, version)).toBe(plaintext);
  });

  it('round-trips long inputs that force multiple cipher blocks', () => {
    const lib = loadFresh();
    // AES block size is 16 bytes; long repeated payload guarantees update()
    // returns content rather than only final(). Mix multibyte chars throughout
    // so the boundary lands on a partial codepoint with high probability.
    const plaintext = '🚨' + 'á'.repeat(500) + 'β'.repeat(500) + '🔥';
    const { encrypted, version } = lib.encryptCredential(plaintext);
    expect(lib.decryptCredential(encrypted, version)).toBe(plaintext);
  });

  it('round-trips a JSON form-credential payload with non-ASCII fields', () => {
    const lib = loadFresh();
    const plaintext = JSON.stringify({
      kind: 'form',
      login_url: 'https://example.com/login',
      username_field: 'email',
      password_field: 'password',
      username: 'jürgen@example.com',
      password: 'P@sswörd!🔑',
    });
    const { encrypted, version } = lib.encryptCredential(plaintext);
    const decrypted = lib.decryptCredential(encrypted, version);
    expect(decrypted).toBe(plaintext);
    // Round-trip survives JSON.parse without producing replacement chars.
    expect(JSON.parse(decrypted).password).toBe('P@sswörd!🔑');
  });
});
