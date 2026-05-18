import * as fs from 'fs';
import * as path from 'path';

import { encryptApiKey, decryptApiKey, isEncryptionConfigured } from '../encryption';

// Single source of truth for the fixture — backend "owns" the file under
// backend/src/lib/ai/__tests__/fixtures/. The depscanner test reads the same
// bytes so a divergence between the synced encryption.ts files surfaces here.
const FIXTURE_PATH = path.resolve(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'backend',
  'src',
  'lib',
  'ai',
  '__tests__',
  'fixtures',
  'encryption-roundtrip.json'
);

const FIXTURE = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8')) as {
  key_hex: string;
  key_version: number;
  plaintext: string;
  encrypted: string;
};

describe('encryption helper (depscanner — synced copy)', () => {
  const ORIG_ENV = { ...process.env };

  beforeEach(() => {
    process.env.AI_ENCRYPTION_KEY = FIXTURE.key_hex;
    process.env.AI_ENCRYPTION_KEY_VERSION = String(FIXTURE.key_version);
    delete process.env.AI_ENCRYPTION_KEY_PREV;
  });

  afterEach(() => {
    process.env = { ...ORIG_ENV };
  });

  it('reports configured when AI_ENCRYPTION_KEY is set', () => {
    expect(isEncryptionConfigured()).toBe(true);
  });

  it('round-trips the fixture plaintext through encryptApiKey + decryptApiKey', () => {
    const { encrypted, version } = encryptApiKey(FIXTURE.plaintext);
    expect(version).toBe(FIXTURE.key_version);
    expect(decryptApiKey(encrypted, version)).toBe(FIXTURE.plaintext);
  });

  it('decrypts the checked-in known ciphertext (cross-package format invariant)', () => {
    // If the depscanner copy ever drifts (algorithm change, nonce layout,
    // auth-tag handling) this assertion fails before any worker code runs.
    expect(decryptApiKey(FIXTURE.encrypted, FIXTURE.key_version)).toBe(FIXTURE.plaintext);
  });
});
