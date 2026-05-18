declare const KEYUTIL: any;

function handler(_req: any) {
  // Hard-coded ciphertext — not tainted, no flow should be emitted.
  const key = KEYUTIL.getKey('-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----');
  const ciphertext = 'safe_constant_ciphertext';
  const plaintext = key.decrypt(ciphertext);
  return plaintext;
}

handler({ body: { ciphertext: 'ignored' } });
