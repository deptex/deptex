declare const KEYUTIL: any;

function handler(_req: any) {
  // Hard-coded ciphertext — not tainted, no flow should be emitted even
  // though it reaches the modelled jsrsasign `decryptOAEP` sink. Proves the
  // sink fires on taint, not on mere presence of the call.
  const key = KEYUTIL.getKey('-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----');
  const ciphertext = 'safe_constant_ciphertext';
  const plaintext = key.decryptOAEP(ciphertext);
  return plaintext;
}

handler({ body: { ciphertext: 'ignored' } });
