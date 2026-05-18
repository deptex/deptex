declare const KEYUTIL: any;

function handler(req: any) {
  // CVE-2024-21484 shape — tainted ciphertext routed into RSAKey.decrypt.
  // jsrsasign's verify/decrypt family accepts crafted material that
  // bypasses the cryptographic guarantee.
  const key = KEYUTIL.getKey('-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----');
  const ciphertext = req.body.ciphertext;
  const plaintext = key.decrypt(ciphertext);
  return plaintext;
}

handler({ body: { ciphertext: 'attacker-crafted' } });
