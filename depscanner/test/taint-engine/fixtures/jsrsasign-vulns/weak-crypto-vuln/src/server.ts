declare const KEYUTIL: any;

function handler(req: any) {
  // CVE-2024-21484 shape — tainted ciphertext routed into jsrsasign's
  // RSAKey OAEP decrypt. We model the jsrsasign-SPECIFIC `decryptOAEP`
  // method (not a bare `*.decrypt(*)` wildcard, which matched every
  // `.decrypt` callee in any library and was dropped as a false-positive
  // magnet). Crafted ciphertext through this surface compromises the
  // cryptographic guarantee.
  const key = KEYUTIL.getKey('-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----');
  const ciphertext = req.body.ciphertext;
  const plaintext = key.decryptOAEP(ciphertext);
  return plaintext;
}

handler({ body: { ciphertext: 'attacker-crafted' } });
