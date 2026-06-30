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

// T2 — arg-index tightening proof. The jsrsasign sinks pin to arg 0 (the
// signature / ciphertext). Here the FIRST argument is a constant and a tainted
// value rides only as a SECONDARY argument (a label). Under the old
// `argument_indices: []` ("any tainted arg fires") this produced a weak_crypto
// false positive; under `[0]` it must NOT fire.
function handlerSecondaryArg(req: any) {
  const key = KEYUTIL.getKey('-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----');
  const label = req.body.label;
  const plaintext = key.decryptOAEP('constant_ciphertext_hex', label);
  return plaintext;
}

handler({ body: { ciphertext: 'ignored' } });
handlerSecondaryArg({ body: { label: 'attacker-controlled' } });
