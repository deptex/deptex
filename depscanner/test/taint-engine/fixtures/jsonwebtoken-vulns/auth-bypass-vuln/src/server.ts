declare const jwt: any;
declare const SECRET: string;

function handler(req: any) {
  // CVE-2022-23539 shape — jwt.verify without an explicit algorithms
  // allowlist accepts the algorithm declared in the JWT header itself,
  // permitting `alg: none` downgrades and HMAC-with-RSA-pubkey attacks.
  const token = req.headers.authorization;
  const decoded = jwt.verify(token, SECRET);
  return decoded;
}

handler({ headers: { authorization: 'attacker-crafted-jwt' } });
