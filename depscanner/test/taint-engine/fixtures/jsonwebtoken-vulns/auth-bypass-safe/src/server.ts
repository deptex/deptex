declare const jwt: any;
declare const SECRET: string;

function handler(req: any) {
  // Hardened — explicit algorithms allowlist pins the verifier to HS256
  // and rejects attacker-supplied `alg` values from the header.
  const token = req.headers.authorization;
  const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'] });
  return decoded;
}

handler({ headers: { authorization: 'attacker-crafted-jwt' } });
