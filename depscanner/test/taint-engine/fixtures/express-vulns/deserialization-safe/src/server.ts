declare function validateSchema(s: string): string;
declare function unserialize(s: string): any;

function handler(req: any) {
  const payload = req.body.payload;
  // Schema-validated before the deserialization sink → sanitized, no finding.
  const verified = validateSchema(payload);
  const obj = unserialize(verified);
  void obj;
}

handler({ body: { payload: '{"a":1}' } });
