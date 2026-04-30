declare const child_process: any;
declare function validateSchema(s: string): string;

function handler(req: any) {
  const payload = req.body.payload;
  const verified = validateSchema(payload);
  const obj = JSON.parse(verified);
  void obj;
}

handler({ body: { payload: '{"a":1}' } });
