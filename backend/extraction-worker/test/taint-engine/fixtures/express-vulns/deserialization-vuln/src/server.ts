declare const child_process: any;

function handler(req: any) {
  const payload = req.body.payload;
  const obj = JSON.parse(payload);
  void obj;
}

handler({ body: { payload: '{"a":1}' } });
