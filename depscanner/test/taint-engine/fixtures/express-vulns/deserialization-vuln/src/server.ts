declare function unserialize(s: string): any;

function handler(req: any) {
  const payload = req.body.payload;
  // node-serialize `unserialize` — a real deserialization-RCE sink (it will run
  // an IIFE embedded in the payload). JSON.parse is intentionally NOT a sink:
  // it cannot execute code, so it was dropped from the deserialization class.
  const obj = unserialize(payload);
  void obj;
}

handler({ body: { payload: '{"a":1}' } });
