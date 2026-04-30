declare const _: { merge(target: any, source: any): any };
declare function stripProtoKeys(obj: any): any;

function handler(req: any) {
  const target = {};
  const userInput = req.body.config;
  const safe = stripProtoKeys(userInput);
  _.merge(target, safe);
}

handler({ body: { config: {} } });
