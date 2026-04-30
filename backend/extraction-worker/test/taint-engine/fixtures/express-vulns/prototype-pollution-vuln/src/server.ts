declare const _: { merge(target: any, source: any): any };

function handler(req: any) {
  const target = {};
  const userInput = req.body.config;
  _.merge(target, userInput);
}

handler({ body: { config: { __proto__: { polluted: true } } } });
