declare const _: { template(s: string, opts?: any): (data: any) => string };

function handler(req: any) {
  // Hard-coded template — not tainted, no flow should be emitted.
  const fixedTpl = 'hello <%= name %>';
  const compiled = _.template(fixedTpl);
  return compiled({ name: req.query.name });
}

handler({ query: { name: 'world' } });
