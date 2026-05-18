declare const _: { template(s: string, opts?: any): (data: any) => string };

function handler(req: any) {
  const userTpl = req.query.tpl;
  const compiled = _.template(userTpl);
  return compiled({});
}

handler({ query: { tpl: '<%= name %>' } });
