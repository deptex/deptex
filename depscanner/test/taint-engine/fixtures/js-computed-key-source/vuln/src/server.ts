// Vuln: computed-key assignment is the AI-fixture shape for CVE-2026-4800
// (lodash _.template injection). `obj[req.query.x] = ...` should taint `obj`
// from the key expression, so the downstream `_.template(obj)` sink fires.
declare const _: { template(s: any): (data: any) => string };

function handler(req: any) {
  const obj: any = {};
  obj[req.query.x] = 'y';
  _.template(obj);
}

handler({ query: { x: 'k' } });
