// Safe: computed-key write with a hard-coded key — `obj` never receives
// taint, and the downstream template call sees a clean object.
declare const _: { template(s: any): (data: any) => string };

function handler(_req: any) {
  const obj: any = {};
  obj['hardcoded'] = 'y';
  _.template(obj);
}

handler({ query: { x: 'k' } });
