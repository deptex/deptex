// Safe counterpart to receiver-taint-vuln. Same `.toString().trim()`
// receiver chain, but the receiver is a string literal — no taint to
// propagate. The rule MUST NOT taint a temp from an inert receiver,
// otherwise every `.toString()` in the codebase would over-approximate.
declare const child_process: any;

function handler(_req: any) {
  const raw = 'static-command';
  const normalised = raw.toString().trim();
  child_process.exec(normalised);
}

handler({});
