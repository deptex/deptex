declare const semver: any;

function handler(_req: any) {
  // Hard-coded range — not tainted, no flow should be emitted.
  const result = semver.satisfies('1.2.3', '>=1.0.0');
  return result;
}

handler({ query: { range: 'ignored' } });
