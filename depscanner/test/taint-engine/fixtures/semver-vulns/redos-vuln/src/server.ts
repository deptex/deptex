declare const semver: any;

function handler(req: any) {
  // CVE-2022-25883 shape — tainted range string into the semver range parser.
  const range = req.query.range;
  const result = semver.satisfies('1.2.3', range);
  return result;
}

handler({ query: { range: '<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<' } });
