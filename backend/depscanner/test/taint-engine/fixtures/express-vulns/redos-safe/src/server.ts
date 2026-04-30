declare function escapeRegExp(s: string): string;

function handler(req: any) {
  const userPattern = req.query.pattern;
  const escaped = escapeRegExp(userPattern);
  const re = new RegExp(escaped);
  re.test('victim');
}

handler({ query: { pattern: '(a+)+$' } });
