function handler(req: any) {
  const userPattern = req.query.pattern;
  const re = new RegExp(userPattern);
  re.test('victim');
}

handler({ query: { pattern: '(a+)+$' } });
