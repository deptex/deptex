// Vuln: method-chained sink. `res.location(q).end()` should fire the
// `res.location(*)` open_redirect sink — without the IR lowerer pre-walking
// the inner call of a member chain, the inner sink-position is invisible.
declare const res: { location(url: string): any; end(): void };

function handler(req: any) {
  const q = req.query.next;
  res.location(q).end();
}

handler({ query: { next: 'http://evil.example' } });
