declare const res: { redirect(url: string): any };

function handler(req: any) {
  const target = req.query.next;
  res.redirect(target);
}

handler({ query: { next: 'http://evil.com' } });
