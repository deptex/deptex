declare const res: { redirect(url: string): any };
declare function assertSafeUrl(s: string): string;

function handler(req: any) {
  const target = req.query.next;
  const safe = assertSafeUrl(target);
  res.redirect(safe);
}

handler({ query: { next: '/dashboard' } });
