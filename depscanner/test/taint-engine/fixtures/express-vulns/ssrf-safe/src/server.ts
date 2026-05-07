declare const fetch: (url: string) => Promise<any>;
declare function assertSafeUrl(s: string): string;

async function handler(req: any) {
  const target = req.query.url;
  const safe = assertSafeUrl(target);
  await fetch(safe);
}

handler({ query: { url: 'https://api.example.com/users' } });
