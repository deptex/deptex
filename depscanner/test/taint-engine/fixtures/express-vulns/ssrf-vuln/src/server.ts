declare const fetch: (url: string) => Promise<any>;

async function handler(req: any) {
  const target = req.query.url;
  await fetch(target);
}

handler({ query: { url: 'http://internal.metadata/' } });
