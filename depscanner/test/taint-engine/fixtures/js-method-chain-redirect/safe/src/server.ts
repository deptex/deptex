// Safe: same method-chain shape, but the location target is a hard-coded
// constant — sink fires on a literal, not on tainted input.
declare const res: { location(url: string): any; end(): void };

function handler(_req: any) {
  res.location('/login').end();
}

handler({ query: { next: 'http://evil.example' } });
