declare const db: { query: (sql: string) => Promise<unknown> };

async function GET(request: any) {
  const name = request.nextUrl.searchParams.get('name');
  return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}

GET({ nextUrl: { searchParams: { get: () => 'foo' } } });
