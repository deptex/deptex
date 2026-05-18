declare const db: { query: (sql: string) => Promise<unknown> };

async function handler(c: any) {
  const name = c.req.query('name');
  const rows = await db.query(`SELECT * FROM users WHERE name = '${name}'`);
  return c.json(rows);
}

handler({ req: { query: () => 'foo' }, json: (x: unknown) => x });
