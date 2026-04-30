declare const db: { query: (sql: string, params?: unknown[]) => Promise<unknown> };

async function handler(request: any, reply: any) {
  const name = request.query.name;
  const rows = await db.query('SELECT * FROM users WHERE name = ?', [name]);
  reply.send(rows);
}

handler({ query: { name: 'foo' } }, { send: () => undefined });
