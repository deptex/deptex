declare const pool: { query(sql: string, params?: any[]): any };

function handler(req: any) {
  const id = req.params.id;
  pool.query(`SELECT * FROM users WHERE id = ${id}`);
}

handler({ params: { id: '1 OR 1=1' } });
