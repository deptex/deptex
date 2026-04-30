declare const pool: { query(sql: string, params?: any[]): any };

function handler(req: any) {
  const id = req.params.id;
  // Parameterized query — user input is in params[1], not interpolated into SQL.
  pool.query('SELECT * FROM users WHERE id = ?', [id]);
}

handler({ params: { id: '1 OR 1=1' } });
