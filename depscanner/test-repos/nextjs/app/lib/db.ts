// Tiny in-memory DB stub so the SQL-injection route has a `.query()` sink
// to flow into without pulling a real driver (and its CVEs) into the fixture.
export const db = {
  query(sql: string): unknown[] {
    // A real driver would execute `sql`; here we just echo it back.
    void sql;
    return [];
  },
};
