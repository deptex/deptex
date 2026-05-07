declare const db: { query: (sql: string) => Promise<unknown> };

class UsersController {
  async search(query: any) {
    const name = query.name;
    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
  }
}

new UsersController().search({ name: 'foo' });
