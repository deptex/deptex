declare const res: { send(s: string): any };
declare const validator: { escape(s: string): string };

function handler(req: any) {
  const name = req.query.name;
  const escaped = validator.escape(name);
  res.send(`<h1>Hello ${escaped}</h1>`);
}

handler({ query: { name: '<script>alert(1)</script>' } });
