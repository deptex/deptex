declare const res: { send(s: string): any };

function handler(req: any) {
  const name = req.query.name;
  res.send(`<h1>Hello ${name}</h1>`);
}

handler({ query: { name: '<script>alert(1)</script>' } });
