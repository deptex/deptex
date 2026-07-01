declare const res: {
  send(s: string): any;
  write(s: string): any;
  setHeader(k: string, v: string): any;
  writeHead(code: number, headers: Record<string, string>): any;
};
declare const validator: { escape(s: string): string };

// Safe #1 — value HTML-escaped before res.send (validator.escape sanitizer).
function handler(req: any) {
  const name = req.query.name;
  const escaped = validator.escape(name);
  res.send(`<h1>Hello ${escaped}</h1>`);
}

// Safe #2 — Server-Sent Events stream: Content-Type is text/event-stream, so
// the reflected value is parsed as a data frame, never rendered as HTML markup.
function sse(req: any) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream' });
  res.write(req.query.msg);
}

// Safe #3 — file download: explicit non-HTML Content-Type + attachment
// disposition means the browser downloads a file rather than rendering a page.
function download(req: any) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="sbom.json"');
  res.send(req.query.body);
}

handler({ query: { name: '<script>alert(1)</script>' } });
sse({ query: { msg: '<script>alert(1)</script>' } });
download({ query: { body: '<script>alert(1)</script>' } });
