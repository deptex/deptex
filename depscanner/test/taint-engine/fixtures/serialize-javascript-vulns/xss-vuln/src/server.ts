declare function require(id: string): any;

// CVE-2024-11831 — serialize-javascript under-escapes `</script>` sequences,
// so attacker-controlled data serialized into an inline <script> can break
// out of the tag. The tainted body flows into the arg-0 sink.
function render(req: any) {
  const serialize = require('serialize-javascript');
  const userData = req.body.data;
  const payload = serialize(userData);
  return `<script>window.__STATE__ = ${payload}</script>`;
}

render({ body: { data: '</script><script>alert(1)</script>' } });
