declare function require(id: string): any;

// Safe: only a hard-coded constant object is serialized, so no attacker-
// controlled data reaches serialize-javascript. No XSS flow should be emitted.
function render(_req: any) {
  const serialize = require('serialize-javascript');
  const constData = { theme: 'dark', locale: 'en' };
  const payload = serialize(constData);
  return `<script>window.__STATE__ = ${payload}</script>`;
}

render({ body: { data: 'ignored' } });
