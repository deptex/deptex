declare function require(id: string): any;

// CVE-2022-37601 — webpack loader-utils `parseQuery` did not sanitize keys,
// so an attacker-controlled `?__proto__[polluted]=true` query string pollutes
// Object.prototype. The tainted query string flows into the arg-0 sink.
function handler(req: any) {
  const loaderUtils = require('loader-utils');
  const queryString = req.body.query;
  const options = loaderUtils.parseQuery(queryString);
  return options;
}

handler({ body: { query: '?__proto__[polluted]=true' } });
