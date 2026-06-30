declare function require(id: string): any;

// Safe: the query string is a hard-coded constant, so nothing attacker-
// controlled reaches loader-utils `parseQuery`. Proves the sink fires on
// taint, not on the mere presence of the call.
function handler(_req: any) {
  const loaderUtils = require('loader-utils');
  const queryString = '?width=100&height=200';
  const options = loaderUtils.parseQuery(queryString);
  return options;
}

handler({ body: { query: 'ignored' } });
