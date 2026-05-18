const Fastify = require('fastify');
const _ = require('lodash');

const app = Fastify();

// lodash imported but only `_.uniq` is called. CVE-2019-10744 sinks
// (defaultsDeep, merge, mergeWith, set, setWith) are never invoked.
app.get('/uniq', async (req, _reply) => {
  return _.uniq([1, 1, 2, 3, 3]);
});

module.exports = app;
