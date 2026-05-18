const Fastify = require('fastify');
const _ = require('lodash');

const app = Fastify();

// CVE-2019-10744 — lodash <= 4.17.11 defaultsDeep prototype pollution.
app.post('/merge', async (req, _reply) => {
  const target = {};
  // Sink: defaultsDeep on user-controlled body. Pollutes Object.prototype.
  return _.defaultsDeep(target, req.body);
});

module.exports = app;
