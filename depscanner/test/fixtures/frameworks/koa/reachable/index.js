const Koa = require('koa');
const Router = require('@koa/router');
const request = require('request');

const app = new Koa();
const router = new Router();

// CVE-2017-16026 — `request` follows attacker-controlled redirects (SSRF).
router.get('/fetch', async (ctx) => {
  // Sink: request() with user-controlled URL.
  return new Promise((resolve) => {
    request(ctx.query.url, (_err, _res, body) => {
      ctx.body = body;
      resolve();
    });
  });
});

app.use(router.routes());
module.exports = app;
