const Koa = require('koa');
const Router = require('@koa/router');
// `request` is declared in package.json but never imported here.
// (Showing module-presence-without-call-site reachability state.)

const app = new Koa();
const router = new Router();

router.get('/health', (ctx) => {
  ctx.body = { ok: true };
});

app.use(router.routes());
module.exports = app;
