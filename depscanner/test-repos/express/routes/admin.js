const express = require('express');
const _ = require('lodash');

const router = express.Router();

// Local auth guard — a name-pattern-recognized auth middleware applied to the
// whole router via `router.use`. Every route registered after this line is
// authenticated, so the taint flows sourced inside those handlers must score as
// AUTH_INTERNAL (entry-point auth classification), NOT PUBLIC_UNAUTH.
function requireAuth(req, res, next) {
  if (!req.headers.authorization) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}
router.use(requireAuth);

// Authenticated taint flow: lodash _.template with an attacker-controlled
// source (CVE-2021-23337) — the SAME modeled sink as the public /api/render
// route, but reachable ONLY behind requireAuth. The engine must therefore stamp
// this flow `framework-route:auth_internal` while /api/render stays
// `framework-route:public_unauth`. This is the executable proof of the
// entry-point auth demotion end-to-end.
router.get('/admin/render', (req, res) => {
  const tpl = req.query.tpl;
  const compiled = _.template(tpl);
  res.send(compiled({}));
});

module.exports = router;
