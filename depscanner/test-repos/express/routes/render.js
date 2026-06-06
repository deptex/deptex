const express = require('express');
const _ = require('lodash');

const router = express.Router();

// Cross-function reachable taint flow: the request input flows through a helper
// before it reaches the lodash _.template sink (CVE-2021-23337). Unlike the
// single-handler flows in api.js, this exercises the taint engine's
// INTERPROCEDURAL propagation — the resulting flow has real intermediate hops
// (source -> helper call -> sink) so the data-flow stepper has more than just a
// source/sink pair to walk.
function renderLayout(rawLayout) {
  // No sanitization — the tainted value passes straight through this helper.
  const compiled = _.template(rawLayout);
  return compiled({});
}

router.get('/preview', (req, res) => {
  const layout = req.query.layout;
  res.send(renderLayout(layout));
});

module.exports = router;
