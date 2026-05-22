const express = require('express');
const _ = require('lodash');

const router = express.Router();

// Reachable taint flow: lodash _.template with attacker-controlled source.
// CVE-2021-23337 — command injection via _.template options.
router.get('/render', (req, res) => {
  const userTpl = req.query.tpl;
  const compiled = _.template(userTpl);
  res.send(compiled({}));
});

// Reachable Semgrep SAST signature: SQL string concatenation.
// This deliberately does NOT use a parameterized query so semgrep's
// javascript.express.security.injection.tainted-sql-string rule fires.
router.get('/users', (req, res) => {
  const id = req.query.id;
  const query = "SELECT * FROM users WHERE id = '" + id + "'";
  // No real DB driver wired — we just expose the sink shape to Semgrep.
  res.json({ query });
});

// Plain healthy endpoint so DAST has something benign to crawl too.
router.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

module.exports = router;
