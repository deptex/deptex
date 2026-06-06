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
  // The concatenated query is executed against the in-memory SQLite seeded at
  // the bottom of this file, so the injection is genuinely exploitable at
  // runtime (error-based + boolean-based) — what a DAST scanner (ZAP/Nuclei)
  // needs to flag dynamically, beyond the static Semgrep signature above.
  try {
    const result = sqlDb ? sqlDb.exec(query) : [];
    res.json({ query, rows: result[0] ? result[0].values : [] });
  } catch (err) {
    // Reflecting the raw SQLite error back to the client is the error-based
    // SQL-injection signal ZAP's active scanner keys on.
    res.status(500).json({ query, error: String((err && err.message) || err) });
  }
});

// Plain healthy endpoint so DAST has something benign to crawl too.
router.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// In-memory SQLite, seeded once at module load. Declared AFTER the routes on
// purpose: the vulnerable sink lines above keep their byte-stable positions
// (the lodash source at line 9, the SQL concatenation at line 19 — both pinned
// by the dogfood expected.yaml + snapshot suite), and the /users handler closes
// over `sqlDb`, reading it lazily per request. sql.js is a pure-WASM SQLite
// build, so it installs with no native toolchain on the node:14 fixture image.
const initSqlJs = require('sql.js');
let sqlDb = null;
initSqlJs()
  .then((SQL) => {
    sqlDb = new SQL.Database();
    sqlDb.run('CREATE TABLE users (id INTEGER, name TEXT);');
    sqlDb.run("INSERT INTO users (id, name) VALUES (1, 'alice'), (2, 'bob');");
  })
  .catch(() => {
    /* fixture boot is best-effort; /users still reflects the SQL error path */
  });

module.exports = router;
