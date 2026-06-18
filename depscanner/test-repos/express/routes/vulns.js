const express = require('express');
const fs = require('fs');
const child_process = require('child_process');
const http = require('http');
const _ = require('lodash');

const router = express.Router();

// Minimal local DB stub so the SQL sink has a host with a real `.query()`
// method — no new npm dependency, keeps the SCA results clean.
const db = {
  query(sql) {
    // pretend to run `sql`; the point is the unsanitized concatenation above.
    return { sql, rows: [] };
  },
};

// Minimal local logger stub exposing a winston-shaped `.info()` so the
// log-injection sink fires without pulling in the winston package.
const winston = {
  info(message) {
    process.stdout.write(`[info] ${message}\n`);
  },
};

// REACHABLE: sql_injection — req.query.account flows into db.query() unparameterized.
router.get('/account', (req, res) => {
  const account = req.query.account;
  db.query(`SELECT * FROM accounts WHERE number = '${account}'`);
  res.json({ status: 'queried' });
});

// REACHABLE: command_injection — req.query.host flows into child_process.exec().
router.get('/ping', (req, res) => {
  const host = req.query.host;
  child_process.exec(`ping -c 1 ${host}`);
  res.json({ status: 'pinging' });
});

// REACHABLE: path_traversal — req.query.file flows into fs.readFile().
router.get('/download', (req, res) => {
  const file = req.query.file;
  fs.readFile(file, () => {});
  res.json({ status: 'reading' });
});

// REACHABLE: ssrf — req.query.url flows into http.get().
router.get('/fetch', (req, res) => {
  const url = req.query.url;
  http.get(url, () => {});
  res.json({ status: 'fetching' });
});

// REACHABLE: prototype_pollution — req.body.profile poisons the merge target.
router.post('/profile', (req, res) => {
  const userInput = req.body.profile;
  const target = {};
  _.merge(target, userInput);
  res.json({ status: 'merged' });
});

// REACHABLE: deserialization — req.body.payload flows into JSON.parse().
router.post('/import', (req, res) => {
  const payload = req.body.payload;
  const parsed = JSON.parse(payload);
  void parsed;
  res.json({ status: 'imported' });
});

// REACHABLE: redos — req.query.pattern flows into the RegExp constructor.
router.get('/search', (req, res) => {
  const pattern = req.query.pattern;
  const re = new RegExp(pattern);
  re.test('candidate string');
  res.json({ status: 'searched' });
});

// REACHABLE: log_injection — req.body.username flows unescaped into the logger.
router.post('/audit', (req, res) => {
  const username = req.body.username;
  winston.info(username);
  res.json({ status: 'logged' });
});

// REACHABLE: open_redirect — req.query.next flows into res.redirect().
router.get('/go', (req, res) => {
  const next = req.query.next;
  res.redirect(next);
});

// REACHABLE: code_injection — req.body.script flows into eval().
router.post('/eval', (req, res) => {
  const script = req.body.script;
  eval(script);
  res.json({ status: 'evaluated' });
});

// REACHABLE: command_injection — cross-function flow; the tainted host passes
// through a helper before reaching child_process.execSync (interprocedural).
function runDiagnostic(rawTarget) {
  return child_process.execSync(`traceroute ${rawTarget}`);
}

router.get('/trace', (req, res) => {
  const target = req.query.target;
  runDiagnostic(target);
  res.json({ status: 'traced' });
});

module.exports = router;
