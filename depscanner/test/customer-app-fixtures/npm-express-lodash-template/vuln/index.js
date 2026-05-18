// Customer-shaped Express entry point — exposes a /render endpoint that
// accepts an attacker-controlled template string and feeds it through the
// service layer to lodash _.template (CVE-2021-23337 / CVE-2026-4800 shape).

const express = require('express');
const { renderTemplate } = require('./services/template');
const { auditRequest } = require('./services/audit');

const app = express();
app.use(express.json());

app.post('/render', (req, res) => {
  const tmpl = req.body.template;
  auditRequest(req);
  const html = renderTemplate(tmpl, { user: req.body.user });
  res.send(html);
});

module.exports = app;
