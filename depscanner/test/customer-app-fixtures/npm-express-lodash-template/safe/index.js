// Patched Express entry point — passes a hard-coded template literal to the
// render service and only interpolates the user-supplied value as data (which
// goes through HTML escape inside the service). No taint flows into _.template.

const express = require('express');
const { renderUserGreeting } = require('./services/template');
const { auditRequest } = require('./services/audit');

const app = express();
app.use(express.json());

app.post('/render', (req, res) => {
  const username = req.body.user;
  auditRequest(req);
  const html = renderUserGreeting(username);
  res.send(html);
});

module.exports = app;
