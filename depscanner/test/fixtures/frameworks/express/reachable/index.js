const express = require('express');
const { renderTemplate } = require('./src/render');

const app = express();
app.use(express.json());

app.post('/', (req, res) => {
  // Sink: lodash.template invoked with user-controlled input.
  // CVE-2021-23337 — template injection in lodash <= 4.17.20.
  res.send(renderTemplate(req.body.template));
});

module.exports = app;
