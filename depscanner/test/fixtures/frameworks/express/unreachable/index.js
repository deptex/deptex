const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

// Lodash is imported but only `_.chunk` is used — never `_.template`.
// No CVE-2021-23337 sink reachable from any HTTP entry point.
app.get('/', (_req, res) => {
  res.json(_.chunk([1, 2, 3, 4], 2));
});

module.exports = app;
