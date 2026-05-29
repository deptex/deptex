const express = require('express');
const apiRouter = require('./routes/api');

const app = express();
const PORT = process.env.PORT || 4001;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api', apiRouter);

app.get('/', (req, res) => {
  res.send('deptex-dogfood-express — see /api/* for instrumented endpoints');
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`express dogfood fixture listening on :${PORT}`);
});
