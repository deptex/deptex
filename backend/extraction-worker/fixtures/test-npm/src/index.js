const _ = require('lodash');
const minimist = require('minimist');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const fetch = require('node-fetch');
const readlineSync = require('readline-sync');

// lodash CVE-2021-23337: command injection via _.template
const userInput = process.env.USER_TEMPLATE || '<%= name %>';
const compiled = _.template(userInput);
console.log(compiled({ name: 'test' }));

// minimist CVE-2021-44906: prototype pollution
const args = minimist(process.argv.slice(2));
console.log(args);

// jsonwebtoken CVE-2022-23529: insecure key handling
const token = jwt.sign({ data: 'test' }, 'secret-key');
const decoded = jwt.verify(token, 'secret-key');
console.log(decoded);

// axios CVE-2021-3749: ReDoS
async function makeRequest() {
  const url = process.env.API_URL || 'https://httpbin.org/get';
  const response = await axios.get(url);
  return response.data;
}

// node-fetch CVE-2022-0235: header leak on redirect
async function fetchData() {
  const res = await fetch('https://example.com', {
    headers: { Authorization: 'Bearer test-token' },
  });
  return res.text();
}

// readline-sync: GPL-3.0 license (policy blocking test)
const name = readlineSync.question('Your name: ');
console.log('Hello', name);

makeRequest();
fetchData();
