const minimist = require('minimist');

// CVE-2021-44906 — minimist <= 1.2.5 prototype pollution via crafted argv.
// AWS Lambda handler reads attacker-controlled event payload and parses it.
exports.handler = async (event) => {
  const args = (event.body || '').split(' ');
  // Sink: minimist parses user-controlled tokens into an object.
  const parsed = minimist(args);
  return { statusCode: 200, body: JSON.stringify(parsed) };
};
