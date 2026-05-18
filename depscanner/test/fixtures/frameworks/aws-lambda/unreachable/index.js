// Lambda handler that imports nothing from minimist.
// Vulnerable dep is declared in package.json but never invoked at runtime.

exports.handler = async (event) => {
  return { statusCode: 200, body: JSON.stringify({ ok: true, ts: Date.now() }) };
};
