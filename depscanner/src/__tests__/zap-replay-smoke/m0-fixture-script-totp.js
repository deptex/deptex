// M0 step 5/6 — Auditable copy of the TOTP-auth script body that lives
// inline in `m0-fixture-totp.yaml` at `context.authentication.parameters.scriptInline`.
//
// Pinned against ZAP @sha256:8770b23f9e8b49038f413cb2b10c58c901e5b6717be221a22b1bcab5c9771b8a
// (ZAP 2.17.0 + authhelper v0.39.0). Engine: ECMAScript : Graal.js.
// RE-VALIDATE this file when the depscanner Dockerfile bumps ZAP.
//
// Demonstrates Patch A: the vendored ~30-LOC RFC 6238 helper is string-inlined
// alongside the captured base32 secret. ZAP's authentication helper invokes
// `authenticate()` at every `loggedOutRegex` match; `__deptexGenerateTotpCode()`
// regenerates a fresh code each invocation from the script-engine clock.
//
// Empirically validated (M0 step 6): two ZAP runs across a 32s boundary
// produced two DIFFERENT codes (465916 → 224826), both accepted by the
// fixture's /totp/verify route (±1 30s window tolerance). The "stale code"
// failure mode of inlining a literal code at script-render-time is
// structurally excluded.
//
// This file is NOT loaded by ZAP — the AF YAML uses `scriptInline`. It
// exists as a readable reference for humans. M3 yaml-builder's emitted
// script body should structurally match this shape.

// ----- vendored RFC 6238 helper (mirrors _helpers/totp-rfc6238.ts) -----
// The TS surface (_helpers/totp-rfc6238.ts) is exercised by RFC 6238 §5.1
// vector tests in dast-replay-totp-rfc6238.test.ts. KEEP IN SYNC with the
// TS surface — any drift will be caught by the M3 contract test that
// generates a script body via yaml-builder and runs the test vectors
// against THIS form via a Java-side jest harness.

function __deptexBase32Decode(b32) {
  var stripped = b32.replace(/=+$/, '');
  var bits = '';
  for (var i = 0; i < stripped.length; i++) {
    var v = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(stripped.charAt(i));
    if (v < 0) throw new Error('invalid base32 char');
    var b = v.toString(2);
    while (b.length < 5) b = '0' + b;
    bits += b;
  }
  var fullBytes = Math.floor(bits.length / 8);
  // Build a JS array of UNSIGNED ints first, then convert to byte[] via
  // Java.to. The earlier Byte.parseByte path failed on values >= 128
  // (out of signed-byte range). Java.to handles the signed narrowing for
  // us when source array values are pre-narrowed to -128..127.
  var ints = new Array(fullBytes);
  for (var j = 0; j < fullBytes; j++) {
    var val = parseInt(bits.substring(j * 8, j * 8 + 8), 2);
    ints[j] = val > 127 ? val - 256 : val;
  }
  return Java.to(ints, 'byte[]');
}

function __deptexGenerateTotpCode(secret) {
  var period = 30;
  var digits = 6;
  var time = Math.floor(Date.now() / 1000);
  var counter = Math.floor(time / period);
  var ByteBuffer = Java.type('java.nio.ByteBuffer');
  var counterBuf = ByteBuffer.allocate(8).putLong(counter).array();
  var Mac = Java.type('javax.crypto.Mac');
  var SecretKeySpec = Java.type('javax.crypto.spec.SecretKeySpec');
  var mac = Mac.getInstance('HmacSHA1');
  mac.init(new SecretKeySpec(__deptexBase32Decode(secret), 'HmacSHA1'));
  var hmac = mac.doFinal(counterBuf);
  var offset = hmac[hmac.length - 1] & 0x0f;
  var code = ((hmac[offset] & 0x7f) << 24)
           | ((hmac[offset + 1] & 0xff) << 16)
           | ((hmac[offset + 2] & 0xff) << 8)
           | (hmac[offset + 3] & 0xff);
  var s = (code % Math.pow(10, digits)).toString();
  while (s.length < digits) s = '0' + s;
  return s;
}

// ----- end vendored helper -----

// Inlined HAR-derived secret (Patch A). The `__DEPTEX_TOTP_SECRET` identifier
// uses the double-underscore prefix per byok-r3-NEW-4 to avoid ZAP API
// global collisions.
var __DEPTEX_TOTP_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

function authenticate(helper, paramsValues, credentials) {
  var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
  var URI = Java.type('org.apache.commons.httpclient.URI');

  // --- Step 1: POST /totp/login (username + password) ---
  var loginUri = new URI('http://host.docker.internal:4500/totp/login', false);
  var step1 = helper.prepareMessage();
  step1.setRequestHeader(new HttpRequestHeader('POST', loginUri, 'HTTP/1.1'));
  step1.getRequestHeader().setHeader('Content-Type', 'application/x-www-form-urlencoded');
  step1.setRequestBody('username=alice&password=wonderland');
  step1.getRequestHeader().setContentLength(step1.getRequestBody().length());
  helper.sendAndReceive(step1, true);

  // Parse the pending_session out of the JSON response body.
  var body = String(step1.getResponseBody().toString());
  var match = /"pending_session"\s*:\s*"([^"]+)"/.exec(body);
  if (!match) throw new Error('totp_login_failed: body=' + body);
  var pendingSession = match[1];

  // --- Step 2: POST /totp/verify with a fresh RFC 6238 code ---
  // Fresh-per-invocation: this runs at every ZAP auth invocation.
  var freshCode = __deptexGenerateTotpCode(__DEPTEX_TOTP_SECRET);

  var verifyUri = new URI('http://host.docker.internal:4500/totp/verify', false);
  var step2 = helper.prepareMessage();
  step2.setRequestHeader(new HttpRequestHeader('POST', verifyUri, 'HTTP/1.1'));
  step2.getRequestHeader().setHeader('Content-Type', 'application/x-www-form-urlencoded');
  step2.setRequestBody('pending_session=' + pendingSession + '&code=' + freshCode);
  step2.getRequestHeader().setContentLength(step2.getRequestBody().length());
  helper.sendAndReceive(step2, true);

  return step2;
}

function getRequiredParamsNames() { return []; }
function getOptionalParamsNames() { return []; }
function getCredentialsParamsNames() { return []; }
