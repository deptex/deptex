// Phase 36 (v1.1) — generator for the ZAP Graal.js script body that replays
// a HAR-derived ReplayCredentialPayload as Script-Based Authentication.
//
// The emitted string is dropped into the AF YAML at
// `context.authentication.parameters.scriptInline` (see yaml-builder.ts).
// ZAP registers + invokes it on every auth invocation (initial + on
// `logged_out_indicator` miss). Cookie-Based Session Management auto-
// harvests every Set-Cookie and threads them onto subsequent requests in
// the same context — no manual cookie wiring needed.
//
// Pinned against ZAP @sha256:8770b23f9e8b49038f413cb2b10c58c901e5b6717be221a22b1bcab5c9771b8a
// (ZAP 2.17.0 + authhelper v0.39.0). The engine identifier
// `ECMAScript : Graal.js` is the exact string returned by ZAP's
// `/JSON/script/view/listEngines/` API on that image — M0 step 0a captured
// this verbatim. Re-validate when depscanner/Dockerfile bumps ZAP.
//
// Security disciplines (Patch I-6 triple-defense against script injection
// via crafted user input):
//
//   1. ALL user-controlled string interpolations into the generated JS
//      source use JSON.stringify() to produce a quoted, escaped JS string
//      literal. NEVER use raw template substitution for user-controlled
//      values (URLs, header names + values, body content, base32 secret).
//   2. The validator at PUT time enforces:
//        - TOTP_BASE32_RE on totp_secret (strict A-Z + 2-7, optional `=`
//          padding only — lowercase / whitespace / hyphens / non-alphabet
//          all reject)
//        - JS_LINE_TERMINATOR_RE rejects U+2028 / U+2029 in every user-
//          supplied string field (pre-ES2019 string-literal break-out CVE
//          class; defense-in-depth even though Graal.js is ES2020+)
//   3. M3 step 12's dast-replay-contracts.test.ts runs the emitted source
//      through `new vm.Script(source)` to confirm V8 parses it cleanly.
//
// Patch A (Decision 18): when both `totp_step` AND `totp_secret` are set,
// the vendored ~30-LOC RFC 6238 helper is string-inlined AT THE TOP of the
// generated script, alongside the inlined base32 secret bound to the
// `__DEPTEX_TOTP_SECRET` identifier (the double-underscore prefix avoids
// ZAP API global collisions per byok-r3-NEW-4). At every ZAP auth
// invocation, the helper regenerates a fresh code and substitutes it into
// the TOTP step's request body — eliminating the stale-code failure mode
// of inlining a literal code at script-render-time.

import type { ReplayCredentialPayload } from './auth-config';

/**
 * The exact string ZAP's `/JSON/script/view/listEngines/` returns for its
 * built-in ECMAScript engine on the pinned image. M0 step 0a captured this
 * verbatim. yaml-builder copies this into the AF context's
 * `authentication.parameters.scriptEngine`.
 *
 * If ZAP drops Graal.js for a new engine name, this is the ONE place that
 * needs updating + the M0 fixture YAML headers need refreshing. The M0
 * smoke files include a header comment explicitly calling out the
 * re-validation trigger.
 */
export const ZAP_SCRIPT_ENGINE = 'ECMAScript : Graal.js' as const;

/**
 * Identifier for the inlined base32 TOTP secret. Double-underscore prefix
 * avoids ZAP API global / community-script identifier collisions
 * (byok-r3-NEW-4).
 */
const TOTP_SECRET_IDENT = '__DEPTEX_TOTP_SECRET';

/**
 * The RFC 6238 helper, written as a Graal.js-compatible JS source string.
 * Mirrors depscanner/src/dast/_helpers/totp-rfc6238.ts (the TS version
 * tested against §5.1 reference vectors in
 * dast-replay-totp-rfc6238.test.ts). KEEP IN SYNC: a structural diff test
 * in M3 step 12 catches drift.
 *
 * Why a separate Graal.js mirror rather than transpiling the TS surface:
 * the TS source uses `crypto.createHmac` (Node), `Buffer`, and arrow-
 * function generics that Graal's V8-compatible ES2020+ engine accepts but
 * is not byte-identical. Hand-mirroring keeps the source readable + lets
 * us pick Java HMAC types (Mac.getInstance) explicitly so the script is
 * insensitive to Graal's host-access mode.
 */
const RFC6238_HELPER_SOURCE = `
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
`.trim();

/**
 * Emit a ZAP Script-Based Authentication body that replays the captured
 * HAR-derived requests in order. Pure function; no I/O. The returned
 * string MUST round-trip through `new vm.Script(...)` parse without throw.
 *
 * Shape of the emitted source:
 *   1. RFC 6238 helper (inlined ONLY when payload.totp_step is set —
 *      otherwise omitted to keep the script body lean).
 *   2. `var __DEPTEX_TOTP_SECRET = <JSON.stringify-quoted base32>;`
 *      (also omitted when no totp_step).
 *   3. `function authenticate(helper, paramsValues, credentials) { ... }`
 *      that iterates `requests[]` building HttpMessage objects and
 *      calling `helper.sendAndReceive(msg, true)`. The TOTP step gets
 *      its body field substituted with a fresh code generated at call
 *      time.
 *   4. `getRequiredParamsNames` / `getOptionalParamsNames` /
 *      `getCredentialsParamsNames` boilerplate (all return []).
 */
export function generateReplayAuthScript(payload: ReplayCredentialPayload): string {
  const hasTotp =
    payload.totp_step !== undefined && typeof payload.totp_secret === 'string';

  // --- Optional preamble: RFC 6238 helper + inlined secret -----------------
  const preamble: string[] = [];
  if (hasTotp) {
    preamble.push(RFC6238_HELPER_SOURCE);
    preamble.push('');
    // JSON.stringify produces a properly-quoted JS string literal — for a
    // canonical base32 secret (A-Z + 2-7 + `=`) the output is just the
    // input wrapped in double quotes. The validator at PUT time enforced
    // strict alphabet + length, so no escape sequences ever land here.
    preamble.push(`var ${TOTP_SECRET_IDENT} = ${JSON.stringify(payload.totp_secret)};`);
  }

  // --- The authenticate() function body ------------------------------------
  //
  // For each captured request we emit a code block that:
  //   - Builds the URI via `new URI(<jsonStringifiedUrl>, false)`.
  //   - Allocates an HttpRequestHeader for the method + URI.
  //   - Sets every preserved header via setHeader().
  //   - Sets the body (with the TOTP step's body-field overwritten by a
  //     fresh code if applicable).
  //   - Calls helper.sendAndReceive(msg, true).
  //
  // The very last request's `msg` is returned from authenticate() per the
  // Script-Based Auth contract.
  const stepBlocks: string[] = payload.requests.map((req, i) => {
    const isTotpStep =
      hasTotp && payload.totp_step !== undefined && payload.totp_step.entry_index === i;

    const urlJs = JSON.stringify(req.url);
    const methodJs = JSON.stringify(req.method);

    // Headers — emit setHeader() calls for every preserved header. JSON-
    // stringify both name + value so a crafted header can't break the
    // string-literal context.
    const headerCalls = req.headers
      .map(
        (h) =>
          `  msg${i}.getRequestHeader().setHeader(${JSON.stringify(h.name)}, ${JSON.stringify(h.value)});`,
      )
      .join('\n');

    // Body — three branches:
    //   (a) totp step + body_kind=form: substitute the TOTP body field's
    //       value with the fresh code at call time. Emit JS that mutates
    //       the body string in place using a regex bound to the field
    //       name.
    //   (b) totp step + body_kind=json: parse, mutate, stringify at call
    //       time so JSON validity survives.
    //   (c) non-TOTP step OR no body: emit the literal body (or skip).
    let bodyEmit = '';
    if (req.body !== undefined) {
      if (isTotpStep && payload.totp_step?.body_kind === 'form') {
        const fieldRe = JSON.stringify(payload.totp_step.body_field);
        bodyEmit = [
          `  var _b${i} = ${JSON.stringify(req.body)};`,
          `  var _fresh${i} = __deptexGenerateTotpCode(${TOTP_SECRET_IDENT});`,
          // Form bodies: replace `<field>=<value>` either at start or after
          // `&`. Anchor the regex with a capture so we can keep the prefix.
          `  _b${i} = _b${i}.replace(new RegExp('(^|&)' + ${fieldRe} + '=[^&]*'), '$1' + ${fieldRe} + '=' + _fresh${i});`,
          `  msg${i}.setRequestBody(_b${i});`,
        ].join('\n');
      } else if (isTotpStep && payload.totp_step?.body_kind === 'json') {
        const fieldRe = JSON.stringify(payload.totp_step.body_field);
        bodyEmit = [
          `  var _bobj${i} = JSON.parse(${JSON.stringify(req.body)});`,
          `  _bobj${i}[${fieldRe}] = __deptexGenerateTotpCode(${TOTP_SECRET_IDENT});`,
          `  msg${i}.setRequestBody(JSON.stringify(_bobj${i}));`,
        ].join('\n');
      } else {
        bodyEmit = `  msg${i}.setRequestBody(${JSON.stringify(req.body)});`;
      }
      bodyEmit += `\n  msg${i}.getRequestHeader().setContentLength(msg${i}.getRequestBody().length());`;
    }

    return [
      `  // --- captured request ${i} ---`,
      `  var uri${i} = new URI(${urlJs}, false);`,
      `  var msg${i} = helper.prepareMessage();`,
      `  msg${i}.setRequestHeader(new HttpRequestHeader(${methodJs}, uri${i}, 'HTTP/1.1'));`,
      headerCalls,
      bodyEmit,
      `  helper.sendAndReceive(msg${i}, true);`,
    ]
      .filter((s) => s.length > 0)
      .join('\n');
  });

  // The final returned message is the last sent one — gives ZAP something to
  // hand back to its caller for header / status inspection.
  const lastIdx = payload.requests.length - 1;
  const trailer = lastIdx >= 0 ? `  return msg${lastIdx};` : '  return null;';

  const authenticateFn = [
    'function authenticate(helper, paramsValues, credentials) {',
    "  var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');",
    "  var URI = Java.type('org.apache.commons.httpclient.URI');",
    '',
    ...stepBlocks,
    '',
    trailer,
    '}',
  ].join('\n');

  const boilerplate = [
    'function getRequiredParamsNames() { return []; }',
    'function getOptionalParamsNames() { return []; }',
    'function getCredentialsParamsNames() { return []; }',
  ].join('\n');

  return [
    '// Generated by depscanner/src/dast/replay-zap-auth.ts',
    '// SECURITY: this string contains plaintext totp_secret + session cookies',
    '//   until V8 GC. Worker process is killed by Fly idle timeout (<5min);',
    '//   accept window. The pre-write Buffer in yaml-builder is zeroed in a',
    '//   try-finally for the artifacts that ARE zeroable.',
    '',
    ...preamble,
    '',
    authenticateFn,
    '',
    boilerplate,
    '',
  ]
    .filter((s) => s !== undefined)
    .join('\n');
}
