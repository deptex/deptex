// M0 step 3/4 — Auditable copy of the FORM-auth script body that lives
// inline in `m0-fixture.yaml` at `context.authentication.parameters.scriptInline`.
//
// Pinned against ZAP @sha256:8770b23f9e8b49038f413cb2b10c58c901e5b6717be221a22b1bcab5c9771b8a
// (ZAP 2.17.0 + authhelper v0.39.0). Engine: ECMAScript : Graal.js.
// RE-VALIDATE this file when the depscanner Dockerfile bumps ZAP.
//
// This file is NOT loaded by ZAP — the AF YAML uses `scriptInline`. It exists
// as a readable reference for humans (M3 yaml-builder's generated output
// should structurally match this shape).

function authenticate(helper, paramsValues, credentials) {
  var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
  var URI = Java.type('org.apache.commons.httpclient.URI');

  var loginUrl = new URI('http://host.docker.internal:4500/login', false);
  var msg = helper.prepareMessage();
  msg.setRequestHeader(new HttpRequestHeader('POST', loginUrl, 'HTTP/1.1'));
  msg.getRequestHeader().setHeader('Content-Type', 'application/x-www-form-urlencoded');
  msg.setRequestBody('username=alice&password=wonderland');
  msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

  helper.sendAndReceive(msg, true);
  return msg;
}

function getRequiredParamsNames() { return []; }
function getOptionalParamsNames() { return []; }
function getCredentialsParamsNames() { return []; }
