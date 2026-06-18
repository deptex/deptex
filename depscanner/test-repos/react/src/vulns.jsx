// Client-side (DOM-based) vulnerabilities for the React SPA dogfood fixture.
// The trust boundary here is the browser, not a server request: each handler
// reads an attacker-controllable DOM input (the URL, referrer, window.name,
// Web Storage, postMessage) and passes it straight into a dangerous DOM/JS
// sink. These are the canonical DOM-XSS / client-side code-injection shapes
// the taint engine confirms via the browser-dom spec. Each is a clean single
// source -> sink flow; nothing reflects tainted data twice.
import React from 'react';
import axios from 'axios';
import _ from 'lodash';

// REACHABLE: xss — URL fragment rendered as raw HTML.
export function HashBanner() {
  const markup = window.location.hash;
  return <div dangerouslySetInnerHTML={{ __html: markup }} />;
}

// REACHABLE: code_injection — lodash template compiled from the query string.
export function compileGreeting() {
  const tpl = window.location.search;
  return _.template(tpl);
}

// REACHABLE: deserialization (code execution) — window.name eval'd.
export function runFromName() {
  const code = window.name;
  eval(code);
}

// REACHABLE: deserialization (code execution) — Function() built from storage.
export function buildHandler() {
  const body = localStorage.getItem('handler');
  const fn = new Function(body);
  fn();
}

// REACHABLE: ssrf — fetch to a URL taken straight from the query string.
export function loadResource() {
  const url = window.location.search;
  return fetch(url);
}

// REACHABLE: ssrf — axios GET to the referrer URL.
export function pingReferrer() {
  const target = document.referrer;
  return axios.get(target);
}

// REACHABLE: redos — RegExp compiled from the URL fragment.
export function buildMatcher() {
  const pattern = window.location.hash;
  return new RegExp(pattern);
}

// REACHABLE: prototype_pollution — postMessage payload merged into an object.
export function onMessage(event) {
  const incoming = event.data;
  const state = {};
  Object.assign(state, incoming);
  return state;
}

// REACHABLE: xss — document.write of the query string.
export function writeQuery() {
  const q = window.location.search;
  document.write(q);
}

// REACHABLE: open_redirect — navigate to a URL from window.name.
export function gotoName() {
  const dest = window.name;
  location.assign(dest);
}

// REACHABLE: open_redirect — open a window at the referrer URL.
export function openReferrer() {
  const dest = document.referrer;
  window.open(dest);
}
