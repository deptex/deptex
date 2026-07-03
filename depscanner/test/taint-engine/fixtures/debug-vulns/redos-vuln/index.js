// debug ReDoS — CVE-2017-16137.
//
// Vulnerable builds of the `debug` package bake a catastrophic-backtracking
// coloring/format regex into the formatter. The regex-literal detector
// (Phase 3.2) fires on the PRESENCE of that known-bad literal in workspace
// code, independent of any source -> sink taint flow. This fixture declares
// the literal so the wired detector path emits a `redos` flow.

const debug = require('debug');
const log = debug('myapp');

// The unsafe coloring-format regex literal (matches the debug.yaml
// unsafe_regex_patterns entry %[oOdisfc%]).
const COLORING = /%[oOdisfc%]/g;

function format(input) {
  return String(input).replace(COLORING, '');
}

module.exports = { log, format };
