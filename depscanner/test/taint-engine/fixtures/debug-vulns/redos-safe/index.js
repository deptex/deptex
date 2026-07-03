// debug used WITHOUT the unsafe coloring-format regex literal present.
//
// The known-bad CVE-2017-16137 regex literal does not appear anywhere in this
// file, so the regex-literal detector must stay quiet and the fixture must
// produce zero redos flows. (The substring scan counts comments too, so this
// fixture deliberately never spells the literal out.)

const debug = require('debug');
const log = debug('myapp');

function format(input) {
  return String(input);
}

module.exports = { log, format };
