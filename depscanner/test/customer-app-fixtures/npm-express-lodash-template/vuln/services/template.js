// Template-rendering service — calls into lodash _.template, which compiles
// the supplied string into an executable JS function. Sink for code_injection.

const _ = require('lodash');

function renderTemplate(source, data) {
  const compiled = _.template(source);
  return compiled(data || {});
}

module.exports = { renderTemplate };
