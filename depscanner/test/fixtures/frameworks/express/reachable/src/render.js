const _ = require('lodash');

function renderTemplate(tmpl) {
  // Sink line — _.template compiles user input into a function and runs it.
  return _.template(tmpl)({});
}

module.exports = { renderTemplate };
