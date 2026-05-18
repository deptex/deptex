// Patched template service — template source is a fixed literal, never tainted.
// User-supplied data is passed only as render-time DATA, not as template SOURCE.

const _ = require('lodash');

const FIXED_TEMPLATE = _.template('<p>Hello, <%- name %></p>');

function renderUserGreeting(name) {
  // _.template was compiled at module load with a constant string; we only
  // invoke the pre-compiled function here, so the lodash code_injection sink
  // never sees a tainted argument.
  return FIXED_TEMPLATE({ name: name });
}

module.exports = { renderUserGreeting };
