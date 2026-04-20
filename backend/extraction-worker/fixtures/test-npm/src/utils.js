const { merge, cloneDeep } = require('lodash');

module.exports.processData = function processData(input) {
  return cloneDeep(merge({}, input));
};
