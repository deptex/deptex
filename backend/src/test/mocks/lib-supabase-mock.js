'use strict';

/**
 * Shared Supabase mock for backend route tests
 * resolve to the same instance. Used via Jest moduleNameMapper.
 */
const { supabase, queryBuilder } = require('./supabaseSingleton');
module.exports = {
  supabase,
  queryBuilder,
  createUserClient: typeof jest !== 'undefined' ? jest.fn() : function () {},
};
