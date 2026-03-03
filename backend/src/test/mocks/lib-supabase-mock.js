'use strict';

/**
 * Shared Supabase mock so backend and ee/backend routes (different import paths)
 * resolve to the same instance. Used via Jest moduleNameMapper.
 */
const { supabase, queryBuilder } = require('./supabaseSingleton');
module.exports = {
  supabase,
  queryBuilder,
  createUserClient: typeof jest !== 'undefined' ? jest.fn() : function () {},
};
