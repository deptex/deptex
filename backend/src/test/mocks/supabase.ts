
// Helper to create a chainable mock for Supabase
export const createMockSupabase = () => {
  const queryBuilder: any = {
    select: jest.fn().mockReturnThis(),
    insert: jest.fn().mockReturnThis(),
    update: jest.fn().mockReturnThis(),
    delete: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    neq: jest.fn().mockReturnThis(),
    in: jest.fn().mockReturnThis(),
    single: jest.fn(), // Should return promise
    maybeSingle: jest.fn(), // Should return promise
    order: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    upsert: jest.fn().mockReturnThis(),
    // Make it Thenable
    then: jest.fn((resolve, reject) => {
      // Default behavior: resolve with empty success
      // Tests should override this with mockImplementation
      return Promise.resolve({ data: {}, error: null }).then(resolve, reject);
    }),
  };

  // Make end-of-chain methods return a Promise resolving to data/error structure
  queryBuilder.single.mockResolvedValue({ data: {}, error: null });
  queryBuilder.maybeSingle.mockResolvedValue({ data: {}, error: null });

  const supabase = {
    auth: {
      getUser: jest.fn(),
      admin: {
        getUserById: jest.fn(),
        listUsers: jest.fn(),
      },
    },
    from: jest.fn().mockReturnValue(queryBuilder),
  };

  return { supabase, queryBuilder };
};
