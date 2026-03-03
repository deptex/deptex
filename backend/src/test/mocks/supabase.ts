
// Table-aware registry: responses keyed by table name so route call order doesn't matter
export type TableRegistry = Record<string, {
  single?: { data: any; error: any };
  then?: { data: any; error: any };
  maybeSingle?: { data: any; error: any };
}>;

export const createMockSupabase = (registry: TableRegistry = {}) => {
  const queryBuilder: any = {
    _table: '' as string,
    select: jest.fn().mockReturnThis(),
    insert: jest.fn().mockReturnThis(),
    update: jest.fn().mockReturnThis(),
    delete: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    neq: jest.fn().mockReturnThis(),
    in: jest.fn().mockReturnThis(),
    is: jest.fn().mockReturnThis(),
    gt: jest.fn().mockReturnThis(),
    single: jest.fn().mockImplementation(function (this: any) {
      const r = registry[this._table]?.single;
      if (r !== undefined) return Promise.resolve(r);
      return Promise.resolve({ data: null, error: null });
    }),
    maybeSingle: jest.fn().mockImplementation(function (this: any) {
      const r = registry[this._table]?.maybeSingle ?? registry[this._table]?.single;
      if (r !== undefined) return Promise.resolve(r);
      return Promise.resolve({ data: null, error: null });
    }),
    order: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    upsert: jest.fn().mockReturnThis(),
    then: jest.fn().mockImplementation(function (this: any, resolve: any) {
      const r = registry[this._table]?.then;
      if (r !== undefined) return resolve(r);
      return resolve({ data: [], error: null });
    }),
  };

  const supabase = {
    auth: {
      getUser: jest.fn(),
      admin: {
        getUserById: jest.fn(),
        listUsers: jest.fn(),
      },
    },
    from: jest.fn().mockImplementation((table: string) => {
      queryBuilder._table = table;
      return queryBuilder;
    }),
  };

  return { supabase, queryBuilder };
};
