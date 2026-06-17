
// Table-aware registry: responses keyed by table name so route call order doesn't matter
export type TableRegistry = Record<string, {
  single?: { data: any; error: any } | Array<{ data: any; error: any }>;
  then?: { data: any; error: any };
  maybeSingle?: { data: any; error: any };
}>;

export type RpcRegistry = Record<string, { data: any; error: any } | Array<{ data: any; error: any }>>;

function consumeSingle(registry: TableRegistry, table: string): { data: any; error: any } | undefined {
  const entry = registry[table]?.single;
  if (entry === undefined) return undefined;
  if (Array.isArray(entry)) {
    // Queue mode: consume first, keep last for subsequent calls
    const val = entry[0];
    if (entry.length > 1) {
      registry[table].single = entry.slice(1);
    } else {
      // Exhausted — keep the last value so subsequent calls still return something
      registry[table].single = val;
    }
    return val;
  }
  // Plain replacement mode: return as-is (don't consume)
  return entry as { data: any; error: any };
}

function consumeRpc(rpcRegistry: RpcRegistry, name: string): { data: any; error: any } | undefined {
  const entry = rpcRegistry[name];
  if (entry === undefined) return undefined;
  if (Array.isArray(entry)) {
    // Queue mode: consume first, keep last for subsequent calls (mirrors consumeSingle)
    const val = entry[0];
    if (entry.length > 1) {
      rpcRegistry[name] = entry.slice(1);
    } else {
      rpcRegistry[name] = val;
    }
    return val;
  }
  // Plain replacement mode: return as-is (don't consume)
  return entry as { data: any; error: any };
}

export const createMockSupabase = (registry: TableRegistry = {}, rpcRegistry: RpcRegistry = {}) => {
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
    lt: jest.fn().mockReturnThis(),
    ilike: jest.fn().mockReturnThis(),
    contains: jest.fn().mockReturnThis(),
    or: jest.fn().mockReturnThis(),
    single: jest.fn().mockImplementation(function (this: any) {
      const r = consumeSingle(registry, this._table);
      if (r !== undefined) return Promise.resolve(r);
      return Promise.resolve({ data: null, error: null });
    }),
    maybeSingle: jest.fn().mockImplementation(function (this: any) {
      const r = registry[this._table]?.maybeSingle ?? consumeSingle(registry, this._table);
      if (r !== undefined) return Promise.resolve(r);
      return Promise.resolve({ data: null, error: null });
    }),
    order: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    range: jest.fn().mockReturnThis(),
    gte: jest.fn().mockReturnThis(),
    lte: jest.fn().mockReturnThis(),
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
      // Real PostgREST clients return a NEW builder per from() call. Mirror
      // that: a derived object carries its own _table so queries constructed
      // concurrently (Promise.all across tables) don't clobber each other,
      // while the shared jest.fn methods are inherited via the prototype so
      // `queryBuilder.eq.mock.calls`-style assertions keep working. The base
      // _table is still set for tests whose custom mockImplementations
      // `return queryBuilder` directly.
      queryBuilder._table = table;
      return Object.create(queryBuilder, { _table: { value: table, writable: true } });
    }),
    rpc: jest.fn().mockImplementation((name: string) => {
      const r = consumeRpc(rpcRegistry, name);
      if (r !== undefined) return Promise.resolve(r);
      return Promise.resolve({ data: null, error: null });
    }),
  };

  return { supabase, queryBuilder };
};
