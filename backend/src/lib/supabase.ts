import { createClient, SupabaseClient } from '@supabase/supabase-js';

// Permissive schema type so table/row types are not inferred as 'never' when no generated types are used
export type SupabaseClientAny = SupabaseClient<any, 'public', any>;

// Lazy initialization - only create client when first accessed
let _supabase: SupabaseClientAny | null = null;

function initSupabase(): SupabaseClientAny {
  if (_supabase) return _supabase;

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseServiceRoleKey) {
    throw new Error('Missing Supabase environment variables. Make sure .env file exists in the backend directory.');
  }

  _supabase = createClient(supabaseUrl, supabaseServiceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  }) as SupabaseClientAny;

  return _supabase;
}

// Export a getter that initializes on first access
export const supabase: SupabaseClientAny = new Proxy({} as SupabaseClientAny, {
  get(_target, prop) {
    const client = initSupabase();
    const value = (client as any)[prop];
    return typeof value === 'function' ? value.bind(client) : value;
  },
});

// Create a Supabase client for user operations (uses anon key)
export const createUserClient = (accessToken: string) => {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    throw new Error('Missing Supabase environment variables');
  }

  return createClient(supabaseUrl, supabaseAnonKey, {
    global: {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  });
};

