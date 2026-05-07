/**
 * SupabaseStorage — thin adapter around `@supabase/supabase-js`.
 *
 * SupabaseClient already implements the entire `Storage` interface
 * structurally (from, rpc, storage.from, chainable .select/.insert/.update/
 * .upsert, .eq/.in/.limit, .single/.maybeSingle, awaitable `{ data, error }`).
 * No runtime wrapping is needed. This file exists for symmetry with the
 * PGLite backend and to localize the one place we touch createClient().
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import type { Storage } from './index';

export interface SupabaseStorageOptions {
  url?: string;
  serviceRoleKey?: string;
}

/**
 * Create a Storage backed by a Supabase service-role client.
 *
 * Reads SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY from env by default.
 * Throws synchronously if neither opts nor env provide them.
 */
export function createSupabaseStorage(
  opts: SupabaseStorageOptions = {},
): Storage {
  const url = opts.url ?? process.env.SUPABASE_URL;
  const key = opts.serviceRoleKey ?? process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    throw new Error(
      'SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set to use SupabaseStorage',
    );
  }
  // SupabaseClient conforms to Storage structurally; the cast is safe.
  return createClient(url, key) as unknown as Storage;
}

/** Re-exported for call sites that want to hold an explicit SupabaseClient. */
export type { SupabaseClient };
