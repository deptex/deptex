/**
 * Storage abstraction for the extraction worker.
 *
 * The pipeline was historically coupled to `@supabase/supabase-js` via
 * `SupabaseClient`. To let the worker run against a local PGLite instance
 * (for CLI mode, tests, and OSS contributors with no Supabase), we narrow
 * the coupling to the minimal surface we actually use: a structural subset
 * of the Supabase query builder plus the Storage (object) bucket API.
 *
 * Two implementations live alongside this file:
 *   - ./supabase — wraps createClient() from @supabase/supabase-js (prod)
 *   - ./pglite   — wraps @electric-sql/pglite + a local filesystem bucket
 *
 * The types below are intentionally compatible with supabase-js so a
 * SupabaseClient can be passed where a Storage is expected.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

export interface UpsertOptions {
  onConflict?: string;
  ignoreDuplicates?: boolean;
}

export interface StorageResult<T> {
  data: T | null;
  error: (Error & { message: string; status?: number }) | null;
}

type Thenable<T> = PromiseLike<T>;

/** Chainable builder returned after a filterable operation (select/update/upsert/delete). */
export interface FilterBuilder<T = any> extends Thenable<StorageResult<T[]>> {
  eq(column: string, value: unknown): FilterBuilder<T>;
  in(column: string, values: readonly unknown[]): FilterBuilder<T>;
  limit(n: number): FilterBuilder<T>;
  select(columns?: string): FilterBuilder<T>;
  single(): Thenable<StorageResult<T>>;
  maybeSingle(): Thenable<StorageResult<T>>;
}

/** Builder returned from `.from(table)`. */
export interface QueryBuilder<T = any> {
  select(columns?: string): FilterBuilder<T>;
  insert(rows: T | T[]): FilterBuilder<T>;
  update(values: Partial<T> | Record<string, unknown>): FilterBuilder<T>;
  upsert(rows: T | T[], options?: UpsertOptions): FilterBuilder<T>;
  delete(): FilterBuilder<T>;
}

export interface UploadOptions {
  contentType?: string;
  upsert?: boolean;
  cacheControl?: string;
}

export interface BucketClient {
  upload(
    path: string,
    content: string | Buffer | Uint8Array,
    options?: UploadOptions,
  ): Promise<StorageResult<{ path: string }>>;
}

export interface StorageBuckets {
  from(bucket: string): BucketClient;
}

export interface Storage {
  from<T = any>(table: string): QueryBuilder<T>;
  rpc<T = any>(
    name: string,
    args?: Record<string, unknown>,
  ): Thenable<StorageResult<T>>;
  storage: StorageBuckets;
}

export { createSupabaseStorage } from './supabase';
export { createPGLiteStorage } from './pglite';
export type { PGLiteStorage, PGLiteStorageOptions } from './pglite';
