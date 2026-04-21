/**
 * PGLiteStorage — in-process Postgres backend for the extraction worker.
 *
 * Implements the Storage interface against `@electric-sql/pglite`, translating
 * Supabase-style chainable builders (from/select/insert/update/upsert/delete +
 * eq/in/limit/single/maybeSingle) into raw parameterized SQL, and writing
 * storage bucket uploads to a local filesystem directory.
 *
 * Used by:
 *   - the `deptex scan` CLI (M2) so contributors can run the pipeline locally
 *     with no Supabase project
 *   - test fixtures / CI smoke tests
 *
 * Bootstrap gotchas (documented in reachability_phase1_state.md memory):
 *   1. Extensions must be passed to the PGlite constructor AND activated via
 *      CREATE EXTENSION. Both are required.
 *   2. pgcrypto is not available in PGLite; gen_random_uuid() is in PG13+ core.
 *   3. Supabase `auth` schema + `auth.users` + `auth.uid/role/email()` stubs
 *      must exist before schema.sql is loaded (triggers reference them).
 *   4. Orphan `aegis_memory` stub must exist (match_aegis_memories() still
 *      references a dropped table).
 *   5. RLS is intentionally omitted from schema.sql — local mode has no auth
 *      context; enabling RLS without policies would hide all rows.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import * as fs from 'fs';
import * as path from 'path';
import { PGlite } from '@electric-sql/pglite';
// PGLite publishes extension bundles under subpath `exports` that require
// moduleResolution "node16"/"nodenext"/"bundler". The rest of the worker
// still uses classic "node" resolution, so we load them via require() to
// keep both worlds happy without a tsconfig-wide change.
// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-explicit-any
const { vector } = require('@electric-sql/pglite/vector') as any;
// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-explicit-any
const { uuid_ossp } = require('@electric-sql/pglite/contrib/uuid_ossp') as any;

import type {
  BucketClient,
  FilterBuilder,
  QueryBuilder,
  Storage,
  StorageBuckets,
  StorageResult,
  UploadOptions,
  UpsertOptions,
} from './index';

export interface PGLiteStorageOptions {
  /** Path to schema.sql. Defaults to <repoRoot>/backend/database/schema.sql. */
  schemaPath?: string;
  /** Directory to write storage-bucket uploads into. Defaults to ./.pglite-buckets. */
  outputDir?: string;
  /** Optional: skip schema load (for testing against an already-seeded db). */
  skipSchemaLoad?: boolean;
}

const STUB_SQL = `
  CREATE SCHEMA IF NOT EXISTS auth;
  CREATE TABLE IF NOT EXISTS auth.users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text,
    created_at timestamptz DEFAULT now()
  );
  CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT NULL::uuid $$;
  CREATE OR REPLACE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE AS $$ SELECT 'service_role'::text $$;
  CREATE OR REPLACE FUNCTION auth.email() RETURNS text LANGUAGE sql STABLE AS $$ SELECT NULL::text $$;
  CREATE TABLE IF NOT EXISTS public.aegis_memory (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid,
    category text,
    key text,
    content text,
    embedding vector(1536),
    expires_at timestamptz
  );
`;

function defaultSchemaPath(): string {
  // src/storage/pglite.ts → ../../../../database/schema.sql (from dist: .ts compiled to dist/storage/pglite.js).
  // Resolve at runtime from this file.
  return path.resolve(__dirname, '../../../database/schema.sql');
}

/**
 * Create a Storage backed by an in-memory PGLite.
 *
 * Booting the DB, installing extensions, applying Supabase stubs and loading
 * schema.sql is ~2.7s total on a typical laptop. The returned Storage is
 * immediately usable from pipeline call sites.
 */
export async function createPGLiteStorage(
  opts: PGLiteStorageOptions = {},
): Promise<PGLiteStorage> {
  const outputDir = opts.outputDir ?? path.resolve(process.cwd(), '.pglite-buckets');
  fs.mkdirSync(outputDir, { recursive: true });

  const db = new PGlite({ extensions: { vector, uuid_ossp } });
  await db.waitReady;
  await db.exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`);
  await db.exec(`CREATE EXTENSION IF NOT EXISTS vector;`);
  await db.exec(STUB_SQL);

  if (!opts.skipSchemaLoad) {
    const schemaPath = opts.schemaPath ?? defaultSchemaPath();
    if (!fs.existsSync(schemaPath)) {
      throw new Error(
        `PGLiteStorage: schema.sql not found at ${schemaPath}. ` +
          `Run "cd backend/extraction-worker && npm run schema:dump" to generate it, or pass { schemaPath }.`,
      );
    }
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    await db.exec(schemaSql);
  }

  return new PGLiteStorage(db, outputDir);
}

/** Public class so callers can reach .close() / .db / .outputDir for tests. */
export class PGLiteStorage implements Storage {
  readonly storage: StorageBuckets;

  constructor(
    public readonly db: PGlite,
    public readonly outputDir: string,
  ) {
    this.storage = new PGLiteStorageBuckets(outputDir);
  }

  from<T = any>(table: string): QueryBuilder<T> {
    return new PGLiteQueryBuilder<T>(this.db, table);
  }

  rpc<T = any>(
    name: string,
    args: Record<string, unknown> = {},
  ): Promise<StorageResult<T>> {
    return invokeRpc<T>(this.db, name, args);
  }

  async close(): Promise<void> {
    await this.db.close();
  }
}

// ---------------------------------------------------------------------------
// Query builder
// ---------------------------------------------------------------------------

type Filter =
  | { type: 'eq'; col: string; val: unknown }
  | { type: 'in'; col: string; vals: readonly unknown[] };

interface BuilderState {
  table: string;
  op: 'select' | 'insert' | 'update' | 'upsert' | 'delete' | null;
  selectColumns?: string;
  insertRows?: any[];
  updateValues?: Record<string, unknown>;
  upsertOnConflict?: string;
  upsertIgnoreDuplicates?: boolean;
  returning?: string;
  filters: Filter[];
  limit?: number;
  single?: 'single' | 'maybeSingle';
}

class PGLiteQueryBuilder<T> implements QueryBuilder<T> {
  constructor(
    private readonly db: PGlite,
    private readonly table: string,
  ) {}

  private freshState(): BuilderState {
    return { table: this.table, op: null, filters: [] };
  }

  select(columns: string = '*'): FilterBuilder<T> {
    const s = this.freshState();
    s.op = 'select';
    s.selectColumns = columns;
    return new PGLiteFilterBuilder<T>(this.db, s);
  }

  insert(rows: T | T[]): FilterBuilder<T> {
    const s = this.freshState();
    s.op = 'insert';
    s.insertRows = Array.isArray(rows) ? [...rows] : [rows];
    return new PGLiteFilterBuilder<T>(this.db, s);
  }

  update(values: Partial<T> | Record<string, unknown>): FilterBuilder<T> {
    const s = this.freshState();
    s.op = 'update';
    s.updateValues = values as Record<string, unknown>;
    return new PGLiteFilterBuilder<T>(this.db, s);
  }

  upsert(rows: T | T[], options: UpsertOptions = {}): FilterBuilder<T> {
    const s = this.freshState();
    s.op = 'upsert';
    s.insertRows = Array.isArray(rows) ? [...rows] : [rows];
    s.upsertOnConflict = options.onConflict;
    s.upsertIgnoreDuplicates = options.ignoreDuplicates;
    return new PGLiteFilterBuilder<T>(this.db, s);
  }

  delete(): FilterBuilder<T> {
    const s = this.freshState();
    s.op = 'delete';
    return new PGLiteFilterBuilder<T>(this.db, s);
  }
}

class PGLiteFilterBuilder<T> implements FilterBuilder<T> {
  constructor(
    private readonly db: PGlite,
    private readonly state: BuilderState,
  ) {}

  eq(col: string, val: unknown): FilterBuilder<T> {
    this.state.filters.push({ type: 'eq', col, val });
    return this;
  }

  in(col: string, vals: readonly unknown[]): FilterBuilder<T> {
    this.state.filters.push({ type: 'in', col, vals });
    return this;
  }

  limit(n: number): FilterBuilder<T> {
    this.state.limit = n;
    return this;
  }

  /**
   * On an already-typed mutation (insert/update/upsert/delete), `.select(cols)`
   * adds a RETURNING clause. On a raw builder (no op), acts like .select().
   */
  select(columns: string = '*'): FilterBuilder<T> {
    if (this.state.op && this.state.op !== 'select') {
      this.state.returning = columns;
    } else {
      this.state.op = 'select';
      this.state.selectColumns = columns;
    }
    return this;
  }

  single(): Promise<StorageResult<T>> {
    this.state.single = 'single';
    return this.execute() as Promise<StorageResult<T>>;
  }

  maybeSingle(): Promise<StorageResult<T>> {
    this.state.single = 'maybeSingle';
    return this.execute() as Promise<StorageResult<T>>;
  }

  then<TResult1 = StorageResult<T[]>, TResult2 = never>(
    onfulfilled?:
      | ((value: StorageResult<T[]>) => TResult1 | PromiseLike<TResult1>)
      | undefined
      | null,
    onrejected?:
      | ((reason: any) => TResult2 | PromiseLike<TResult2>)
      | undefined
      | null,
  ): PromiseLike<TResult1 | TResult2> {
    // .execute() unions StorageResult<T> | StorageResult<T[]> because
    // single/maybeSingle share the same codepath. When awaited without
    // .single()/.maybeSingle() the runtime shape is always an array,
    // so the cast matches the declared signature.
    return (this.execute() as Promise<StorageResult<T[]>>).then(
      onfulfilled,
      onrejected,
    ) as PromiseLike<TResult1 | TResult2>;
  }

  private async execute(): Promise<StorageResult<T> | StorageResult<T[]>> {
    try {
      const { sql, params } = buildSql(this.state);
      const res = await this.db.query<any>(sql, params);
      return shapeResult<T>(this.state, res.rows as any[]);
    } catch (e: any) {
      return { data: null, error: wrapError(e) };
    }
  }
}

// ---------------------------------------------------------------------------
// SQL generation
// ---------------------------------------------------------------------------

function buildSql(s: BuilderState): { sql: string; params: unknown[] } {
  const params: unknown[] = [];
  const bind = (v: unknown): string => {
    params.push(normalizeValue(v));
    return `$${params.length}`;
  };

  switch (s.op) {
    case 'select': {
      const cols = s.selectColumns && s.selectColumns.length > 0 ? s.selectColumns : '*';
      let sql = `SELECT ${cols} FROM ${s.table}`;
      const where = buildWhere(s.filters, bind);
      if (where) sql += ` WHERE ${where}`;
      if (s.limit != null) sql += ` LIMIT ${Math.floor(s.limit)}`;
      return { sql, params };
    }
    case 'insert': {
      if (!s.insertRows || s.insertRows.length === 0) {
        // Degenerate case: Supabase silently succeeds with empty input.
        throw new Error('insert: cannot insert zero rows');
      }
      const { cols, valuesSql } = buildInsertValues(s.insertRows, bind);
      let sql = `INSERT INTO ${s.table} (${cols.join(', ')}) VALUES ${valuesSql}`;
      if (s.returning) sql += ` RETURNING ${s.returning}`;
      return { sql, params };
    }
    case 'update': {
      if (!s.updateValues || Object.keys(s.updateValues).length === 0) {
        throw new Error('update: no columns supplied');
      }
      const setSql = Object.entries(s.updateValues)
        .map(([k, v]) => `${k} = ${bind(v)}`)
        .join(', ');
      let sql = `UPDATE ${s.table} SET ${setSql}`;
      // Postgres doesn't support LIMIT on UPDATE. To preserve Supabase
      // semantics of "at most N matching rows" we scope via a ctid subquery.
      if (s.limit != null) {
        const sub = buildWhere(s.filters, bind);
        sql += ` WHERE ctid IN (SELECT ctid FROM ${s.table}`;
        if (sub) sql += ` WHERE ${sub}`;
        sql += ` LIMIT ${Math.floor(s.limit)})`;
      } else {
        const where = buildWhere(s.filters, bind);
        if (where) sql += ` WHERE ${where}`;
      }
      if (s.returning) sql += ` RETURNING ${s.returning}`;
      return { sql, params };
    }
    case 'upsert': {
      if (!s.insertRows || s.insertRows.length === 0) {
        throw new Error('upsert: cannot upsert zero rows');
      }
      const { cols, valuesSql } = buildInsertValues(s.insertRows, bind);
      let sql = `INSERT INTO ${s.table} (${cols.join(', ')}) VALUES ${valuesSql}`;
      const conflictCols = (s.upsertOnConflict ?? '')
        .split(',')
        .map((c) => c.trim())
        .filter(Boolean);
      if (conflictCols.length === 0) {
        // Supabase treats missing onConflict as "use primary key"; PGLite needs it
        // explicit. If callers ever forget, let Postgres complain naturally.
        sql += ` ON CONFLICT DO NOTHING`;
      } else if (s.upsertIgnoreDuplicates) {
        sql += ` ON CONFLICT (${conflictCols.join(', ')}) DO NOTHING`;
      } else {
        const nonConflict = cols.filter((c) => !conflictCols.includes(c));
        if (nonConflict.length === 0) {
          sql += ` ON CONFLICT (${conflictCols.join(', ')}) DO NOTHING`;
        } else {
          const updateSet = nonConflict
            .map((c) => `${c} = EXCLUDED.${c}`)
            .join(', ');
          sql += ` ON CONFLICT (${conflictCols.join(', ')}) DO UPDATE SET ${updateSet}`;
        }
      }
      if (s.returning) sql += ` RETURNING ${s.returning}`;
      return { sql, params };
    }
    case 'delete': {
      let sql = `DELETE FROM ${s.table}`;
      const where = buildWhere(s.filters, bind);
      if (where) sql += ` WHERE ${where}`;
      if (s.returning) sql += ` RETURNING ${s.returning}`;
      return { sql, params };
    }
    default:
      throw new Error(`unknown or unset op: ${s.op}`);
  }
}

function buildWhere(
  filters: Filter[],
  bind: (v: unknown) => string,
): string | null {
  if (filters.length === 0) return null;
  const parts: string[] = [];
  for (const f of filters) {
    if (f.type === 'eq') {
      if (f.val === null) parts.push(`${f.col} IS NULL`);
      else parts.push(`${f.col} = ${bind(f.val)}`);
    } else if (f.type === 'in') {
      if (f.vals.length === 0) {
        // Empty IN list: SQL-standard says this should match nothing.
        parts.push(`FALSE`);
      } else {
        const placeholders = f.vals.map((v) => bind(v)).join(', ');
        parts.push(`${f.col} IN (${placeholders})`);
      }
    }
  }
  return parts.join(' AND ');
}

function buildInsertValues(
  rows: any[],
  bind: (v: unknown) => string,
): { cols: string[]; valuesSql: string } {
  // Union of columns across all rows, preserving first-seen order.
  const colOrder: string[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    for (const k of Object.keys(row)) {
      if (!seen.has(k)) {
        seen.add(k);
        colOrder.push(k);
      }
    }
  }
  const tuples: string[] = [];
  for (const row of rows) {
    const placeholders = colOrder.map((c) =>
      Object.prototype.hasOwnProperty.call(row, c) ? bind(row[c]) : `DEFAULT`,
    );
    tuples.push(`(${placeholders.join(', ')})`);
  }
  return { cols: colOrder, valuesSql: tuples.join(', ') };
}

/**
 * Normalize a JS value for PGLite's parameter binding.
 *
 * Postgres has two different array representations, and without knowing the
 * column type ahead of time we have to infer:
 *   - Native text[] / numeric[] columns expect a JS array passed natively
 *     (PGLite's binding formats `{a,b,c}` on the wire).
 *   - JSONB columns (including jsonb arrays-of-objects like flow_nodes)
 *     expect a JSON string.
 *
 * Heuristic: an array of primitives is almost always a native Postgres
 * array column in our schema (e.g. fixed_versions text[], aliases text[]).
 * An array containing any object is JSONB. Plain objects are JSONB.
 *
 * This is good enough for every call site in the extraction pipeline. A
 * future type-aware version could introspect pg_catalog once at boot.
 */
function normalizeValue(v: unknown): unknown {
  if (v === null || v === undefined) return null;
  if (v instanceof Date) return v.toISOString();
  if (Array.isArray(v)) {
    const hasObject = v.some(
      (el) => el !== null && typeof el === 'object' && !(el instanceof Date),
    );
    return hasObject ? JSON.stringify(v) : v;
  }
  if (typeof v === 'object') return JSON.stringify(v);
  return v;
}

// ---------------------------------------------------------------------------
// Result shaping — match supabase-js return contract
// ---------------------------------------------------------------------------

function shapeResult<T>(
  s: BuilderState,
  rows: any[],
): StorageResult<T> | StorageResult<T[]> {
  // Mutations with no RETURNING clause: Supabase returns { data: null, error: null }.
  if ((s.op === 'insert' || s.op === 'update' || s.op === 'upsert' || s.op === 'delete') && !s.returning) {
    return { data: null, error: null };
  }
  if (s.single === 'single') {
    if (rows.length === 0) {
      return {
        data: null,
        error: Object.assign(new Error('No rows found'), { code: 'PGRST116' }) as any,
      };
    }
    if (rows.length > 1) {
      return {
        data: null,
        error: Object.assign(new Error('More than one row returned'), {
          code: 'PGRST116',
        }) as any,
      };
    }
    return { data: rows[0] as T, error: null };
  }
  if (s.single === 'maybeSingle') {
    if (rows.length === 0) return { data: null, error: null };
    if (rows.length > 1) {
      return {
        data: null,
        error: Object.assign(new Error('More than one row returned'), {
          code: 'PGRST116',
        }) as any,
      };
    }
    return { data: rows[0] as T, error: null };
  }
  return { data: rows as T[], error: null };
}

function wrapError(e: unknown): Error & { message: string; status?: number } {
  if (e instanceof Error) return e as Error & { message: string };
  const err = new Error(String(e));
  return err as Error & { message: string };
}

// ---------------------------------------------------------------------------
// RPC invocation
// ---------------------------------------------------------------------------

async function invokeRpc<T>(
  db: PGlite,
  name: string,
  args: Record<string, unknown>,
): Promise<StorageResult<T>> {
  try {
    const entries = Object.entries(args);
    const params = entries.map(([, v]) => normalizeValue(v));
    const argSql = entries
      .map(([k], i) => `${k} := $${i + 1}`)
      .join(', ');
    const sql = `SELECT * FROM ${name}(${argSql})`;
    const res = await db.query<any>(sql, params);
    const rows = res.rows as any[];
    if (rows.length === 0) {
      // Convention: scalar-return functions still yield one row.
      // Zero rows means a SETOF function with no results.
      return { data: null as any, error: null };
    }
    const keys = Object.keys(rows[0] ?? {});
    // Scalar-return (e.g. JSONB): PGLite gives one row with one column
    // named after the function. Unwrap to match Supabase's behavior.
    if (rows.length === 1 && keys.length === 1 && keys[0] === name) {
      return { data: (rows[0] as any)[keys[0]] as T, error: null };
    }
    return { data: rows as unknown as T, error: null };
  } catch (e: any) {
    return { data: null, error: wrapError(e) };
  }
}

// ---------------------------------------------------------------------------
// Storage buckets (filesystem-backed)
// ---------------------------------------------------------------------------

class PGLiteStorageBuckets implements StorageBuckets {
  constructor(private readonly outputDir: string) {}

  from(bucket: string): BucketClient {
    return new PGLiteBucket(path.join(this.outputDir, bucket));
  }
}

class PGLiteBucket implements BucketClient {
  constructor(private readonly dir: string) {}

  async upload(
    filePath: string,
    content: string | Buffer | Uint8Array,
    options: UploadOptions = {},
  ): Promise<StorageResult<{ path: string }>> {
    try {
      const abs = path.join(this.dir, filePath);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      if (!options.upsert && fs.existsSync(abs)) {
        return {
          data: null,
          error: Object.assign(new Error('File already exists'), {
            statusCode: '409',
          }) as any,
        };
      }
      const buf =
        typeof content === 'string'
          ? Buffer.from(content, 'utf8')
          : Buffer.isBuffer(content)
            ? content
            : Buffer.from(content);
      fs.writeFileSync(abs, buf);
      return { data: { path: filePath }, error: null };
    } catch (e: any) {
      return { data: null, error: wrapError(e) };
    }
  }
}
