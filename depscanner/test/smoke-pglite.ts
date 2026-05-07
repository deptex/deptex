/**
 * PGLite smoke test: verify PGLite can run all 192 migrations from
 * backend/database/*.sql and execute finalize_extraction end-to-end.
 *
 * Critical risk gate for M1 of the local-depscanner (formerly local-extraction-worker) plan. If this
 * passes, Postgres parity is good enough to build the storage abstraction on.
 *
 * Run: npx tsx test/smoke-pglite.ts
 */

import { PGlite } from '@electric-sql/pglite';
import { vector } from '@electric-sql/pglite/vector';
import { uuid_ossp } from '@electric-sql/pglite/contrib/uuid_ossp';
import * as fs from 'fs';
import * as path from 'path';

const SCHEMA_FILE = path.resolve(__dirname, '../../backend/database/schema.sql');

async function main() {
  const t0 = Date.now();
  console.log('PGLite smoke test — booting in-memory PGLite with pgvector + uuid-ossp...');
  const db = new PGlite({ extensions: { vector, uuid_ossp } });
  await db.waitReady;
  console.log(`  booted in ${Date.now() - t0}ms`);
  // gen_random_uuid() is built into Postgres 13+ core, so no pgcrypto needed.

  console.log('Activating extensions + creating stubs...');
  await db.exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`);
  await db.exec(`CREATE EXTENSION IF NOT EXISTS vector;`);
  await db.exec(`
    CREATE SCHEMA IF NOT EXISTS auth;
    CREATE TABLE IF NOT EXISTS auth.users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      email text,
      created_at timestamptz DEFAULT now()
    );
    -- Supabase auth.uid() stub — returns NULL in local mode (no user context).
    -- Triggers that reference auth.uid() will get NULL, which is fine for local testing.
    CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT NULL::uuid $$;
    CREATE OR REPLACE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE AS $$ SELECT 'service_role'::text $$;
    CREATE OR REPLACE FUNCTION auth.email() RETURNS text LANGUAGE sql STABLE AS $$ SELECT NULL::text $$;
    -- Stub for match_aegis_memories function — aegis_memory table was dropped
    -- but the function still exists. Give it a stub so the function compiles.
    CREATE TABLE IF NOT EXISTS public.aegis_memory (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      organization_id uuid,
      category text,
      key text,
      content text,
      embedding vector(1536),
      expires_at timestamptz
    );
  `);

  const schemaSql = fs.readFileSync(SCHEMA_FILE, 'utf8');
  console.log(`Loading schema dump (${(schemaSql.length / 1024).toFixed(1)} KB)...`);
  const t1 = Date.now();
  try {
    await db.exec(schemaSql);
    console.log(`  schema loaded in ${Date.now() - t1}ms`);
  } catch (e) {
    console.log(`  SCHEMA LOAD FAILED: ${(e as Error).message}`);
    process.exit(1);
  }

  console.log('\nSeeding minimal project + organization...');
  const orgId = '00000000-0000-0000-0000-000000000001';
  const projectId = '00000000-0000-0000-0000-000000000002';
  const runId = 'run_smoke_test_001';

  try {
    await db.exec(`
      INSERT INTO organizations (id, name, created_at)
      VALUES ('${orgId}', 'smoke-org', NOW())
      ON CONFLICT (id) DO NOTHING;
    `);
    await db.exec(`
      INSERT INTO projects (id, organization_id, name, active_extraction_run_id, created_at)
      VALUES ('${projectId}', '${orgId}', 'smoke-project', NULL, NOW())
      ON CONFLICT (id) DO NOTHING;
    `);
    console.log('  seeded org + project');
  } catch (e) {
    console.log(`  SEED FAILED: ${(e as Error).message}`);
    console.log('\nSmoke test inconclusive — cannot proceed to finalize_extraction.');
    process.exit(1);
  }

  console.log('\nCalling finalize_extraction(...)...');
  try {
    const res = await db.query<{ finalize_extraction: unknown }>(
      `SELECT finalize_extraction($1::uuid, $2::uuid, $3::text) AS finalize_extraction`,
      [projectId, projectId, runId],
    );
    console.log('  SUCCESS. Returned:');
    console.log(JSON.stringify(res.rows[0], null, 2));
  } catch (e) {
    console.log(`  FAILED: ${(e as Error).message}`);
    console.log('\nSmoke test failed. PGLite parity gap detected.');
    process.exit(1);
  }

  await db.close();
  console.log(`\nSmoke test PASSED in ${Date.now() - t0}ms`);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});
