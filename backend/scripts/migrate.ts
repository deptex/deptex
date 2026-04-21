/**
 * Deptex migration runner.
 *
 * Applies unapplied files from `backend/database/*.sql` to the target database,
 * tracking state in a `schema_migrations` table.
 *
 * Usage (from backend/):
 *   npm run migrate            # apply any unapplied migrations
 *   npm run migrate:baseline   # mark all current migrations as already applied
 *                              # (run once, right after `psql -f schema.sql`)
 *   npm run migrate:status     # list applied + pending migrations
 *
 * Config:
 *   DATABASE_URL=postgres://user:pass@host:port/db
 *   — or —
 *   defaults to local supabase stack (postgres://postgres:postgres@127.0.0.1:54322/postgres)
 *
 * Shells out to `psql` rather than taking a Node Postgres dep. Any self-hoster
 * running `supabase start` already has psql installed.
 *
 * Files in backend/database/ that are NOT treated as migrations:
 *   - schema.sql                             (baseline pg_dump — applied during initial setup)
 *   - phase19_4_schema_dump_helper.sql       (installed by setup-local-db.sh)
 *   - Anything not ending in .sql
 */

import * as fs from 'fs';
import * as path from 'path';
import { execFileSync, spawnSync } from 'child_process';

const DB_URL =
  process.env.DATABASE_URL ||
  'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

const MIGRATIONS_DIR = path.resolve(__dirname, '../database');

const EXCLUDE = new Set(['schema.sql', 'phase19_4_schema_dump_helper.sql']);

const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  filename TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`.trim();

function psqlQuery(sql: string): string {
  const r = spawnSync('psql', [DB_URL, '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', sql], {
    encoding: 'utf8',
  });
  if (r.status !== 0) {
    throw new Error(`psql failed (${r.status}): ${r.stderr || r.stdout}`);
  }
  return r.stdout.trim();
}

function psqlFile(file: string): void {
  // Wrap file in a single transaction so a failure rolls back cleanly.
  execFileSync('psql', [DB_URL, '-X', '-v', 'ON_ERROR_STOP=1', '--single-transaction', '-f', file], {
    stdio: 'inherit',
  });
}

function assertPsql() {
  const r = spawnSync('psql', ['--version'], { encoding: 'utf8' });
  if (r.status !== 0) {
    console.error('ERROR: psql not found on PATH. Install PostgreSQL client tools.');
    process.exit(1);
  }
}

function listMigrationFiles(): string[] {
  return fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql') && !EXCLUDE.has(f))
    .sort();
}

function listApplied(): Set<string> {
  psqlQuery(CREATE_TABLE_SQL);
  const out = psqlQuery('SELECT filename FROM schema_migrations ORDER BY filename;');
  return new Set(out.split('\n').map((s) => s.trim()).filter(Boolean));
}

function recordApplied(filename: string) {
  const safe = filename.replace(/'/g, "''");
  psqlQuery(`INSERT INTO schema_migrations (filename) VALUES ('${safe}') ON CONFLICT DO NOTHING;`);
}

function cmdStatus() {
  const applied = listApplied();
  const all = listMigrationFiles();
  const pending = all.filter((f) => !applied.has(f));
  console.log(`Applied: ${applied.size}`);
  for (const f of [...applied].sort()) console.log('  + ' + f);
  console.log(`\nPending: ${pending.length}`);
  for (const f of pending) console.log('  - ' + f);
}

function cmdBaseline() {
  const all = listMigrationFiles();
  psqlQuery(CREATE_TABLE_SQL);
  for (const f of all) recordApplied(f);
  console.log(`Marked ${all.length} migration(s) as applied (baseline).`);
}

function cmdMigrate() {
  const applied = listApplied();
  const all = listMigrationFiles();
  const pending = all.filter((f) => !applied.has(f));

  if (pending.length === 0) {
    console.log('No pending migrations.');
    return;
  }

  console.log(`Applying ${pending.length} migration(s) to ${DB_URL.replace(/:[^:@]+@/, ':***@')}`);
  for (const f of pending) {
    console.log(`\n==> ${f}`);
    psqlFile(path.join(MIGRATIONS_DIR, f));
    recordApplied(f);
    console.log(`    OK`);
  }
  console.log(`\nDone. Applied ${pending.length} migration(s).`);
}

function main() {
  assertPsql();
  const cmd = process.argv[2] || 'migrate';
  switch (cmd) {
    case 'migrate':
      cmdMigrate();
      break;
    case 'baseline':
      cmdBaseline();
      break;
    case 'status':
      cmdStatus();
      break;
    default:
      console.error(`Unknown command: ${cmd}`);
      console.error('Usage: migrate | baseline | status');
      process.exit(1);
  }
}

main();
