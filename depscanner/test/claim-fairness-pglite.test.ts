/**
 * Integration test: claim_scan_job (phase43 fairness) against an in-memory
 * PGLite running the real schema.sql.
 *
 *   1. Per-org cap is honored at a NON-DEFAULT value (1, not the default 5) —
 *      so a green test can't be an accident of the default.
 *   2. Fewest-in-flight-first ordering interleaves orgs instead of draining one.
 *
 * Run: npx tsx test/claim-fairness-pglite.test.ts
 */
import { createPGLiteStorage } from '../src/storage';

let failures = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

const ORG_A = '00000000-0000-0000-0000-00000000000a';
const ORG_B = '00000000-0000-0000-0000-00000000000b';

async function main(): Promise<void> {
  console.log('Booting PGLiteStorage (schema.sql)...');
  const storage = await createPGLiteStorage();
  const db = (storage as any).db;
  // FK triggers off so we can insert scan_jobs with synthetic org/project ids
  // without seeding the full organizations/projects graph.
  await db.exec(`SET session_replication_role = 'replica';`);

  const enqueue = async (org: string, offsetSec: number) => {
    await db.query(
      `INSERT INTO scan_jobs (project_id, organization_id, type, status, run_id, payload, created_at)
       VALUES (gen_random_uuid(), $1, 'extraction', 'queued', gen_random_uuid(), '{}'::jsonb,
               NOW() - ($2 || ' seconds')::interval)`,
      [org, String(offsetSec)],
    );
  };
  const claim = async (maxPerOrg: number): Promise<string | null> => {
    const res = await db.query(
      `SELECT organization_id FROM claim_scan_job('m-1', ARRAY['extraction'], $1)`,
      [maxPerOrg],
    );
    return res.rows[0]?.organization_id ?? null;
  };

  // --- Test 1: per-org cap at non-default value (1) ---
  console.log('\n[test] per-org cap honored at non-default value (1)');
  await db.exec(`DELETE FROM scan_jobs;`);
  for (let i = 0; i < 5; i++) await enqueue(ORG_A, 100 - i); // org A: 5 queued, oldest first
  await enqueue(ORG_B, 1); // org B: 1 queued, newest

  const c1 = await claim(1);
  const c2 = await claim(1);
  const c3 = await claim(1);
  assert(c1 === ORG_A, `first claim picks oldest org (A): got ${c1}`);
  assert(c2 === ORG_B, `second claim flips to B (A at cap 1): got ${c2}`);
  assert(c3 === null, `third claim is null — A capped, B exhausted (proves cap=1 took): got ${c3}`);

  // --- Test 2: fewest-in-flight-first interleaving at a high cap ---
  console.log('\n[test] fewest-in-flight-first interleaves orgs');
  await db.exec(`DELETE FROM scan_jobs;`);
  for (let i = 0; i < 3; i++) await enqueue(ORG_A, 100 - i);
  for (let i = 0; i < 3; i++) await enqueue(ORG_B, 50 - i);
  const claimed: string[] = [];
  for (let i = 0; i < 4; i++) {
    const c = await claim(5);
    if (c) claimed.push(c);
  }
  const aCount = claimed.filter((o) => o === ORG_A).length;
  const bCount = claimed.filter((o) => o === ORG_B).length;
  assert(aCount === 2 && bCount === 2, `4 claims interleave 2 A + 2 B: got A=${aCount} B=${bCount}`);

  console.log(failures === 0 ? '\nALL PASSED' : `\n${failures} FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
