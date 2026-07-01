/**
 * doFinalize scan-job completion guard (P5 reliability fix).
 *
 * The completion write used to flip the scan job to 'completed' unconditionally.
 * A user cancel landing during finalize sets status='cancelled' on the same row
 * (without rotating machine_id/run_id), so the unguarded write silently
 * overwrote the cancel. doFinalize now only flips a still-in-flight
 * ('processing') job, leaving a 'cancelled' (or recovery-requeued) status intact.
 *
 * Run: npx tsx test/finalize-cancel-guard.test.ts
 */

import { createPGLiteStorage, type PGLiteStorage } from '../src/storage';
import { doFinalize } from '../src/pipeline-steps/finalize';

let failures = 0;
let passed = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`    FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`    ok: ${msg}`);
    passed++;
  }
}

function makeLogger() {
  const warns: string[] = [];
  const logger = {
    info: async () => {},
    success: async () => {},
    warn: async (_step: string, msg: string) => {
      warns.push(msg);
    },
    error: async () => {},
  };
  return { logger, warns };
}

const ORG_ID = '00000000-0000-0000-0000-0000000000a1';

async function seed(
  storage: PGLiteStorage,
  projectId: string,
  jobId: string,
  jobStatus: 'processing' | 'cancelled',
): Promise<void> {
  await storage.from('organizations').insert({ id: ORG_ID, name: 'cg-org', created_at: new Date().toISOString() });
  await storage.from('projects').insert({
    id: projectId,
    organization_id: ORG_ID,
    name: `cg-project-${jobStatus}`,
    active_extraction_run_id: null,
    created_at: new Date().toISOString(),
  });
  await storage.from('scan_jobs').insert({
    id: jobId,
    project_id: projectId,
    organization_id: ORG_ID,
    type: 'extraction',
    status: jobStatus,
    payload: { source: 'cancel-guard-test' },
  });
}

function makeCtx(storage: PGLiteStorage, projectId: string, jobId: string, runId: string) {
  const { logger, warns } = makeLogger();
  const ctx = {
    job: { jobId },
    projectId,
    organizationId: ORG_ID,
    jobEcosystem: 'npm',
    runId,
    supabase: storage,
    log: logger,
    repoPath: null,
    workspaceRoot: '',
    importance: 1.0,
    graphTrusted: true,
    projectDepsCount: 0,
    newDepsToPopulate: [], // empty → status 'ready' → completion write fires
    astParsedSuccessfully: false,
  };
  return { ctx: ctx as any, warns };
}

async function jobStatusOf(storage: PGLiteStorage, jobId: string): Promise<string | null> {
  const { data } = await storage.from('scan_jobs').select('status').eq('id', jobId).single();
  return (data as { status?: string } | null)?.status ?? null;
}

async function main(): Promise<void> {
  const t0 = Date.now();
  console.log('Booting PGLiteStorage...');
  const storage = await createPGLiteStorage();
  console.log(`  booted in ${Date.now() - t0}ms\n`);

  // Scenario A: a still-in-flight ('processing') job is marked 'completed'.
  console.log('Scenario A: processing job → completed');
  {
    const projectId = '00000000-0000-0000-0000-0000000000b1';
    const jobId = '00000000-0000-0000-0000-0000000000c1';
    await seed(storage, projectId, jobId, 'processing');
    const { ctx, warns } = makeCtx(storage, projectId, jobId, 'run-a-1');
    await doFinalize(ctx, null);
    assert((await jobStatusOf(storage, jobId)) === 'completed', "processing job flipped to 'completed'");
    assert(
      !warns.some((w) => w.includes('no longer in-flight')),
      'no "left status untouched" warning for the normal completion path',
    );
  }

  // Scenario B: a job cancelled during finalize keeps its 'cancelled' status.
  console.log('\nScenario B: cancelled job → stays cancelled');
  {
    const projectId = '00000000-0000-0000-0000-0000000000b2';
    const jobId = '00000000-0000-0000-0000-0000000000c2';
    await seed(storage, projectId, jobId, 'cancelled');
    const { ctx, warns } = makeCtx(storage, projectId, jobId, 'run-b-1');
    await doFinalize(ctx, null);
    assert((await jobStatusOf(storage, jobId)) === 'cancelled', "cancelled job NOT overwritten (still 'cancelled')");
    assert(
      warns.some((w) => w.includes('no longer in-flight')),
      'warned that the cancelled job was left untouched',
    );
  }

  await storage.close();
  const label = failures === 0 ? 'ALL TESTS PASSED' : `${failures} ASSERTION(S) FAILED`;
  console.log(`\n${label} — ${passed} ok, ${failures} fail — ${Date.now() - t0}ms`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});
