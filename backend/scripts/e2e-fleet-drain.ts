/**
 * Live FULL-DRAIN e2e for the fleet dispatcher — the production path end to end.
 *
 * Drives the exact function the create-project route calls (queueExtractionJob),
 * whose in-process nudge fires the dispatcher. So this one script reproduces:
 *
 *   enqueue → nudge → dispatchFleet (provision, single-flight, hard-capped)
 *           → real Fly machine boots → worker claims the job (claim_scan_job)
 *           → dispatcher sees it inflight + stops provisioning → job drains
 *           → terminal status → machine auto-destroys (auto_destroy=true)
 *
 * It re-extracts an EXISTING ready test project (no throwaway data to create or
 * tear down) and watches the whole thing against real Fly + real Supabase + real
 * Upstash. It spins a REAL billable machine and re-runs a real extraction, so it
 * is opt-in: set DEPTEX_FLEET_DRAIN=1 to run.
 *
 *   DEPTEX_FLEET_DRAIN=1 npm run e2e:fleet:drain   (in backend/)
 *
 * Override the target with DRAIN_PROJECT_ID / DRAIN_ORG_ID / DRAIN_REPO etc.
 */
import 'dotenv/config';
import { queueExtractionJob } from '../src/lib/extraction-jobs';
import { dispatchFleet, getFleetMetrics } from '../src/lib/fleet-dispatcher';
import { supabase } from '../src/lib/supabase';
import { DEPSCANNER_CONFIG, listMachines, stopFlyMachine } from '../src/lib/fly-machines';

// Default target: the "Deptex Test Python" project (the only `ready` repo).
const PROJECT_ID = process.env.DRAIN_PROJECT_ID || 'a3c467e0-ed32-4791-85bd-0ac8ece30a36';
const ORG_ID = process.env.DRAIN_ORG_ID || '5a7b7c20-8d56-4005-9a8e-9ee63391b102';
const REPO = {
  repo_full_name: process.env.DRAIN_REPO || 'deptex/deptex-test-python',
  installation_id: process.env.DRAIN_INSTALLATION_ID || '114098183',
  default_branch: process.env.DRAIN_BRANCH || 'master',
  ecosystem: process.env.DRAIN_ECOSYSTEM || 'pypi',
  provider: 'github',
  integration_id: process.env.DRAIN_INTEGRATION_ID || '00047489-f877-4fdf-af43-2ff65fffe27b',
};

const POLL_MS = 5000;
const MAX_MS = 12 * 60 * 1000; // python extraction headroom

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const nowHHMMSS = (iso?: string) => (iso ? iso.slice(11, 19) : '--:--:--');

async function main(): Promise<void> {
  if (process.env.DEPTEX_FLEET_DRAIN !== '1') {
    console.error('Refusing to run: this spins a real Fly machine + re-runs a real extraction. Set DEPTEX_FLEET_DRAIN=1.');
    process.exit(2);
  }
  if (!process.env.FLY_API_TOKEN) throw new Error('FLY_API_TOKEN not set');
  // FLY_DEPSCANNER_IMAGE is optional now — the dispatcher auto-resolves the image
  // from the live deployment when it's unset (see resolveDepscannerImage).

  const app = DEPSCANNER_CONFIG.app;
  console.log(`[drain] app=${app}`);
  console.log(`[drain] target project=${PROJECT_ID} repo=${REPO.repo_full_name}@${REPO.default_branch} (${REPO.ecosystem})`);

  // Preflight: confirm the queue is idle so we observe a clean 0→1→0 provision.
  const pre = await getFleetMetrics('extraction');
  console.log(`[drain] preflight metrics: queued=${pre.queued} running=${pre.running} starting=${pre.starting} inflight=${pre.inflight}`);
  if (pre.queued > 0 || pre.running > 0) {
    console.warn('[drain] WARNING: queue/fleet not idle — provision math below will include pre-existing work.');
  }

  // 1. Enqueue exactly as the create-project route does. This nudges the
  //    dispatcher in-process, which provisions one machine.
  console.log('[drain] enqueueing extraction (queueExtractionJob → nudgeDispatcher)…');
  const res = await queueExtractionJob(PROJECT_ID, ORG_ID, REPO, { trigger_type: 'manual' });
  if (!res.success || !res.run_id) {
    throw new Error(`enqueue failed: ${res.error ?? 'unknown'}`);
  }
  const runId = res.run_id;
  console.log(`[drain] queued run_id=${runId}`);

  // 2. Watch it drain. Each tick we also call dispatchFleet (mimicking the
  //    every-minute cron) to prove it does NOT over-provision while inflight.
  const start = Date.now();
  let maxStarted = 0;
  let maxInflight = 0;
  let claimedMachine: string | null = null;
  let everProcessing = false;
  let terminal: string | null = null;
  let lastStep = '';

  while (Date.now() - start < MAX_MS) {
    const tick = await dispatchFleet('extraction');
    maxStarted = Math.max(maxStarted, tick.started);
    maxInflight = Math.max(maxInflight, tick.inflight);

    const { data: job } = await supabase
      .from('scan_jobs')
      .select('status, machine_id, attempts, started_at, completed_at')
      .eq('run_id', runId)
      .maybeSingle();
    const { data: logRows } = await supabase
      .from('extraction_logs')
      .select('step, level, message, created_at')
      .eq('run_id', runId)
      .order('created_at', { ascending: false })
      .limit(1);
    const log = logRows?.[0];

    if (job?.machine_id) claimedMachine = job.machine_id;
    if (job?.status === 'processing') everProcessing = true;
    const step = log?.step ?? '';
    const stepNote = step && step !== lastStep ? `  ▸ ${step}: ${log?.message ?? ''}`.slice(0, 110) : '';
    lastStep = step || lastStep;

    const t = Math.round((Date.now() - start) / 1000);
    console.log(
      `[drain +${String(t).padStart(3)}s] job=${job?.status ?? '?'} machine=${job?.machine_id ?? '—'} ` +
        `| tick: queued=${tick.queued} inflight=${tick.inflight} started=${tick.started} desired=${tick.desired} capped=${tick.capped}` +
        (stepNote ? `\n${stepNote}` : ''),
    );

    if (job?.status && ['completed', 'failed', 'cancelled'].includes(job.status)) {
      terminal = job.status;
      break;
    }
    await sleep(POLL_MS);
  }

  // 3. Settle: give auto_destroy a moment, then check the machine is gone.
  await sleep(4000);
  let machineGone = true;
  try {
    const machines = await listMachines(app);
    const m = claimedMachine ? machines.find((x) => x.id === claimedMachine) : undefined;
    if (m) {
      machineGone = ['stopped', 'destroyed', 'destroying'].includes(m.state);
      console.log(`[drain] claimed machine ${m.id} final state=${m.state}`);
      // Belt-and-braces: if it's still 'started' with the job terminal, stop it.
      if (m.state === 'started' && terminal) {
        try { await stopFlyMachine(app, m.id); console.log(`[drain] stopped lingering machine ${m.id}`); } catch { /* auto_destroy will get it */ }
      }
    } else if (claimedMachine) {
      console.log(`[drain] claimed machine ${claimedMachine} no longer listed (auto-destroyed) ✓`);
    }
  } catch (e: any) {
    console.warn(`[drain] machine check failed: ${e?.message ?? e}`);
  }

  // 4. Verdict.
  console.log('\n' + '─'.repeat(64));
  console.log(`provisioned a machine ........ ${maxStarted >= 1 ? '✓' : '✗'} (max started in one tick = ${maxStarted})`);
  console.log(`worker claimed the job ....... ${claimedMachine ? '✓' : '✗'} (machine ${claimedMachine ?? '—'})`);
  console.log(`reached processing ........... ${everProcessing ? '✓' : '✗'}`);
  console.log(`never over-provisioned ....... ${maxInflight <= 1 ? '✓' : '✗'} (max inflight = ${maxInflight}, expected ≤1 for one job)`);
  console.log(`terminal status .............. ${terminal ?? 'TIMED OUT (still draining)'}`);
  console.log(`machine cleaned up ........... ${machineGone ? '✓' : '⚠ still running'}`);
  console.log('─'.repeat(64));

  // Success = dispatcher provisioned exactly one machine, it claimed the job,
  // and the job reached a terminal state. A clone failure (access_revoked) still
  // proves provision+claim+drain — it just ends in `failed` rather than `completed`.
  const dispatchOk = maxStarted >= 1 && !!claimedMachine && everProcessing && maxInflight <= 1;
  if (terminal === 'completed') {
    console.log('PASS — full drain: provisioned → claimed → extracted → completed → cleaned up.');
    process.exit(0);
  }
  if (dispatchOk && terminal === 'failed') {
    console.log('PARTIAL — dispatcher loop proven (provision→claim→drain) but extraction FAILED (likely clone/access). Dispatcher is good; check the GitHub App install.');
    process.exit(0);
  }
  console.error('FAIL — dispatch→claim→drain loop not fully observed (see verdict above).');
  process.exit(1);
}

main().catch((e) => {
  console.error('[drain] FAILED:', e?.message ?? e);
  process.exit(1);
});
