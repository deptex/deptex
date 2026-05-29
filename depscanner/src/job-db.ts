import type { Storage } from './storage';

export interface ExtractionJobRow {
  id: string;
  project_id: string;
  organization_id: string;
  type: string;
  status: string;
  run_id: string;
  machine_id: string | null;
  payload: Record<string, unknown>;
  attempts: number;
  max_attempts: number;
  error: string | null;
  started_at: string | null;
  heartbeat_at: string | null;
  completed_at: string | null;
  created_at: string;
}

// PR 2: depscanner accepts both extraction and dast. The dast pipeline ships in PR 3;
// PR 2 has a stub that fails fast so the queue path can be exercised end-to-end.
//
// Phase 24a (v2.1a) introduces a startup probe: when DAST_CREDENTIAL_KEY is
// absent the worker MUST NOT claim DAST jobs (see plan §Task 7 acceptance —
// silent-anonymous-fallback is the non-negotiable invariant). The supported-
// types list is derived from the env at process start; flipping the key on
// requires a worker restart to pick up.
export function getSupportedJobTypes(): string[] {
  const types: string[] = ['extraction'];
  if (process.env.DAST_CREDENTIAL_KEY) {
    types.push('dast', 'dast_zap', 'dast_nuclei', 'dast_zap_dry_run');
  }
  // The fleet provisioner stamps each machine with SCAN_TYPE at create time.
  // When set, the machine only claims jobs of that kind — so an extraction-
  // shaped (64GB) machine never claims a small dast job, and a dast-shaped
  // (16GB) machine never claims a 64GB extraction job (which would OOM). Both
  // kinds share the single `deptex-depscanner` Fly app, so this intersection is
  // what keeps them from poaching each other's work. Untagged machines (legacy
  // / local dev) keep the previous behaviour of claiming anything they support.
  const scanType = process.env.SCAN_TYPE?.trim();
  if (scanType === 'extraction') return ['extraction'];
  if (scanType === 'dast') return types.filter((t) => t.startsWith('dast'));
  return types;
}

export async function claimJob(
  supabase: Storage,
  machineId: string,
  supportedTypes: string[] = getSupportedJobTypes(),
): Promise<ExtractionJobRow | null> {
  // Per-org in-flight cap so one tenant can't monopolize the fleet. Parse
  // defensively: a Fly secret that is empty ('') or non-numeric ('abc') must
  // NOT become 0 or NaN→null — either would make the RPC's `(count) < cap`
  // condition never true and silently halt ALL claiming. Mirror the dispatcher's
  // parseInt(... || '5') + finite/positive guard.
  const parsedCap = parseInt(process.env.FLY_MAX_PER_ORG || '5', 10);
  const maxPerOrg = Number.isFinite(parsedCap) && parsedCap > 0 ? parsedCap : 5;
  const { data, error } = await supabase.rpc('claim_scan_job', {
    p_machine_id: machineId,
    p_supported_types: supportedTypes,
    p_max_per_org: maxPerOrg,
  });

  // A claim RPC error (e.g. Supabase outage) is NOT "no job available" —
  // throw so the caller can retry without counting it as idle time.
  if (error) {
    throw new Error(`claim_scan_job failed: ${error.message}`);
  }

  if (!data || (Array.isArray(data) && data.length === 0)) {
    return null;
  }

  return Array.isArray(data) ? data[0] : data;
}

/**
 * Updates the terminal status of a job, guarded by machine_id + run_id so a
 * slow-but-alive original machine cannot clobber a recovered/re-queued attempt.
 * Returns true when exactly the expected (this-machine, this-run) row was
 * updated; false means the claim was revoked (cancelled/recovered) — the caller
 * must stop and not overwrite. Retries once if the update query itself errors.
 *
 * `machineId`/`runId` are optional: the worker control loop always passes them
 * to get the ownership guard; in-pipeline callers (finalize, dast) that already
 * own their write path may omit them for an unguarded update.
 */
export async function updateJobStatus(
  supabase: Storage,
  jobId: string,
  machineId: string | null | undefined,
  runId: string | null | undefined,
  status: 'completed' | 'failed',
  error?: string
): Promise<boolean> {
  const apply = async () => {
    let q = supabase
      .from('scan_jobs')
      .update({
        status,
        error: error ?? null,
        completed_at: new Date().toISOString(),
      })
      .eq('id', jobId);
    if (machineId != null) q = q.eq('machine_id', machineId);
    if (runId != null) q = q.eq('run_id', runId);
    return q.select('id');
  };

  let { data, error: updErr } = await apply();
  if (updErr) {
    console.error(`[EXTRACT] updateJobStatus failed for ${jobId}, retrying: ${updErr.message}`);
    ({ data, error: updErr } = await apply());
    if (updErr) {
      console.error(`[EXTRACT] updateJobStatus retry failed for ${jobId}: ${updErr.message}`);
      return false;
    }
  }
  return Array.isArray(data) && data.length > 0;
}

/**
 * Writes a heartbeat, guarded by machine_id + run_id when supplied. Returns
 * false when the guarded update affects 0 rows (claim revoked) so the caller
 * can stop.
 */
export async function sendHeartbeat(
  supabase: Storage,
  jobId: string,
  machineId?: string | null,
  runId?: string | null
): Promise<boolean> {
  let q = supabase
    .from('scan_jobs')
    .update({ heartbeat_at: new Date().toISOString() })
    .eq('id', jobId);
  if (machineId != null) q = q.eq('machine_id', machineId);
  if (runId != null) q = q.eq('run_id', runId);
  const { data, error } = await q.select('id');
  if (error) {
    console.error(`[EXTRACT] sendHeartbeat failed for ${jobId}: ${error.message}`);
    return true; // transient query error — do not signal a revoked claim
  }
  return Array.isArray(data) && data.length > 0;
}

/**
 * Checks whether a job has been cancelled. A transient query error must not
 * read as "not cancelled" (that would let a cancelled job run to completion),
 * so on error we return `lastKnown` — the previous known value.
 */
export async function isJobCancelled(
  supabase: Storage,
  jobId: string,
  lastKnown = false
): Promise<boolean> {
  const { data, error } = await supabase
    .from('scan_jobs')
    .select('status')
    .eq('id', jobId)
    .single();
  if (error) {
    console.error(`[EXTRACT] isJobCancelled query failed for ${jobId}: ${error.message}`);
    return lastKnown;
  }
  return data?.status === 'cancelled';
}

/**
 * Merge commit_sha, commit_message, branch into job payload only when not already set
 * (e.g. webhook may have set them; worker fills them after clone for manual/initial runs).
 */
export async function updateJobPayloadCommit(
  supabase: Storage,
  jobId: string,
  commit: { commit_sha: string; commit_message?: string; branch?: string }
): Promise<void> {
  const { data, error: fetchError } = await supabase
    .from('scan_jobs')
    .select('payload')
    .eq('id', jobId)
    .single();

  if (fetchError || !data?.payload) return;

  const payload = data.payload as Record<string, unknown>;
  if (payload.commit_sha) return;

  const merged = {
    ...payload,
    commit_sha: commit.commit_sha,
    ...(commit.commit_message != null && { commit_message: commit.commit_message }),
    ...(commit.branch != null && { branch: commit.branch }),
  };

  await supabase
    .from('scan_jobs')
    .update({ payload: merged })
    .eq('id', jobId);
}
