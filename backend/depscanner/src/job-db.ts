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
    types.push('dast', 'dast_zap', 'dast_nuclei');
  }
  return types;
}

export async function claimJob(
  supabase: Storage,
  machineId: string,
  supportedTypes: string[] = getSupportedJobTypes(),
): Promise<ExtractionJobRow | null> {
  const { data, error } = await supabase.rpc('claim_scan_job', {
    p_machine_id: machineId,
    p_supported_types: supportedTypes,
  });

  if (error) {
    console.error('[EXTRACT] Failed to claim job:', error.message);
    return null;
  }

  if (!data || (Array.isArray(data) && data.length === 0)) {
    return null;
  }

  return Array.isArray(data) ? data[0] : data;
}

export async function updateJobStatus(
  supabase: Storage,
  jobId: string,
  status: 'completed' | 'failed',
  error?: string
): Promise<void> {
  await supabase
    .from('scan_jobs')
    .update({
      status,
      error: error ?? null,
      completed_at: new Date().toISOString(),
    })
    .eq('id', jobId);
}

export async function sendHeartbeat(
  supabase: Storage,
  jobId: string
): Promise<void> {
  await supabase
    .from('scan_jobs')
    .update({ heartbeat_at: new Date().toISOString() })
    .eq('id', jobId);
}

export async function isJobCancelled(
  supabase: Storage,
  jobId: string
): Promise<boolean> {
  const { data } = await supabase
    .from('scan_jobs')
    .select('status')
    .eq('id', jobId)
    .single();
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
