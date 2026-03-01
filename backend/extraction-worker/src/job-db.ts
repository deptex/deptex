import { SupabaseClient } from '@supabase/supabase-js';

export interface ExtractionJobRow {
  id: string;
  project_id: string;
  organization_id: string;
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

export async function claimJob(
  supabase: SupabaseClient,
  machineId: string
): Promise<ExtractionJobRow | null> {
  const { data, error } = await supabase.rpc('claim_extraction_job', {
    p_machine_id: machineId,
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
  supabase: SupabaseClient,
  jobId: string,
  status: 'completed' | 'failed',
  error?: string
): Promise<void> {
  await supabase
    .from('extraction_jobs')
    .update({
      status,
      error: error ?? null,
      completed_at: new Date().toISOString(),
    })
    .eq('id', jobId);
}

export async function sendHeartbeat(
  supabase: SupabaseClient,
  jobId: string
): Promise<void> {
  await supabase
    .from('extraction_jobs')
    .update({ heartbeat_at: new Date().toISOString() })
    .eq('id', jobId);
}

export async function isJobCancelled(
  supabase: SupabaseClient,
  jobId: string
): Promise<boolean> {
  const { data } = await supabase
    .from('extraction_jobs')
    .select('status')
    .eq('id', jobId)
    .single();
  return data?.status === 'cancelled';
}
