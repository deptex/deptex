import { SupabaseClient } from '@supabase/supabase-js';

export interface FixJobRow {
  id: string;
  project_id: string;
  organization_id: string;
  run_id: string;
  fix_type: string;
  strategy: string;
  status: string;
  triggered_by: string;
  osv_id: string | null;
  dependency_id: string | null;
  project_dependency_id: string | null;
  semgrep_finding_id: string | null;
  secret_finding_id: string | null;
  target_version: string | null;
  payload: Record<string, any>;
  machine_id: string | null;
  heartbeat_at: string | null;
  attempts: number;
  max_attempts: number;
  pr_url: string | null;
  pr_number: number | null;
  pr_branch: string | null;
  diff_summary: string | null;
  tokens_used: number | null;
  estimated_cost: number | null;
  error_message: string | null;
  error_category: string | null;
  introduced_vulns: string[] | null;
  validation_result: Record<string, unknown> | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export async function claimJob(supabase: SupabaseClient, machineId: string): Promise<FixJobRow | null> {
  const { data, error } = await supabase.rpc('claim_fix_job', { p_machine_id: machineId });
  if (error) {
    console.error('[AIDER] Failed to claim job:', error.message);
    return null;
  }
  const rows = Array.isArray(data) ? data : data ? [data] : [];
  return rows.length > 0 ? (rows[0] as FixJobRow) : null;
}

export async function sendHeartbeat(supabase: SupabaseClient, jobId: string): Promise<void> {
  await supabase
    .from('project_security_fixes')
    .update({ heartbeat_at: new Date().toISOString() })
    .eq('id', jobId);
}

export async function updateJobStatus(
  supabase: SupabaseClient,
  jobId: string,
  status: string,
  updates: Record<string, any> = {},
): Promise<void> {
  const data: Record<string, any> = { status, ...updates };
  if (['completed', 'failed', 'cancelled'].includes(status)) {
    data.completed_at = new Date().toISOString();
  }
  await supabase
    .from('project_security_fixes')
    .update(data)
    .eq('id', jobId);
}

export async function isJobCancelled(supabase: SupabaseClient, jobId: string): Promise<boolean> {
  const { data } = await supabase
    .from('project_security_fixes')
    .select('status')
    .eq('id', jobId)
    .single();
  return data?.status === 'cancelled';
}
