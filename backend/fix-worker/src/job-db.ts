import type { SupabaseClient } from '@supabase/supabase-js';
import type { FixPlan } from './plan-types';

export interface FixJobRow {
  id: string;
  project_id: string;
  organization_id: string;
  payload: Record<string, unknown>;
  plan: FixPlan;
  attempts: number;
}

interface FullFixRow {
  id: string;
  project_id: string;
  organization_id: string;
  fix_type: string;
  strategy: string;
  status: string;
  run_id: string;
  plan: FixPlan | null;
  plan_base_sha: string | null;
  plan_base_branch: string | null;
  payload: Record<string, unknown>;
  attempts: number;
  osv_id: string | null;
  semgrep_finding_id: string | null;
  secret_finding_id: string | null;
}

export async function claimJob(
  supabase: SupabaseClient,
  machineId: string,
): Promise<FixJobRow | null> {
  const { data, error } = await supabase.rpc('claim_fix_job', {
    p_machine_id: machineId,
  });
  if (error) {
    console.error('[FIX] Failed to claim job:', error.message);
    return null;
  }
  if (!data || (Array.isArray(data) && data.length === 0)) return null;
  const row = Array.isArray(data) ? data[0] : data;
  if (!row?.plan) return null;
  return row as FixJobRow;
}

export async function loadFullRow(
  supabase: SupabaseClient,
  fixId: string,
): Promise<FullFixRow | null> {
  const { data } = await supabase
    .from('project_security_fixes')
    .select(
      'id, project_id, organization_id, fix_type, strategy, status, run_id, plan, plan_base_sha, plan_base_branch, payload, attempts, osv_id, semgrep_finding_id, secret_finding_id',
    )
    .eq('id', fixId)
    .maybeSingle();
  return (data as FullFixRow | null) ?? null;
}

export async function sendHeartbeat(supabase: SupabaseClient, fixId: string) {
  await supabase
    .from('project_security_fixes')
    .update({ heartbeat_at: new Date().toISOString() })
    .eq('id', fixId);
}

export async function markCompleted(
  supabase: SupabaseClient,
  fixId: string,
  result: {
    prUrl: string;
    prNumber: number;
    prBranch: string;
    prRepoFullName: string;
    diffSummary: string;
    tokensUsed?: number;
    estimatedCost?: number;
  },
) {
  await supabase
    .from('project_security_fixes')
    .update({
      status: 'completed',
      pr_url: result.prUrl,
      pr_number: result.prNumber,
      pr_branch: result.prBranch,
      pr_provider: 'github',
      pr_repo_full_name: result.prRepoFullName,
      diff_summary: result.diffSummary,
      tokens_used: result.tokensUsed ?? null,
      estimated_cost: result.estimatedCost ?? null,
      completed_at: new Date().toISOString(),
    })
    .eq('id', fixId);
}

export async function markFailed(
  supabase: SupabaseClient,
  fixId: string,
  errorMessage: string,
  errorCategory?: string,
) {
  await supabase
    .from('project_security_fixes')
    .update({
      status: 'failed',
      error_message: errorMessage,
      error_category: errorCategory ?? null,
      completed_at: new Date().toISOString(),
    })
    .eq('id', fixId);
}

export async function isJobCancelled(supabase: SupabaseClient, fixId: string): Promise<boolean> {
  const { data } = await supabase
    .from('project_security_fixes')
    .select('status')
    .eq('id', fixId)
    .maybeSingle();
  return data?.status === 'rejected';
}

export async function getOrgInstallationId(
  supabase: SupabaseClient,
  organizationId: string,
  projectId: string,
): Promise<{ installationId: string; repoFullName: string } | null> {
  const { data: repo } = await supabase
    .from('project_repositories')
    .select('repo_full_name, installation_id')
    .eq('project_id', projectId)
    .maybeSingle();
  if (!repo?.repo_full_name) return null;

  if (repo.installation_id) {
    return { installationId: repo.installation_id as string, repoFullName: repo.repo_full_name };
  }

  const { data: org } = await supabase
    .from('organizations')
    .select('github_installation_id')
    .eq('id', organizationId)
    .single();
  if (!org?.github_installation_id) return null;
  return { installationId: org.github_installation_id as string, repoFullName: repo.repo_full_name };
}
