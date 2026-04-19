import { supabase } from '../../../backend/src/lib/supabase';
import { startAiderMachine, stopFlyMachine, AIDER_CONFIG } from './fly-machines';
import { Redis } from '@upstash/redis';

// ---------- Types ----------

export type FixStrategy =
  | 'bump_version'
  | 'code_patch'
  | 'add_wrapper'
  | 'pin_transitive'
  | 'remove_unused'
  | 'fix_semgrep'
  | 'remediate_secret';

export type FixType = 'vulnerability' | 'semgrep' | 'secret';

export interface FixRequest {
  projectId: string;
  organizationId: string;
  userId: string;
  strategy: FixStrategy;
  vulnerabilityOsvId?: string;
  dependencyId?: string;
  projectDependencyId?: string;
  targetVersion?: string;
  semgrepFindingId?: string;
  secretFindingId?: string;
}

export interface FixJobRow {
  id: string;
  project_id: string;
  organization_id: string;
  run_id: string;
  fix_type: FixType;
  strategy: FixStrategy;
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
  validation_result: Record<string, any> | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface ExistingFixCheck {
  hasActiveFix?: boolean;
  hasCompletedFix?: boolean;
  canProceed?: boolean;
  fix?: FixJobRow;
  message?: string;
}

// ---------- Redis ----------

let redisClient: Redis | null = null;

function getRedis(): Redis | null {
  if (!redisClient) {
    const url = process.env.UPSTASH_REDIS_URL;
    const token = process.env.UPSTASH_REDIS_TOKEN;
    if (!url || !token) return null;
    redisClient = new Redis({ url, token });
  }
  return redisClient;
}

// ---------- Budget ----------

export async function checkAndReserveBudget(orgId: string, estimatedCost: number): Promise<boolean> {
  const redis = getRedis();
  if (!redis) return true;

  const now = new Date();
  const key = `ai:cost:${orgId}:${now.getFullYear()}:${now.getMonth() + 1}`;
  const estimatedCents = Math.ceil(estimatedCost * 100);

  const { data: provider } = await supabase
    .from('organization_ai_providers')
    .select('monthly_cost_cap')
    .eq('organization_id', orgId)
    .eq('is_default', true)
    .single();

  const capCents = Math.floor((provider?.monthly_cost_cap ?? 100) * 100);

  try {
    const newTotal = await redis.incrby(key, estimatedCents);
    if (newTotal === estimatedCents) {
      await redis.expire(key, 35 * 24 * 60 * 60);
    }
    if (newTotal > capCents) {
      await redis.decrby(key, estimatedCents);
      return false;
    }
    return true;
  } catch {
    return true;
  }
}

// ---------- Duplicate detection ----------

export async function checkExistingFix(
  projectId: string,
  target: { type: FixType; osvId?: string; semgrepFindingId?: string; secretFindingId?: string },
): Promise<ExistingFixCheck> {
  const matchFilter =
    target.type === 'vulnerability' ? { osv_id: target.osvId } :
    target.type === 'semgrep' ? { semgrep_finding_id: target.semgrepFindingId } :
    { secret_finding_id: target.secretFindingId };

  const { data: activeFix } = await supabase
    .from('project_security_fixes')
    .select('*')
    .eq('project_id', projectId)
    .in('status', ['queued', 'running'])
    .match(matchFilter)
    .maybeSingle();

  if (activeFix) {
    const timeAgo = activeFix.started_at
      ? `${Math.round((Date.now() - new Date(activeFix.started_at).getTime()) / 60000)}m ago`
      : 'just queued';
    return {
      hasActiveFix: true,
      fix: activeFix,
      message: `This ${target.type} is already being fixed. Status: ${activeFix.status} (started ${timeAgo}).`,
    };
  }

  const { data: completedFix } = await supabase
    .from('project_security_fixes')
    .select('*')
    .eq('project_id', projectId)
    .eq('status', 'completed')
    .not('pr_url', 'is', null)
    .match(matchFilter)
    .order('completed_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (completedFix) {
    return {
      hasCompletedFix: true,
      fix: completedFix,
      message: `A fix PR already exists: PR #${completedFix.pr_number}. Merge it to resolve, or close and retry.`,
    };
  }

  return { canProceed: true };
}

// ---------- Max attempts guard ----------

async function checkMaxAttempts(
  projectId: string,
  target: { osvId?: string; semgrepFindingId?: string; secretFindingId?: string },
): Promise<{ blocked: boolean; count: number }> {
  const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  let query = supabase
    .from('project_security_fixes')
    .select('id', { count: 'exact' })
    .eq('project_id', projectId)
    .eq('status', 'failed')
    .gte('created_at', twentyFourHoursAgo);

  if (target.osvId) query = query.eq('osv_id', target.osvId);
  if (target.semgrepFindingId) query = query.eq('semgrep_finding_id', target.semgrepFindingId);
  if (target.secretFindingId) query = query.eq('secret_finding_id', target.secretFindingId);

  const { count } = await query;
  return { blocked: (count ?? 0) >= 3, count: count ?? 0 };
}

// ---------- Context gathering ----------

async function gatherVulnerabilityContext(req: FixRequest): Promise<Record<string, any>> {
  const ctx: Record<string, any> = {};

  if (req.vulnerabilityOsvId) {
    const { data: vuln } = await supabase
      .from('dependency_vulnerabilities')
      .select('osv_id, severity, summary, details, affected_versions, fixed_versions, references')
      .eq('osv_id', req.vulnerabilityOsvId)
      .single();
    if (vuln) ctx.vulnerability = vuln;
  }

  if (req.projectDependencyId) {
    const { data: pd } = await supabase
      .from('project_dependencies')
      .select('id, version, is_direct, source, environment, files_importing_count, dependencies!inner(name, ecosystem, latest_version)')
      .eq('id', req.projectDependencyId)
      .single();
    if (pd) {
      ctx.dependency = {
        name: (pd as any).dependencies?.name,
        ecosystem: (pd as any).dependencies?.ecosystem,
        currentVersion: pd.version,
        isDirect: pd.is_direct,
        latestVersion: (pd as any).dependencies?.latest_version,
        filesImporting: pd.files_importing_count,
      };
    }

    const { data: flows } = await supabase
      .from('project_reachable_flows')
      .select('entry_point_file, entry_point_line, entry_point_method, sink_method, flow_nodes, llm_prompt')
      .eq('project_id', req.projectId)
      .eq('dependency_id', req.dependencyId!)
      .limit(5);
    if (flows?.length) ctx.reachableFlows = flows;

    const { data: slices } = await supabase
      .from('project_usage_slices')
      .select('file_path, line_number, target_name, resolved_method, target_type')
      .eq('project_id', req.projectId)
      .limit(20);
    if (slices?.length) ctx.usageSlices = slices;

    const { data: files } = await supabase
      .from('project_dependency_files')
      .select('file_path')
      .eq('project_dependency_id', req.projectDependencyId)
      .limit(30);
    if (files?.length) ctx.importingFiles = files.map((f: any) => f.file_path);

    const { data: fns } = await supabase
      .from('project_dependency_functions')
      .select('function_name, import_type')
      .eq('project_dependency_id', req.projectDependencyId)
      .limit(30);
    if (fns?.length) ctx.importedFunctions = fns;
  }

  return ctx;
}

async function gatherSemgrepContext(findingId: string): Promise<Record<string, any>> {
  const { data } = await supabase
    .from('project_semgrep_findings')
    .select('rule_id, severity, message, path, line_start, line_end, category, cwe_ids')
    .eq('id', findingId)
    .single();
  return data ? { semgrepFinding: data } : {};
}

async function gatherSecretContext(findingId: string): Promise<Record<string, any>> {
  const { data } = await supabase
    .from('project_secret_findings')
    .select('detector_type, file_path, line_number, verified')
    .eq('id', findingId)
    .single();
  return data ? { secretFinding: data } : {};
}

// ---------- Main orchestrator ----------

export async function requestFix(req: FixRequest): Promise<{ success: boolean; jobId?: string; error?: string; errorCode?: string }> {
  // 1. Validate project has a connected repo
  const { data: repo } = await supabase
    .from('project_repositories')
    .select('id, repo_full_name, default_branch, provider, integration_id, status')
    .eq('project_id', req.projectId)
    .single();

  if (!repo || repo.status === 'not_connected') {
    return { success: false, error: 'Project has no connected repository', errorCode: 'NO_REPO' };
  }

  // 2. Validate org has BYOK
  const { data: aiProvider } = await supabase
    .from('organization_ai_providers')
    .select('id, provider, model_preference, monthly_cost_cap')
    .eq('organization_id', req.organizationId)
    .eq('is_default', true)
    .maybeSingle();

  if (!aiProvider) {
    return { success: false, error: 'No AI provider configured. Set up in Organization Settings > AI Configuration.', errorCode: 'NO_BYOK' };
  }

  // 3. Determine fix type
  const fixType: FixType = req.semgrepFindingId ? 'semgrep' : req.secretFindingId ? 'secret' : 'vulnerability';

  // 4. Check duplicates
  const existing = await checkExistingFix(req.projectId, {
    type: fixType,
    osvId: req.vulnerabilityOsvId,
    semgrepFindingId: req.semgrepFindingId,
    secretFindingId: req.secretFindingId,
  });
  if (existing.hasActiveFix) {
    return { success: false, error: existing.message, errorCode: 'DUPLICATE_ACTIVE' };
  }

  // 5. Max attempts guard
  const attempts = await checkMaxAttempts(req.projectId, {
    osvId: req.vulnerabilityOsvId,
    semgrepFindingId: req.semgrepFindingId,
    secretFindingId: req.secretFindingId,
  });
  if (attempts.blocked) {
    return { success: false, error: `${attempts.count} fix attempts failed in 24 hours. Manual intervention required.`, errorCode: 'MAX_ATTEMPTS' };
  }

  // 6. Budget check (estimate ~$0.20 per fix)
  const estimatedCost = 0.20;
  const budgetOk = await checkAndReserveBudget(req.organizationId, estimatedCost);
  if (!budgetOk) {
    return { success: false, error: 'Monthly AI budget exceeded. An admin can increase the limit in Organization Settings.', errorCode: 'BUDGET_EXCEEDED' };
  }

  // 7. Gather context
  let context: Record<string, any> = {};
  if (fixType === 'vulnerability') {
    context = await gatherVulnerabilityContext(req);
  } else if (fixType === 'semgrep' && req.semgrepFindingId) {
    context = await gatherSemgrepContext(req.semgrepFindingId);
  } else if (fixType === 'secret' && req.secretFindingId) {
    context = await gatherSecretContext(req.secretFindingId);
  }

  // 8. Build payload (NO secrets)
  const { data: project } = await supabase
    .from('projects')
    .select('name, root_directory')
    .eq('id', req.projectId)
    .single();

  const payload = {
    ...context,
    repo: {
      fullName: repo.repo_full_name,
      defaultBranch: repo.default_branch || 'main',
      provider: repo.provider || 'github',
      integrationId: repo.integration_id,
      rootDirectory: project?.root_directory || '',
    },
    aiProvider: aiProvider.provider,
    aiModel: aiProvider.model_preference,
    estimatedCost,
  };

  // 9. Queue via RPC
  try {
    const { data: jobId, error: rpcError } = await supabase.rpc('queue_fix_job', {
      p_project_id: req.projectId,
      p_organization_id: req.organizationId,
      p_fix_type: fixType,
      p_strategy: req.strategy,
      p_triggered_by: req.userId,
      p_osv_id: req.vulnerabilityOsvId || null,
      p_dependency_id: req.dependencyId || null,
      p_project_dependency_id: req.projectDependencyId || null,
      p_semgrep_finding_id: req.semgrepFindingId || null,
      p_secret_finding_id: req.secretFindingId || null,
      p_target_version: req.targetVersion || null,
      p_payload: payload,
    });

    if (rpcError) {
      if (rpcError.message?.includes('MAX_CONCURRENT_FIXES')) {
        return { success: false, error: 'Organization has reached the maximum of 5 concurrent fix jobs. Wait for one to complete.', errorCode: 'MAX_CONCURRENT' };
      }
      return { success: false, error: rpcError.message };
    }

    // 10. Start Fly machine (best-effort)
    try {
      await startAiderMachine();
    } catch (e: any) {
      console.warn(`[FIX] Failed to start Aider machine (job stays queued): ${e.message}`);
    }

    return { success: true, jobId: jobId as string };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
}

// ---------- Cancellation ----------

export async function cancelFixJob(jobId: string, userId: string): Promise<{ success: boolean; error?: string }> {
  const { data: job } = await supabase
    .from('project_security_fixes')
    .select('id, status, machine_id')
    .eq('id', jobId)
    .single();

  if (!job || !['queued', 'running'].includes(job.status)) {
    return { success: false, error: 'No active fix job found' };
  }

  await supabase
    .from('project_security_fixes')
    .update({ status: 'cancelled', completed_at: new Date().toISOString() })
    .eq('id', jobId);

  if (job.status === 'running' && job.machine_id) {
    try {
      await stopFlyMachine(AIDER_CONFIG.app, job.machine_id);
    } catch {
      // best-effort
    }
  }

  return { success: true };
}

// ---------- Status queries ----------

export async function getFixStatus(projectId: string): Promise<FixJobRow[]> {
  const { data } = await supabase
    .from('project_security_fixes')
    .select('*')
    .eq('project_id', projectId)
    .in('status', ['queued', 'running', 'completed', 'failed'])
    .order('created_at', { ascending: false })
    .limit(20);
  return (data || []) as FixJobRow[];
}

export async function getFixesForOrg(orgId: string): Promise<FixJobRow[]> {
  const { data } = await supabase
    .from('project_security_fixes')
    .select('*')
    .eq('organization_id', orgId)
    .in('status', ['queued', 'running'])
    .order('created_at', { ascending: false })
    .limit(50);
  return (data || []) as FixJobRow[];
}

export async function getFixHistory(projectId: string, target: {
  osvId?: string;
  semgrepFindingId?: string;
  secretFindingId?: string;
}): Promise<FixJobRow[]> {
  let query = supabase
    .from('project_security_fixes')
    .select('*')
    .eq('project_id', projectId)
    .order('created_at', { ascending: false })
    .limit(10);

  if (target.osvId) query = query.eq('osv_id', target.osvId);
  if (target.semgrepFindingId) query = query.eq('semgrep_finding_id', target.semgrepFindingId);
  if (target.secretFindingId) query = query.eq('secret_finding_id', target.secretFindingId);

  const { data } = await query;
  return (data || []) as FixJobRow[];
}
