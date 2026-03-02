import { supabase } from '../../../../backend/src/lib/supabase';
import { normalizeStrategy } from './strategy-constants';
import { recomputePatterns } from './pattern-engine';

const CWE_TO_VULN_TYPE: Record<string, string> = {
  'CWE-79': 'xss',
  'CWE-89': 'sql-injection',
  'CWE-1321': 'prototype-pollution',
  'CWE-22': 'path-traversal',
  'CWE-78': 'command-injection',
  'CWE-502': 'deserialization',
  'CWE-918': 'ssrf',
  'CWE-287': 'auth-bypass',
  'CWE-200': 'information-disclosure',
  'CWE-400': 'denial-of-service',
  'CWE-77': 'code-injection',
  'CWE-611': 'xxe',
  'CWE-352': 'csrf',
  'CWE-601': 'open-redirect',
  'CWE-94': 'code-injection',
  'CWE-362': 'race-condition',
  'CWE-863': 'authorization-bypass',
  'CWE-798': 'hardcoded-credentials',
  'CWE-327': 'weak-crypto',
  'CWE-295': 'improper-cert-validation',
  'CWE-190': 'integer-overflow',
  'CWE-416': 'use-after-free',
  'CWE-120': 'buffer-overflow',
};

export function mapCweToVulnType(cweIds: string[]): { vulnType: string | null; cweId: string | null } {
  for (const cwe of cweIds) {
    const mapped = CWE_TO_VULN_TYPE[cwe];
    if (mapped) return { vulnType: mapped, cweId: cwe };
  }
  return { vulnType: null, cweId: cweIds[0] || null };
}

export function categorizeFailure(errorCategory: string | null, errorMessage: string | null): string {
  if (errorCategory === 'no_changes') return 'empty_diff';
  if (errorCategory === 'auth_failed') return 'auth_failed';
  if (errorCategory === 'pr_creation_failed') return 'pr_creation_failed';
  if (errorCategory === 'timeout') return 'timeout';
  if (errorMessage?.match(/npm ERR!|yarn error|pnpm ERR|build.*fail/i)) return 'build_error';
  if (errorMessage?.match(/test.*fail|jest.*fail|mocha.*fail/i)) return 'test_failure';
  if (errorMessage?.match(/no.*safe.*version|no.*patched/i)) return 'no_safe_version';
  if (errorMessage?.match(/breaking.*change|major.*version/i)) return 'breaking_changes';
  if (errorMessage?.match(/rate.*limit|429|quota/i)) return 'api_error';
  return 'unknown';
}

function parseDiffStats(diffSummary: string | null): { filesChanged: number; linesAdded: number; linesRemoved: number } {
  if (!diffSummary) return { filesChanged: 0, linesAdded: 0, linesRemoved: 0 };
  const filesMatch = diffSummary.match(/(\d+)\s*files?\s*changed/i);
  const addMatch = diffSummary.match(/(\d+)\s*insertions?/i);
  const delMatch = diffSummary.match(/(\d+)\s*deletions?/i);
  return {
    filesChanged: filesMatch ? parseInt(filesMatch[1], 10) : 0,
    linesAdded: addMatch ? parseInt(addMatch[1], 10) : 0,
    linesRemoved: delMatch ? parseInt(delMatch[1], 10) : 0,
  };
}

export async function recordOutcomeFromFixJob(fixJobId: string): Promise<string | null> {
  const { data: existing } = await supabase
    .from('fix_outcomes')
    .select('id')
    .eq('fix_job_id', fixJobId)
    .maybeSingle();

  if (existing) return existing.id;

  const { data: job } = await supabase
    .from('project_security_fixes')
    .select('*')
    .eq('id', fixJobId)
    .single();

  if (!job) return null;
  if (!['completed', 'failed'].includes(job.status)) return null;

  const success = job.status === 'completed' && !job.error_category;

  let ecosystem = job.payload?.dependency?.ecosystem || 'npm';
  let framework: string | null = null;
  let packageName: string | null = job.payload?.dependency?.name || null;
  let isDirect: boolean | null = null;
  let hasReachabilityData = false;
  let reachabilityLevel: string | null = null;
  let vulnType: string | null = null;
  let cweId: string | null = null;
  let severity: string | null = null;

  if (job.project_id) {
    const { data: project } = await supabase
      .from('projects')
      .select('framework')
      .eq('id', job.project_id)
      .single();
    framework = project?.framework || null;
  }

  if (job.osv_id && job.dependency_id) {
    const { data: vuln } = await supabase
      .from('dependency_vulnerabilities')
      .select('severity, cwe_ids')
      .eq('dependency_id', job.dependency_id)
      .eq('osv_id', job.osv_id)
      .maybeSingle();

    if (vuln) {
      severity = vuln.severity;
      const cweMapping = mapCweToVulnType(vuln.cwe_ids || []);
      vulnType = cweMapping.vulnType;
      cweId = cweMapping.cweId;
    }

    if (job.project_dependency_id) {
      const { data: pd } = await supabase
        .from('project_dependencies')
        .select('is_direct')
        .eq('id', job.project_dependency_id)
        .maybeSingle();
      isDirect = pd?.is_direct ?? null;

      const { data: pdv } = await supabase
        .from('project_dependency_vulnerabilities')
        .select('reachability_level, is_reachable')
        .eq('project_dependency_id', job.project_dependency_id)
        .eq('osv_id', job.osv_id)
        .maybeSingle();

      if (pdv) {
        hasReachabilityData = !!pdv.reachability_level || !!pdv.is_reachable;
        reachabilityLevel = pdv.reachability_level || null;
      }
    }
  }

  const diffStats = parseDiffStats(job.diff_summary);
  const durationSeconds = job.started_at && job.completed_at
    ? Math.round((new Date(job.completed_at).getTime() - new Date(job.started_at).getTime()) / 1000)
    : null;

  let previousAttemptId: string | null = null;
  if (job.osv_id && job.project_id) {
    const { data: prev } = await supabase
      .from('fix_outcomes')
      .select('id')
      .eq('organization_id', job.organization_id)
      .eq('project_id', job.project_id)
      .neq('fix_job_id', fixJobId)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    previousAttemptId = prev?.id || null;
  }

  const { data: outcome, error } = await supabase
    .from('fix_outcomes')
    .insert({
      organization_id: job.organization_id,
      fix_job_id: fixJobId,
      project_id: job.project_id,
      fix_type: job.fix_type,
      strategy: normalizeStrategy(job.strategy),
      ecosystem,
      framework,
      vulnerability_type: vulnType,
      cwe_id: cweId,
      severity,
      package_name: packageName,
      is_direct_dep: isDirect,
      has_reachability_data: hasReachabilityData,
      reachability_level: reachabilityLevel,
      provider: job.pr_provider || 'github',
      success,
      failure_reason: success ? null : categorizeFailure(job.error_category, job.error_message),
      failure_detail: success ? null : (job.error_message || '').slice(0, 2000),
      duration_seconds: durationSeconds,
      tokens_used: job.tokens_used,
      estimated_cost: job.estimated_cost,
      files_changed: diffStats.filesChanged,
      lines_added: diffStats.linesAdded,
      lines_removed: diffStats.linesRemoved,
      previous_attempt_id: previousAttemptId,
    })
    .select('id')
    .single();

  if (error) {
    console.error('[learning] Failed to record outcome:', error.message);
    return null;
  }

  if (previousAttemptId) {
    await supabase
      .from('fix_outcomes')
      .update({ led_to_strategy: normalizeStrategy(job.strategy) })
      .eq('id', previousAttemptId);
  }

  try {
    await recomputePatterns(job.organization_id);
  } catch (e) {
    console.warn('[learning] Pattern recomputation failed (non-fatal):', (e as Error).message);
  }

  return outcome?.id || null;
}

export async function updateOutcomeOnMerge(
  projectId: string,
  prNumber: number,
  provider: string,
  isMerged: boolean,
  mergedAt?: string,
): Promise<void> {
  const { data: fixJob } = await supabase
    .from('project_security_fixes')
    .select('id')
    .eq('project_id', projectId)
    .eq('pr_number', prNumber)
    .eq('pr_provider', provider)
    .maybeSingle();

  if (!fixJob) return;

  const updates: Record<string, any> = {};
  if (isMerged) {
    updates.pr_merged = true;
    updates.pr_merged_at = mergedAt || new Date().toISOString();
  } else {
    updates.pr_merged = false;
  }

  await supabase
    .from('fix_outcomes')
    .update(updates)
    .eq('fix_job_id', fixJob.id);
}

export async function markOutcomeReverted(fixJobId: string): Promise<void> {
  await supabase
    .from('fix_outcomes')
    .update({ fix_reverted: true })
    .eq('fix_job_id', fixJobId);
}

export async function backfillMissingOutcomes(): Promise<number> {
  const { data: jobs } = await supabase
    .from('project_security_fixes')
    .select('id')
    .in('status', ['completed', 'failed', 'merged', 'pr_closed'])
    .not('id', 'in', supabase.from('fix_outcomes').select('fix_job_id'))
    .limit(200);

  if (!jobs || jobs.length === 0) return 0;

  let count = 0;
  for (const job of jobs) {
    const id = await recordOutcomeFromFixJob(job.id);
    if (id) count++;
  }
  return count;
}
