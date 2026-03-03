import { supabase } from '../../../../backend/src/lib/supabase';
import { createTask, TaskPlan } from './tasks';
import { normalizeStrategy } from '../learning/strategy-constants';
import { recommendStrategies } from '../learning/recommendation-engine';

export interface SecuritySprintRequest {
  projectId?: string;
  organizationId: string;
  userId: string;
  mode: 'auto' | 'interactive';
  criteria?: {
    maxFixes?: number;
    minDepscore?: number;
    onlyReachable?: boolean;
    strategies?: string[];
    includeTypes?: ('vulnerability' | 'semgrep' | 'secret')[];
    includeSuppressed?: boolean;
    includeAccepted?: boolean;
  };
  fixRequests?: FixRequest[];
}

interface FixRequest {
  type: 'vulnerability' | 'semgrep' | 'secret';
  targetId: string;
  strategy?: string;
  projectId: string;
}

interface SprintCandidate {
  type: 'vulnerability' | 'semgrep' | 'secret';
  id: string;
  projectId: string;
  projectName: string;
  severity: string;
  depscore: number | null;
  isReachable: boolean;
  reachabilityLevel: string | null;
  osvId?: string;
  dependencyName?: string;
  title: string;
  strategy: string;
}

const MAX_SPRINT_FIXES = 50;
const MAX_CONCURRENT_SPRINTS = 3;

export async function createSecuritySprint(request: SecuritySprintRequest): Promise<{
  taskId?: string;
  error?: string;
  candidates?: SprintCandidate[];
}> {
  const concurrentCheck = await supabase
    .from('aegis_tasks')
    .select('id', { count: 'exact' })
    .eq('organization_id', request.organizationId)
    .like('title', 'Security Sprint%')
    .in('status', ['running', 'awaiting_approval']);

  if ((concurrentCheck.count || 0) >= MAX_CONCURRENT_SPRINTS) {
    return { error: `Maximum ${MAX_CONCURRENT_SPRINTS} concurrent sprints per organization` };
  }

  const candidates = request.fixRequests
    ? await resolveExplicitRequests(request.fixRequests)
    : await discoverCandidates(request);

  if (candidates.length === 0) {
    return { error: 'No fixable issues found matching the criteria' };
  }

  if (request.mode === 'interactive') {
    return { candidates };
  }

  const maxFixes = Math.min(
    request.criteria?.maxFixes || MAX_SPRINT_FIXES,
    MAX_SPRINT_FIXES
  );
  const selected = candidates.slice(0, maxFixes);

  const plan = buildSprintPlan(request, selected);
  const taskId = await createTask(
    request.organizationId,
    request.userId,
    null,
    plan,
  );

  return { taskId, candidates: selected };
}

export async function confirmInteractiveSprint(
  organizationId: string,
  userId: string,
  selectedCandidates: SprintCandidate[],
): Promise<{ taskId: string }> {
  const plan = buildSprintPlan(
    { organizationId, userId },
    selectedCandidates
  );
  const taskId = await createTask(organizationId, userId, null, plan);
  return { taskId };
}

async function discoverCandidates(request: SecuritySprintRequest): Promise<SprintCandidate[]> {
  const candidates: SprintCandidate[] = [];
  const types = request.criteria?.includeTypes || ['vulnerability', 'semgrep', 'secret'];

  const projectIds = await getTargetProjectIds(request);
  if (projectIds.length === 0) return [];

  if (types.includes('vulnerability')) {
    const vulns = await discoverVulnerabilityCandidates(
      projectIds,
      request.criteria,
      request.organizationId,
    );
    candidates.push(...vulns);
  }

  if (types.includes('semgrep')) {
    const semgrep = await discoverSemgrepCandidates(projectIds);
    candidates.push(...semgrep);
  }

  if (types.includes('secret')) {
    const secrets = await discoverSecretCandidates(projectIds);
    candidates.push(...secrets);
  }

  candidates.sort((a, b) => {
    const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const sevDiff = (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4);
    if (sevDiff !== 0) return sevDiff;
    return (b.depscore ?? 0) - (a.depscore ?? 0);
  });

  return candidates;
}

async function getTargetProjectIds(request: SecuritySprintRequest): Promise<string[]> {
  if (request.projectId) return [request.projectId];

  const { data: projects } = await supabase
    .from('projects')
    .select('id')
    .eq('organization_id', request.organizationId);

  return (projects || []).map(p => p.id);
}

async function discoverVulnerabilityCandidates(
  projectIds: string[],
  criteria?: SecuritySprintRequest['criteria'],
  organizationId?: string,
): Promise<SprintCandidate[]> {
  let query = supabase
    .from('project_dependency_vulnerabilities')
    .select(`
      id, osv_id, severity, depscore, is_reachable, reachability_level,
      suppressed, risk_accepted,
      project_dependencies!inner(
        id, version,
        projects!inner(id, name),
        dependencies!inner(id, name, ecosystem)
      )
    `)
    .in('project_dependencies.project_id', projectIds)
    .order('depscore', { ascending: false });

  if (!criteria?.includeSuppressed) {
    query = query.neq('suppressed', true);
  }
  if (!criteria?.includeAccepted) {
    query = query.neq('risk_accepted', true);
  }
  if (criteria?.minDepscore) {
    query = query.gte('depscore', criteria.minDepscore);
  }
  if (criteria?.onlyReachable) {
    query = query.eq('is_reachable', true);
  }

  const { data: vulns } = await query.limit(200);
  if (!vulns) return [];

  const results: SprintCandidate[] = [];
  for (const v of vulns) {
    const pdRaw = v.project_dependencies;
    const pd = Array.isArray(pdRaw) ? pdRaw[0] : pdRaw;
    const depRaw = pd?.dependencies;
    const dep = Array.isArray(depRaw) ? depRaw[0] : depRaw;
    const projRaw = pd?.projects;
    const proj = Array.isArray(projRaw) ? projRaw[0] : projRaw;
    const strategy = organizationId
      ? await determineFixStrategyWithRecommendations(v, dep, organizationId)
      : determineFixStrategy(v, dep);
    results.push({
      type: 'vulnerability' as const,
      id: v.id,
      projectId: proj?.id,
      projectName: proj?.name || 'Unknown',
      severity: v.severity || 'medium',
      depscore: v.depscore,
      isReachable: v.is_reachable || false,
      reachabilityLevel: v.reachability_level,
      osvId: v.osv_id,
      dependencyName: dep?.name,
      title: `Fix ${v.osv_id} in ${dep?.name}`,
      strategy,
    });
  }
  return results;
}

async function discoverSemgrepCandidates(
  projectIds: string[],
): Promise<SprintCandidate[]> {
  const { data: findings } = await supabase
    .from('project_semgrep_findings')
    .select('id, rule_id, severity, path, message, project_id')
    .in('project_id', projectIds)
    .in('severity', ['ERROR', 'WARNING'])
    .limit(100);

  if (!findings) return [];

  const projNames = await getProjectNames(projectIds);

  return findings.map((f: any) => ({
    type: 'semgrep' as const,
    id: f.id,
    projectId: f.project_id,
    projectName: projNames[f.project_id] || 'Unknown',
    severity: f.severity === 'ERROR' ? 'high' : 'medium',
    depscore: null,
    isReachable: true,
    reachabilityLevel: null,
    title: `Fix Semgrep ${f.rule_id} in ${f.path}`,
    strategy: 'fix_semgrep',
  }));
}

async function discoverSecretCandidates(
  projectIds: string[],
): Promise<SprintCandidate[]> {
  const { data: findings } = await supabase
    .from('project_secret_findings')
    .select('id, detector_name, file, project_id')
    .in('project_id', projectIds)
    .limit(50);

  if (!findings) return [];

  const projNames = await getProjectNames(projectIds);

  return findings.map((f: any) => ({
    type: 'secret' as const,
    id: f.id,
    projectId: f.project_id,
    projectName: projNames[f.project_id] || 'Unknown',
    severity: 'critical',
    depscore: null,
    isReachable: true,
    reachabilityLevel: null,
    title: `Remove ${f.detector_name} secret in ${f.file}`,
    strategy: 'remediate_secret',
  }));
}

async function getProjectNames(projectIds: string[]): Promise<Record<string, string>> {
  const { data } = await supabase
    .from('projects')
    .select('id, name')
    .in('id', projectIds);

  const map: Record<string, string> = {};
  (data || []).forEach((p: any) => { map[p.id] = p.name; });
  return map;
}

async function resolveExplicitRequests(
  fixRequests: FixRequest[],
): Promise<SprintCandidate[]> {
  const projIds = [...new Set(fixRequests.map(f => f.projectId))];
  const projNames = await getProjectNames(projIds);

  return fixRequests.map(req => ({
    type: req.type,
    id: req.targetId,
    projectId: req.projectId,
    projectName: projNames[req.projectId] || 'Unknown',
    severity: 'high',
    depscore: null,
    isReachable: true,
    reachabilityLevel: null,
    title: `Fix ${req.type} ${req.targetId}`,
    strategy: normalizeStrategy(req.strategy || 'bump_version'),
  }));
}

async function determineFixStrategyWithRecommendations(vuln: any, dep: any, orgId: string): Promise<string> {
  try {
    const recs = await recommendStrategies(
      orgId,
      dep?.ecosystem || 'npm',
      null,
      !!dep?.is_direct,
      'vulnerability',
    );
    if (recs.length > 0 && recs[0].confidence !== 'low') {
      return recs[0].strategy;
    }
  } catch {
    // Fall back to legacy logic
  }
  return determineFixStrategy(vuln, dep);
}

function determineFixStrategy(vuln: any, dep: any): string {
  if (!dep) return 'bump_version';

  if (vuln.reachability_level === 'data_flow' || vuln.reachability_level === 'confirmed') {
    return 'code_patch';
  }

  if (['critical', 'high'].includes(vuln.severity)) {
    return 'bump_version';
  }

  return dep.ecosystem === 'npm' ? 'pin_transitive' : 'bump_version';
}

function buildSprintPlan(
  request: Pick<SecuritySprintRequest, 'organizationId' | 'userId'>,
  candidates: SprintCandidate[],
): TaskPlan {
  const isOrgWide = new Set(candidates.map(c => c.projectId)).size > 1;
  const projectSummary = isOrgWide
    ? `across ${new Set(candidates.map(c => c.projectId)).size} projects`
    : `in ${candidates[0]?.projectName || 'project'}`;

  const steps = candidates.map((candidate, idx) => ({
    title: candidate.title,
    toolName: 'triggerFix',
    toolParams: {
      organizationId: request.organizationId,
      projectId: candidate.projectId,
      fixType: candidate.type,
      targetId: candidate.id,
      strategy: candidate.strategy,
      osvId: candidate.osvId,
    },
    estimatedCost: 0.05,
  }));

  const vulnCount = candidates.filter(c => c.type === 'vulnerability').length;
  const semgrepCount = candidates.filter(c => c.type === 'semgrep').length;
  const secretCount = candidates.filter(c => c.type === 'secret').length;
  const parts: string[] = [];
  if (vulnCount) parts.push(`${vulnCount} vulnerabilities`);
  if (semgrepCount) parts.push(`${semgrepCount} code findings`);
  if (secretCount) parts.push(`${secretCount} secrets`);

  return {
    title: `Security Sprint ${projectSummary}`,
    description: `Automated security sprint fixing ${parts.join(', ')} ${projectSummary}. Issues sorted by severity and depscore.`,
    steps,
    estimatedCost: steps.length * 0.05,
    estimatedTimeMinutes: steps.length * 3,
  };
}

export async function getSprintSummary(taskId: string) {
  const { data: task } = await supabase
    .from('aegis_tasks')
    .select('*')
    .eq('id', taskId)
    .single();

  if (!task) return null;

  const { data: steps } = await supabase
    .from('aegis_task_steps')
    .select('*')
    .eq('task_id', taskId)
    .order('step_number', { ascending: true });

  const completed = (steps || []).filter((s: any) => s.status === 'completed').length;
  const failed = (steps || []).filter((s: any) => s.status === 'failed').length;
  const pending = (steps || []).filter((s: any) => s.status === 'pending').length;

  const prsCreated = (steps || [])
    .filter((s: any) => s.status === 'completed' && s.result_json?.pr_url)
    .map((s: any) => ({
      title: s.title,
      prUrl: s.result_json.pr_url,
      prBranch: s.result_json.pr_branch,
    }));

  return {
    task: {
      id: task.id,
      title: task.title,
      description: task.description,
      status: task.status,
      startedAt: task.started_at,
      completedAt: task.completed_at,
      totalCost: task.total_cost,
    },
    stats: {
      total: (steps || []).length,
      completed,
      failed,
      pending,
      successRate: completed > 0 ? Math.round((completed / (completed + failed)) * 100) : 0,
    },
    prsCreated,
    steps: (steps || []).map((s: any) => ({
      id: s.id,
      stepNumber: s.step_number,
      title: s.title,
      status: s.status,
      errorMessage: s.error_message,
      result: s.result_json,
    })),
  };
}
