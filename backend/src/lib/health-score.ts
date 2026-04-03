import { supabase } from '../lib/supabase';

/**
 * Compute and persist a 0–100 health score for a project.
 *
 * Weights:
 *   40% — compliance rate (policy_result->'allowed')
 *   30% — inverse vulnerability severity
 *   20% — dependency freshness (is_outdated)
 *   10% — code findings (semgrep + secrets)
 */
export async function computeHealthScore(projectId: string): Promise<number> {
  const [complianceScore, vulnScore, freshnessScore, findingsScore] = await Promise.all([
    getComplianceScore(projectId),
    getVulnScore(projectId),
    getFreshnessScore(projectId),
    getFindingsScore(projectId),
  ]);

  const scorePreClamp = Math.round(
    complianceScore * 0.4 +
    vulnScore * 0.3 +
    freshnessScore * 0.2 +
    findingsScore * 0.1,
  );

  const clamped = Math.max(0, Math.min(100, scorePreClamp));

  await supabase
    .from('projects')
    .update({ health_score: clamped })
    .eq('id', projectId);

  return clamped;
}

async function getComplianceScore(projectId: string): Promise<number> {
  const { data: deps } = await supabase
    .from('project_dependencies')
    .select('policy_result')
    .eq('project_id', projectId);

  if (!deps || deps.length === 0) return 100;

  // Match frontend: allowed !== false (so null/undefined policy_result or allowed counts as compliant)
  const compliant = deps.filter(
    (d: any) => d.policy_result?.allowed !== false,
  ).length;

  return (compliant / deps.length) * 100;
}

async function getVulnScore(projectId: string): Promise<number> {
  const { data: vulns } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('severity')
    .eq('project_id', projectId)
    .eq('suppressed', false);

  if (!vulns || vulns.length === 0) return 100;

  let penalty = 0;
  for (const v of vulns) {
    switch (v.severity) {
      case 'critical': penalty += 25; break;
      case 'high':     penalty += 10; break;
      case 'medium':   penalty += 5;  break;
      case 'low':      penalty += 1;  break;
    }
  }

  return Math.max(0, 100 - penalty);
}

async function getFreshnessScore(projectId: string): Promise<number> {
  const { data: deps } = await supabase
    .from('project_dependencies')
    .select('is_outdated')
    .eq('project_id', projectId);

  if (!deps || deps.length === 0) return 100;

  const hasOutdatedColumn = deps.some((d: any) => d.is_outdated !== null && d.is_outdated !== undefined);
  if (!hasOutdatedColumn) return 80;

  const outdated = deps.filter((d: any) => d.is_outdated === true).length;
  return ((deps.length - outdated) / deps.length) * 100;
}

/** Returns the 4 component scores (0–100) without persisting. For debugging. */
export async function getHealthScoreBreakdown(projectId: string): Promise<{
  complianceScore: number;
  vulnScore: number;
  freshnessScore: number;
  findingsScore: number;
}> {
  const [complianceScore, vulnScore, freshnessScore, findingsScore] = await Promise.all([
    getComplianceScore(projectId),
    getVulnScore(projectId),
    getFreshnessScore(projectId),
    getFindingsScore(projectId),
  ]);
  return { complianceScore, vulnScore, freshnessScore, findingsScore };
}

async function getFindingsScore(projectId: string): Promise<number> {
  const [{ count: semgrepCount }, { count: secretCount }] = await Promise.all([
    supabase
      .from('project_semgrep_findings')
      .select('id', { count: 'exact', head: true })
      .eq('project_id', projectId)
      .then((r) => ({ count: r.count ?? 0 })),
    supabase
      .from('project_secret_findings')
      .select('id', { count: 'exact', head: true })
      .eq('project_id', projectId)
      .eq('verified', true)
      .then((r) => ({ count: r.count ?? 0 })),
  ]);

  const penalty = semgrepCount * 5 + secretCount * 10;
  return Math.max(0, 100 - penalty);
}
