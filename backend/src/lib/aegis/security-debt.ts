/**
 * Phase 7B: Security debt tracking and burndown.
 * Requires security_debt_snapshots table (phase7b_aegis_platform.sql).
 */
import { supabase } from '../../lib/supabase';

const VULN_WEIGHTS: Record<string, number> = {
  critical: 10,
  high: 5,
  medium: 2,
  low: 1,
};

const SEMGREP_WEIGHTS: Record<string, number> = {
  critical: 5,
  high: 3,
  medium: 1,
  low: 0.5,
};

const SECRET_WEIGHT = 5;
const NON_COMPLIANT_WEIGHT = 3;
const STALE_DEP_WEIGHT = 1;

export interface DebtBreakdown {
  vulns: number;
  compliance: number;
  staleDeps: number;
  codeIssues: number;
  secrets: number;
}

export interface DebtScoreResult {
  score: number;
  breakdown: DebtBreakdown;
}

/**
 * Calculate composite security debt score (0-1000, lower is better).
 * Components: unfixed vulns, non-compliant packages, stale deps, code issues, unresolved secrets.
 */
export async function computeDebtScore(
  organizationId: string,
  projectId?: string
): Promise<DebtScoreResult> {
  const projectIds = projectId
    ? [projectId]
    : await getOrgProjectIds(organizationId);

  if (projectIds.length === 0) {
    return {
      score: 0,
      breakdown: { vulns: 0, compliance: 0, staleDeps: 0, codeIssues: 0, secrets: 0 },
    };
  }

  const [vulnPoints, compliancePoints, stalePoints, codePoints, secretPoints] =
    await Promise.all([
      getVulnDebtPoints(projectIds),
      getComplianceDebtPoints(projectIds),
      getStaleDebtPoints(projectIds),
      getCodeIssuesDebtPoints(projectIds),
      getSecretsDebtPoints(projectIds),
    ]);

  const score = Math.min(
    1000,
    vulnPoints + compliancePoints + stalePoints + codePoints + secretPoints
  );

  return {
    score,
    breakdown: {
      vulns: vulnPoints,
      compliance: compliancePoints,
      staleDeps: stalePoints,
      codeIssues: codePoints,
      secrets: secretPoints,
    },
  };
}

async function getOrgProjectIds(organizationId: string): Promise<string[]> {
  const { data } = await supabase
    .from('projects')
    .select('id')
    .eq('organization_id', organizationId);
  return (data ?? []).map((r: { id: string }) => r.id);
}

async function getVulnDebtPoints(projectIds: string[]): Promise<number> {
  const { data } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('severity')
    .in('project_id', projectIds)
    .eq('suppressed', false)
    .eq('risk_accepted', false);

  let points = 0;
  for (const v of data ?? []) {
    const w = VULN_WEIGHTS[(v.severity ?? '').toLowerCase()];
    if (w != null) points += w;
  }
  return points;
}

async function getComplianceDebtPoints(projectIds: string[]): Promise<number> {
  const { data } = await supabase
    .from('project_dependencies')
    .select('policy_result')
    .in('project_id', projectIds);

  let count = 0;
  for (const d of data ?? []) {
    const pr = d.policy_result as { allowed?: boolean } | null;
    if (pr && pr.allowed === false) count++;
  }
  return count * NON_COMPLIANT_WEIGHT;
}

async function getStaleDebtPoints(projectIds: string[]): Promise<number> {
  const { data } = await supabase
    .from('project_dependencies')
    .select('is_outdated')
    .in('project_id', projectIds);

  let count = 0;
  for (const d of data ?? []) {
    if (d.is_outdated === true) count++;
  }
  return count * STALE_DEP_WEIGHT;
}

async function getCodeIssuesDebtPoints(projectIds: string[]): Promise<number> {
  const { data } = await supabase
    .from('project_semgrep_findings')
    .select('severity')
    .in('project_id', projectIds);

  let points = 0;
  for (const f of data ?? []) {
    const w = SEMGREP_WEIGHTS[(f.severity ?? '').toLowerCase()];
    if (w != null) points += w;
  }
  return points;
}

async function getSecretsDebtPoints(projectIds: string[]): Promise<number> {
  const hasIsCurrent = await checkSecretsHasIsCurrent();

  let query = supabase
    .from('project_secret_findings')
    .select('id')
    .in('project_id', projectIds);

  if (hasIsCurrent) {
    query = query.eq('is_current', true);
  }

  const { count } = await query;
  return (count ?? 0) * SECRET_WEIGHT;
}

let _secretsHasIsCurrent: boolean | null = null;

async function checkSecretsHasIsCurrent(): Promise<boolean> {
  if (_secretsHasIsCurrent !== null) return _secretsHasIsCurrent;
  const { data, error } = await supabase
    .from('project_secret_findings')
    .select('is_current')
    .limit(1);
  _secretsHasIsCurrent = !error && data != null && data.length > 0 && 'is_current' in data[0];
  return _secretsHasIsCurrent;
}

/**
 * Daily snapshot: compute org-wide score + per-project scores, insert into security_debt_snapshots.
 * Called by QStash cron (e.g. 0 2 * * *).
 */
export async function snapshotDebt(organizationId: string): Promise<void> {
  const projectIds = await getOrgProjectIds(organizationId);
  const today = new Date().toISOString().slice(0, 10);

  // Org-wide snapshot
  const orgScore = await computeDebtScore(organizationId);
  await supabase.from('security_debt_snapshots').upsert(
    {
      organization_id: organizationId,
      project_id: null,
      score: orgScore.score,
      breakdown: orgScore.breakdown,
      snapshot_date: today,
    },
    { onConflict: 'organization_id,project_id,snapshot_date' }
  );

  // Per-project snapshots
  for (const projectId of projectIds) {
    const projScore = await computeDebtScore(organizationId, projectId);
    await supabase.from('security_debt_snapshots').upsert(
      {
        organization_id: organizationId,
        project_id: projectId,
        score: projScore.score,
        breakdown: projScore.breakdown,
        snapshot_date: today,
      },
      { onConflict: 'organization_id,project_id,snapshot_date' }
    );
  }
}

export interface DebtHistoryPoint {
  date: string;
  score: number;
  breakdown: DebtBreakdown;
}

/**
 * Query security_debt_snapshots for time range, return data points for chart.
 */
export async function getDebtHistory(
  organizationId: string,
  projectId?: string,
  days = 30
): Promise<DebtHistoryPoint[]> {
  const start = new Date();
  start.setDate(start.getDate() - days);
  const startStr = start.toISOString().slice(0, 10);

  let query = supabase
    .from('security_debt_snapshots')
    .select('snapshot_date, score, breakdown')
    .eq('organization_id', organizationId)
    .gte('snapshot_date', startStr)
    .order('snapshot_date', { ascending: true });

  if (projectId != null) {
    query = query.eq('project_id', projectId);
  } else {
    query = query.is('project_id', null);
  }

  const { data } = await query;

  return (data ?? []).map((r: { snapshot_date: string; score: number; breakdown: DebtBreakdown }) => ({
    date: r.snapshot_date,
    score: r.score,
    breakdown: r.breakdown ?? { vulns: 0, compliance: 0, staleDeps: 0, codeIssues: 0, secrets: 0 },
  }));
}

export type TrendDirection = 'improving' | 'stable' | 'worsening';

export interface DebtVelocityResult {
  averageDailyChange: number;
  projectedDaysToZero: number | null;
  trendDirection: TrendDirection;
}

/**
 * Calculate debt reduction rate from last 30 days of snapshots.
 */
export async function getDebtVelocity(
  organizationId: string,
  projectId?: string
): Promise<DebtVelocityResult> {
  const points = await getDebtHistory(organizationId, projectId, 30);

  if (points.length < 2) {
    return {
      averageDailyChange: 0,
      projectedDaysToZero: null,
      trendDirection: 'stable',
    };
  }

  const changes: number[] = [];
  for (let i = 1; i < points.length; i++) {
    const prev = points[i - 1];
    const curr = points[i];
    const days = (new Date(curr.date).getTime() - new Date(prev.date).getTime()) / 86400000;
    if (days > 0) {
      changes.push((curr.score - prev.score) / days);
    }
  }

  const averageDailyChange =
    changes.length > 0 ? changes.reduce((a, b) => a + b, 0) / changes.length : 0;

  const latestScore = points[points.length - 1].score;

  let projectedDaysToZero: number | null = null;
  if (averageDailyChange < 0 && latestScore > 0) {
    projectedDaysToZero = Math.ceil(Math.abs(latestScore / averageDailyChange));
  }

  let trendDirection: TrendDirection = 'stable';
  if (averageDailyChange < -0.5) trendDirection = 'improving';
  else if (averageDailyChange > 0.5) trendDirection = 'worsening';

  return {
    averageDailyChange,
    projectedDaysToZero,
    trendDirection,
  };
}
