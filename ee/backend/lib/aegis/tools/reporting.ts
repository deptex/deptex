import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../../../backend/src/lib/supabase';

const timeRangeSchema = z.enum(['7d', '30d', '90d']).optional();

registerAegisTool(
  'generateSecurityReport',
  { category: 'reporting', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Generate a comprehensive security report in markdown. Aggregates vulns, semgrep, secrets, compliance for a project.',
    parameters: z.object({
      projectId: z.string().uuid(),
    }),
    execute: async ({ projectId }) => {
      const [{ data: project }, { data: deps }, { data: vulns }, { data: semgrep }, { data: secrets }] = await Promise.all([
        supabase.from('projects').select('name, health_score, status_id').eq('id', projectId).single(),
        supabase.from('project_dependencies').select('id, policy_result').eq('project_id', projectId),
        supabase.from('project_dependency_vulnerabilities').select('osv_id, severity, is_reachable, reachability_level, suppressed').eq('project_id', projectId).eq('suppressed', false),
        supabase.from('project_semgrep_findings').select('rule_id, severity, path, message').eq('project_id', projectId),
        supabase.from('project_secret_findings').select('rule_id, path').eq('project_id', projectId),
      ]);
      if (!project) return JSON.stringify({ error: 'Project not found' });
      const vulnBySev = (vulns ?? []).reduce((a: Record<string, number>, v: any) => {
        a[v.severity || 'unknown'] = (a[v.severity || 'unknown'] || 0) + 1;
        return a;
      }, {});
      const policyViolations = (deps ?? []).filter((d: any) => (d.policy_result as any)?.allowed === false).length;
      const lines: string[] = [
        `# Security Report: ${project.name}`,
        `Generated: ${new Date().toISOString()}`,
        '',
        '## Summary',
        `- Health Score: ${project.health_score ?? 'N/A'}`,
        `- Direct Dependencies: ${deps?.length ?? 0}`,
        `- Policy Violations: ${policyViolations}`,
        `- Vulnerabilities: ${vulns?.length ?? 0}`,
        `- Semgrep Findings: ${semgrep?.length ?? 0}`,
        `- Secret Findings: ${secrets?.length ?? 0}`,
        '',
        '## Vulnerabilities by Severity',
        ...Object.entries(vulnBySev).map(([k, v]) => `- ${k}: ${v}`),
        '',
        '## Reachability',
        `- Reachable: ${(vulns ?? []).filter((v: any) => v.is_reachable || ['data_flow', 'function', 'confirmed'].includes(v.reachability_level)).length}`,
        `- Unreachable: ${(vulns ?? []).filter((v: any) => !v.is_reachable && !['data_flow', 'function', 'confirmed'].includes(v.reachability_level)).length}`,
        '',
        '## Code Security (Semgrep)',
        ...(semgrep ?? []).slice(0, 10).map((s: any) => `- [${s.severity}] ${s.rule_id}: ${s.path} - ${s.message}`),
        semgrep?.length && semgrep.length > 10 ? `\n... and ${semgrep.length - 10} more` : '',
        '',
        '## Secret Findings',
        ...(secrets ?? []).slice(0, 5).map((s: any) => `- ${s.rule_id}: ${s.path}`),
        secrets?.length && secrets.length > 5 ? `\n... and ${secrets.length - 5} more` : '',
      ].filter(Boolean);
      const report = lines.join('\n');
      return JSON.stringify({ report, projectId, projectName: project.name });
    },
  })
);

registerAegisTool(
  'generateComplianceReport',
  { category: 'reporting', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Generate a compliance-focused report. License compliance, policy adherence, SBOM freshness.',
    parameters: z.object({
      projectId: z.string().uuid(),
    }),
    execute: async ({ projectId }) => {
      const [{ data: project }, { data: deps }, { data: repo }, { data: latestJob }] = await Promise.all([
        supabase.from('projects').select('name, status_id, policy_evaluated_at').eq('id', projectId).single(),
        supabase.from('project_dependencies').select('id, name, version, license, policy_result').eq('project_id', projectId),
        supabase.from('project_repositories').select('last_extracted_at, status').eq('project_id', projectId).single(),
        supabase.from('extraction_jobs').select('completed_at').eq('project_id', projectId).eq('status', 'completed').order('completed_at', { ascending: false }).limit(1).single(),
      ]);
      if (!project) return JSON.stringify({ error: 'Project not found' });
      const violations = (deps ?? []).filter((d: any) => (d.policy_result as any)?.allowed === false);
      const byLicense = new Map<string, number>();
      for (const d of deps ?? []) {
        const lic = d.license || 'Unknown';
        byLicense.set(lic, (byLicense.get(lic) ?? 0) + 1);
      }
      const lines: string[] = [
        `# Compliance Report: ${project.name}`,
        `Generated: ${new Date().toISOString()}`,
        '',
        '## Policy Adherence',
        `- Policy Last Evaluated: ${project.policy_evaluated_at ?? 'Never'}`,
        `- Policy Violations: ${violations.length}`,
        ...violations.slice(0, 5).map((v: any) => `  - ${v.name}@${v.version}: ${(v.policy_result as any)?.reasons?.join(', ') ?? 'Blocked'}`),
        '',
        '## License Distribution',
        ...[...byLicense.entries()].map(([lic, c]) => `- ${lic}: ${c} packages`),
        '',
        '## SBOM Freshness',
        `- Last Extraction: ${repo?.last_extracted_at ?? latestJob?.completed_at ?? 'Never'}`,
        `- Repo Status: ${repo?.status ?? 'unknown'}`,
      ];
      const report = lines.join('\n');
      return JSON.stringify({ report, projectId, projectName: project.name });
    },
  })
);

registerAegisTool(
  'generateExecutiveSummary',
  { category: 'reporting', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Generate a non-technical C-suite summary. Overall status, key metrics, trends.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      timeRange: timeRangeSchema,
    }),
    execute: async ({ organizationId, timeRange }) => {
      const range = timeRange ?? '30d';
      const days = range === '7d' ? 7 : range === '90d' ? 90 : 30;
      const since = new Date();
      since.setDate(since.getDate() - days);
      const { data: projects } = await supabase.from('projects').select('id, name, health_score, status_id').eq('organization_id', organizationId);
      const projectIds = (projects ?? []).map((p: any) => p.id);
      const [{ count: vulnCount }, { count: compliantCount }] = await Promise.all([
        projectIds.length ? supabase.from('project_dependency_vulnerabilities').select('id', { count: 'exact', head: true }).in('project_id', projectIds).eq('suppressed', false) : { count: 0 },
        projectIds.length ? supabase.from('projects').select('id', { count: 'exact', head: true }).eq('organization_id', organizationId).not('status_id', 'is', null) : { count: 0 },
      ]);
      const avgHealth = projects?.length ? (projects as any[]).reduce((a: number, p: any) => a + (p.health_score ?? 0), 0) / projects.length : 0;
      const summary = {
        organizationId,
        timeRange: range,
        projectCount: projects?.length ?? 0,
        averageHealthScore: Math.round(avgHealth),
        totalVulnerabilities: vulnCount ?? 0,
        projectsWithStatus: compliantCount ?? 0,
        message: `Over the past ${days} days, your organization has ${projects?.length ?? 0} projects with an average health score of ${Math.round(avgHealth)}. There are ${vulnCount ?? 0} active vulnerabilities across all projects.`,
      };
      return JSON.stringify(summary);
    },
  })
);

const ROI_HEURISTICS: Record<string, { hours: number }> = {
  auto_fix: { hours: 2 },
  code_patch: { hours: 4 },
  sprint: { hours: 3 },
  triage: { hours: 0.5 },
  report: { hours: 4 },
  vex: { hours: 2 },
  audit_package: { hours: 8 },
  pr_review: { hours: 0.5 },
};
const HOURLY_RATE = 75;

registerAegisTool(
  'getROIMetrics',
  { category: 'reporting', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Calculate ROI metrics. Counts fixes, reports, PRs reviewed. Applies heuristic hour/dollar savings.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      timeRange: timeRangeSchema,
    }),
    execute: async ({ organizationId, timeRange }) => {
      const range = timeRange ?? '30d';
      const days = range === '7d' ? 7 : range === '90d' ? 90 : 30;
      const since = new Date();
      since.setDate(since.getDate() - days);
      const sinceStr = since.toISOString();
      const { data: fixes } = await supabase
        .from('project_security_fixes')
        .select('id, fix_type, status')
        .eq('organization_id', organizationId)
        .gte('created_at', sinceStr);
      const completedFixes = (fixes ?? []).filter((f: any) => ['completed', 'merged', 'pr_closed'].includes(f.status));
      const autoFixCount = completedFixes.filter((f: any) => f.fix_type === 'vulnerability').length;
      const codePatchCount = completedFixes.filter((f: any) => f.fix_type === 'semgrep' || f.fix_type === 'secret').length;
      const { data: orgProjects } = await supabase.from('projects').select('id').eq('organization_id', organizationId);
      const pids = (orgProjects ?? []).map((p: any) => p.id);
      const { count: prCount } = pids.length
        ? await supabase.from('project_pull_requests').select('id', { count: 'exact', head: true }).in('project_id', pids).gte('created_at', sinceStr)
        : { count: 0 };
      const hoursSaved = (autoFixCount * ROI_HEURISTICS.auto_fix.hours)
        + (codePatchCount * ROI_HEURISTICS.code_patch.hours)
        + (Math.min(completedFixes.length, 10) * ROI_HEURISTICS.sprint.hours)
        + (completedFixes.length * ROI_HEURISTICS.triage.hours)
        + ((prCount ?? 0) * ROI_HEURISTICS.pr_review.hours);
      const dollarsSaved = Math.round(hoursSaved * HOURLY_RATE);
      return JSON.stringify({
        organizationId,
        timeRange: range,
        fixesCompleted: completedFixes.length,
        autoFixCount,
        codePatchCount,
        prsReviewed: prCount ?? 0,
        estimatedHoursSaved: Math.round(hoursSaved * 10) / 10,
        estimatedDollarsSaved: dollarsSaved,
        hourlyRate: HOURLY_RATE,
      });
    },
  })
);

// Phase 15: getSLAReport
registerAegisTool(
  'getSLAReport',
  { category: 'reporting', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Get SLA compliance report for the organization. Summary metrics and violation counts suitable for briefing or reports.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      timeRange: z.enum(['30d', '90d', '6m', '12m']).optional(),
    }),
    execute: async ({ organizationId, timeRange }) => {
      const { data: projects } = await supabase.from('projects').select('id, name').eq('organization_id', organizationId);
      const projectIds = (projects ?? []).map((p: { id: string }) => p.id);
      if (projectIds.length === 0) {
        return JSON.stringify({ overall_compliance_percent: 100, current_breaches: 0, violations_count: 0, message: 'No projects' });
      }
      const { data: pdvList } = await supabase
        .from('project_dependency_vulnerabilities')
        .select('sla_status, severity, sla_met_at, detected_at, created_at')
        .in('project_id', projectIds);
      const list = pdvList ?? [];
      const met = list.filter((p: any) => p.sla_status === 'met').length;
      const resolvedLate = list.filter((p: any) => p.sla_status === 'resolved_late').length;
      const breached = list.filter((p: any) => p.sla_status === 'breached').length;
      const totalResolved = met + resolvedLate;
      const overall_compliance_percent = totalResolved > 0 ? Math.round((met / totalResolved) * 100) : 100;
      const violations = list.filter((p: any) => p.sla_status === 'breached' || p.sla_status === 'warning');
      return JSON.stringify({
        overall_compliance_percent,
        current_breaches: breached,
        violations_count: violations.length,
        met,
        resolved_late: resolvedLate,
        on_track: list.filter((p: any) => p.sla_status === 'on_track').length,
        warning: list.filter((p: any) => p.sla_status === 'warning').length,
        exempt: list.filter((p: any) => p.sla_status === 'exempt').length,
        time_range: timeRange ?? '90d',
      });
    },
  })
);
