import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../../../backend/src/lib/supabase';

// 1. getVulnerabilityDetail
registerAegisTool(
  'getVulnerabilityDetail',
  {
    category: 'security_ops',
    permissionLevel: 'safe',
    requiredRbacPermissions: [],
  },
  tool({
    description: 'Get full detail for a specific vulnerability by OSV ID. Joins dependency_vulnerabilities with project_dependency_vulnerabilities.',
    parameters: z.object({
      projectId: z.string().uuid(),
      osvId: z.string(),
    }),
    execute: async ({ projectId, osvId }) => {
      const { data: dv } = await supabase
        .from('dependency_vulnerabilities')
        .select('*')
        .eq('osv_id', osvId)
        .single();

      if (!dv) {
        return JSON.stringify({ error: 'Vulnerability not found' });
      }

      const { data: pdvs } = await supabase
        .from('project_dependency_vulnerabilities')
        .select(
          `
          id, depscore, epss_score, cvss_score, cisa_kev, is_reachable,
          suppressed, suppressed_by, suppressed_at,
          risk_accepted, risk_accepted_by, risk_accepted_at, risk_accepted_reason,
          reachability_level, reachability_details,
          project_dependencies!inner(
            id, version, is_direct,
            dependencies!inner(id, name, ecosystem, latest_version)
          )
        `,
        )
        .eq('project_id', projectId)
        .eq('osv_id', osvId);

      const pdv = pdvs && pdvs.length > 0 ? pdvs[0] : null;
      const pd = pdv?.project_dependencies;
      const dep = Array.isArray(pd) ? pd[0]?.dependencies : (pd as any)?.dependencies;

      const result = {
        osvId: dv.osv_id,
        severity: dv.severity,
        summary: dv.summary,
        details: dv.details,
        affectedVersions: dv.affected_versions,
        fixedVersions: dv.fixed_versions,
        references: dv.references,
        publishedAt: dv.published_at,
        projectContext: pdv
          ? {
              package: dep?.name,
              currentVersion: (pd as any)?.version ?? dep?.version,
              depscore: pdv.depscore,
              epssScore: pdv.epss_score,
              cvssScore: pdv.cvss_score,
              cisaKev: pdv.cisa_kev,
              isReachable: pdv.is_reachable,
              reachabilityLevel: pdv.reachability_level,
              suppressed: pdv.suppressed,
              riskAccepted: pdv.risk_accepted,
            }
          : null,
      };

      return JSON.stringify(result);
    },
  }),
);

// 2. suppressVulnerability
registerAegisTool(
  'suppressVulnerability',
  {
    category: 'security_ops',
    permissionLevel: 'moderate',
    requiredRbacPermissions: ['interact_with_aegis'],
  },
  tool({
    description: 'Mark a vulnerability as suppressed. Use suppressedBy (userId) - caller injects from context.',
    parameters: z.object({
      projectId: z.string().uuid(),
      osvId: z.string(),
      reason: z.string().optional(),
      suppressedBy: z.string().uuid(),
    }),
    execute: async ({ projectId, osvId, suppressedBy }) => {
      const { data: affected, error } = await supabase
        .from('project_dependency_vulnerabilities')
        .update({
          suppressed: true,
          suppressed_by: suppressedBy,
          suppressed_at: new Date().toISOString(),
        })
        .eq('project_id', projectId)
        .eq('osv_id', osvId)
        .select('id');

      if (error) {
        return JSON.stringify({ error: error.message });
      }

      if (!affected || affected.length === 0) {
        return JSON.stringify({ error: 'Vulnerability not found in project' });
      }

      await supabase.from('project_vulnerability_events').insert({
        project_id: projectId,
        osv_id: osvId,
        event_type: 'suppressed',
        metadata: { suppressed_by: suppressedBy },
      });

      return JSON.stringify({ success: true, suppressed: true });
    },
  }),
);

// 3. acceptRisk
registerAegisTool(
  'acceptRisk',
  {
    category: 'security_ops',
    permissionLevel: 'moderate',
    requiredRbacPermissions: ['interact_with_aegis'],
  },
  tool({
    description: 'Accept risk for a vulnerability. Use acceptedBy (userId) - caller injects from context.',
    parameters: z.object({
      projectId: z.string().uuid(),
      osvId: z.string(),
      reason: z.string(),
      acceptedBy: z.string().uuid(),
    }),
    execute: async ({ projectId, osvId, reason, acceptedBy }) => {
      const { data: affected, error } = await supabase
        .from('project_dependency_vulnerabilities')
        .update({
          risk_accepted: true,
          risk_accepted_by: acceptedBy,
          risk_accepted_at: new Date().toISOString(),
          risk_accepted_reason: reason,
        })
        .eq('project_id', projectId)
        .eq('osv_id', osvId)
        .select('id');

      if (error) {
        return JSON.stringify({ error: error.message });
      }

      if (!affected || affected.length === 0) {
        return JSON.stringify({ error: 'Vulnerability not found in project' });
      }

      await supabase.from('project_vulnerability_events').insert({
        project_id: projectId,
        osv_id: osvId,
        event_type: 'accepted',
        metadata: { accepted_by: acceptedBy, reason },
      });

      return JSON.stringify({ success: true, riskAccepted: true });
    },
  }),
);

// 4. revertSuppression
registerAegisTool(
  'revertSuppression',
  {
    category: 'security_ops',
    permissionLevel: 'moderate',
    requiredRbacPermissions: ['interact_with_aegis'],
  },
  tool({
    description: 'Revert suppression for a vulnerability.',
    parameters: z.object({
      projectId: z.string().uuid(),
      osvId: z.string(),
    }),
    execute: async ({ projectId, osvId }) => {
      const { data: affected, error } = await supabase
        .from('project_dependency_vulnerabilities')
        .update({ suppressed: false, suppressed_by: null, suppressed_at: null })
        .eq('project_id', projectId)
        .eq('osv_id', osvId)
        .select('id');

      if (error) {
        return JSON.stringify({ error: error.message });
      }

      if (!affected || affected.length === 0) {
        return JSON.stringify({ error: 'Vulnerability not found in project' });
      }

      await supabase.from('project_vulnerability_events').insert({
        project_id: projectId,
        osv_id: osvId,
        event_type: 'unsuppressed',
        metadata: {},
      });

      return JSON.stringify({ success: true, unsuppressed: true });
    },
  }),
);

// 5. triggerFix
registerAegisTool(
  'triggerFix',
  {
    category: 'security_ops',
    permissionLevel: 'moderate',
    requiredRbacPermissions: ['trigger_fix'],
  },
  tool({
    description: 'Trigger AI fix via the Aider engine. Calls queue_fix_job RPC. For vulnerability: targetId=osvId. For semgrep: targetId=semgrepFindingId. For secret: targetId=secretFindingId.',
    parameters: z.object({
      projectId: z.string().uuid(),
      fixType: z.enum(['vulnerability', 'semgrep', 'secret']),
      strategy: z.string(),
      targetId: z.string().optional(),
      organizationId: z.string().uuid(),
      triggeredBy: z.string().uuid(),
    }),
    execute: async ({ projectId, fixType, strategy, targetId, organizationId, triggeredBy }) => {
      const { requestFix } = await import('../../../ai-fix-engine');

      const req: any = {
        projectId,
        organizationId,
        userId: triggeredBy,
        strategy: strategy as any,
      };

      if (fixType === 'vulnerability') {
        req.vulnerabilityOsvId = targetId;
      } else if (fixType === 'semgrep') {
        req.semgrepFindingId = targetId;
      } else if (fixType === 'secret') {
        req.secretFindingId = targetId;
      }

      const result = await requestFix(req);

      if (!result.success) {
        return JSON.stringify({ error: result.error, errorCode: result.errorCode });
      }

      return JSON.stringify({ success: true, jobId: result.jobId });
    },
  }),
);

// 6. getFixStatus
registerAegisTool(
  'getFixStatus',
  {
    category: 'security_ops',
    permissionLevel: 'safe',
    requiredRbacPermissions: [],
  },
  tool({
    description: 'Get fix job statuses for a project. Optional status filter: queued, running, completed, failed, cancelled.',
    parameters: z.object({
      projectId: z.string().uuid(),
      status: z.enum(['queued', 'running', 'completed', 'failed', 'cancelled']).optional(),
    }),
    execute: async ({ projectId, status }) => {
      let query = supabase
        .from('project_security_fixes')
        .select('id, fix_type, strategy, status, osv_id, pr_url, pr_number, error_message, created_at, completed_at')
        .eq('project_id', projectId)
        .order('created_at', { ascending: false })
        .limit(20);

      if (status) {
        query = query.eq('status', status);
      }

      const { data, error } = await query;

      if (error) {
        return JSON.stringify({ error: error.message });
      }

      return JSON.stringify(data || []);
    },
  }),
);

// 7. createSecuritySprint
registerAegisTool(
  'createSecuritySprint',
  {
    category: 'security_ops',
    permissionLevel: 'moderate',
    requiredRbacPermissions: ['trigger_fix'],
  },
  tool({
    description: 'Create a security sprint (batch fix task). Creates aegis_tasks record with fix steps. Use triggeredBy (userId) - caller injects from context.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      projectId: z.string().uuid().optional(),
      maxFixes: z.number().optional(),
      onlyReachable: z.boolean().optional(),
      triggeredBy: z.string().uuid(),
    }),
    execute: async ({ organizationId, projectId, maxFixes, onlyReachable, triggeredBy }) => {
      const max = maxFixes ?? 10;

      let vulnQuery = supabase
        .from('project_dependency_vulnerabilities')
        .select(
          `
          id, project_id, osv_id, depscore,
          project_dependencies!inner(
            id, version,
            dependencies!inner(name)
          )
        `,
        )
        .eq('suppressed', false)
        .eq('risk_accepted', false)
        .order('depscore', { ascending: false })
        .limit(max);

      if (projectId) {
        vulnQuery = vulnQuery.eq('project_id', projectId);
      } else {
        const { data: projs } = await supabase
          .from('projects')
          .select('id')
          .eq('organization_id', organizationId);
        const ids = (projs || []).map((p) => p.id);
        if (ids.length === 0) {
          return JSON.stringify({ error: 'No projects in organization' });
        }
        vulnQuery = vulnQuery.in('project_id', ids);
      }

      if (onlyReachable) {
        vulnQuery = vulnQuery.eq('is_reachable', true);
      }

      const { data: vulns, error: vulnError } = await vulnQuery;

      if (vulnError) {
        return JSON.stringify({ error: vulnError.message });
      }

      const steps = (vulns || []).map((v, i) => {
        const pd = v.project_dependencies as any;
        const dep = Array.isArray(pd) ? pd[0] : pd;
        return {
          step_number: i + 1,
          title: `Fix ${dep?.dependencies?.name ?? 'vuln'} - ${v.osv_id}`,
          tool_name: 'triggerFix',
          tool_params: {
            projectId: v.project_id,
            fixType: 'vulnerability',
            strategy: 'bump_version',
            targetId: v.osv_id,
          },
        };
      });

      const { data: task, error: taskError } = await supabase
        .from('aegis_tasks')
        .insert({
          organization_id: organizationId,
          user_id: triggeredBy,
          title: `Security Sprint ${projectId ? '(project)' : '(org-wide)'}`,
          description: `Batch fix up to ${max} vulnerabilities`,
          mode: 'plan',
          status: 'planning',
          plan_json: { steps, maxFixes: max, onlyReachable: !!onlyReachable },
          total_steps: steps.length,
        })
        .select('id, title, status, total_steps, created_at')
        .single();

      if (taskError) {
        return JSON.stringify({ error: taskError.message });
      }

      for (const step of steps) {
        await supabase.from('aegis_task_steps').insert({
          task_id: task.id,
          step_number: step.step_number,
          title: step.title,
          tool_name: step.tool_name,
          tool_params: step.tool_params,
          status: 'pending',
        });
      }

      return JSON.stringify({ success: true, taskId: task.id, totalSteps: steps.length });
    },
  }),
);

// 8. getSprintStatus
registerAegisTool(
  'getSprintStatus',
  {
    category: 'security_ops',
    permissionLevel: 'safe',
    requiredRbacPermissions: [],
  },
  tool({
    description: 'Get sprint/task status from aegis_tasks and aegis_task_steps.',
    parameters: z.object({
      taskId: z.string().uuid(),
    }),
    execute: async ({ taskId }) => {
      const { data: task, error: taskError } = await supabase
        .from('aegis_tasks')
        .select('id, title, status, mode, total_steps, completed_steps, failed_steps, summary, started_at, completed_at')
        .eq('id', taskId)
        .single();

      if (taskError || !task) {
        return JSON.stringify({ error: 'Task not found' });
      }

      const { data: steps } = await supabase
        .from('aegis_task_steps')
        .select('step_number, title, tool_name, status, error_message, started_at, completed_at')
        .eq('task_id', taskId)
        .order('step_number');

      return JSON.stringify({ ...task, steps: steps || [] });
    },
  }),
);

// 9. assessBlastRadius
registerAegisTool(
  'assessBlastRadius',
  {
    category: 'security_ops',
    permissionLevel: 'safe',
    requiredRbacPermissions: [],
  },
  tool({
    description: 'Cross-project blast radius for a package. Query project_dependencies across all org projects for a given dependency name.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      packageName: z.string(),
    }),
    execute: async ({ organizationId, packageName }) => {
      const { data: dep } = await supabase
        .from('dependencies')
        .select('id, name, ecosystem, latest_version')
        .eq('name', packageName)
        .maybeSingle();

      if (!dep) {
        return JSON.stringify({ error: 'Package not found' });
      }

      const { data: projs } = await supabase
        .from('projects')
        .select('id, name')
        .eq('organization_id', organizationId);

      const projectIds = (projs || []).map((p) => p.id);
      const projMap = new Map((projs || []).map((p) => [p.id, p.name]));

      if (projectIds.length === 0) {
        return JSON.stringify({ packageName, projects: [], totalProjects: 0 });
      }

      const { data: pds } = await supabase
        .from('project_dependencies')
        .select('project_id, version, is_direct')
        .eq('dependency_id', dep.id)
        .in('project_id', projectIds);

      const byProject = (pds || []).reduce(
        (acc, pd) => {
          const list = acc.get(pd.project_id) || [];
          list.push({ version: pd.version, isDirect: pd.is_direct });
          acc.set(pd.project_id, list);
          return acc;
        },
        new Map<string, { version: string; isDirect: boolean }[]>(),
      );

      const projects = Array.from(byProject.entries()).map(([pid, deps]) => ({
        projectId: pid,
        projectName: projMap.get(pid),
        usages: deps,
      }));

      return JSON.stringify({
        packageName,
        dependencyId: dep.id,
        ecosystem: dep.ecosystem,
        latestVersion: dep.latest_version,
        projects,
        totalProjects: projects.length,
      });
    },
  }),
);

// 10. emergencyLockdownPackage
registerAegisTool(
  'emergencyLockdownPackage',
  {
    category: 'security_ops',
    permissionLevel: 'dangerous',
    requiredRbacPermissions: ['manage_aegis'],
  },
  tool({
    description: 'Pin/ban a package version across all org projects. Inserts into banned_versions. bumpToVersion optional (defaults to latest); bannedBy (userId) - caller injects from context.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      packageName: z.string(),
      version: z.string(),
      reason: z.string(),
      bumpToVersion: z.string().optional(),
      bannedBy: z.string().uuid(),
    }),
    execute: async ({ organizationId, packageName, version, reason, bumpToVersion, bannedBy }) => {
      const { data: dep } = await supabase
        .from('dependencies')
        .select('id, latest_version')
        .eq('name', packageName)
        .maybeSingle();

      if (!dep) {
        return JSON.stringify({ error: 'Package not found' });
      }

      const targetVersion = bumpToVersion ?? dep.latest_version ?? version;
      if (targetVersion === version) {
        return JSON.stringify({ error: 'bumpToVersion must differ from banned version (or provide when latest equals banned)' });
      }

      const { error } = await supabase.from('banned_versions').insert({
        organization_id: organizationId,
        dependency_id: dep.id,
        banned_version: version,
        bump_to_version: targetVersion,
        banned_by: bannedBy,
      });

      if (error) {
        if (error.code === '23505') {
          return JSON.stringify({ error: 'This version is already banned' });
        }
        return JSON.stringify({ error: error.message });
      }

      return JSON.stringify({
        success: true,
        packageName,
        bannedVersion: version,
        bumpToVersion: targetVersion,
        reason,
      });
    },
  }),
);

// 11. getSLAStatus (Phase 15)
registerAegisTool(
  'getSLAStatus',
  {
    category: 'security_ops',
    permissionLevel: 'safe',
    requiredRbacPermissions: [],
  },
  tool({
    description: 'Get SLA compliance summary for the organization or a specific project. Returns counts (on_track, warning, breached) and lists of breached/approaching items.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      projectId: z.string().uuid().optional(),
      severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    }),
    execute: async ({ organizationId, projectId, severity }) => {
      let projectIds: string[] = [];
      if (projectId) {
        const { data: p } = await supabase.from('projects').select('id').eq('id', projectId).eq('organization_id', organizationId).single();
        if (!p) return JSON.stringify({ error: 'Project not found or not in organization' });
        projectIds = [projectId];
      } else {
        const { data: projs } = await supabase.from('projects').select('id').eq('organization_id', organizationId);
        projectIds = (projs ?? []).map((p: { id: string }) => p.id);
      }
      if (projectIds.length === 0) return JSON.stringify({ on_track: 0, warning: 0, breached: 0, breaches: [], approaching: [] });

      let query = supabase
        .from('project_dependency_vulnerabilities')
        .select('id, project_id, osv_id, severity, sla_status, sla_deadline_at, sla_warning_at, detected_at')
        .in('project_id', projectIds)
        .not('sla_status', 'is', null);
      if (severity) query = query.eq('severity', severity);
      const { data: rows, error } = await query;
      if (error) return JSON.stringify({ error: error.message });

      const list = rows ?? [];
      const on_track = list.filter((r: any) => r.sla_status === 'on_track').length;
      const warning = list.filter((r: any) => r.sla_status === 'warning').length;
      const breached = list.filter((r: any) => r.sla_status === 'breached').length;
      const breaches = list.filter((r: any) => r.sla_status === 'breached').map((r: any) => ({ project_id: r.project_id, osv_id: r.osv_id, severity: r.severity, deadline: r.sla_deadline_at }));
      const now = new Date().toISOString();
      const approaching = list.filter((r: any) => r.sla_status === 'on_track' && r.sla_warning_at && r.sla_warning_at <= now).map((r: any) => ({ project_id: r.project_id, osv_id: r.osv_id, severity: r.severity, warning_at: r.sla_warning_at }));

      return JSON.stringify({
        on_track,
        warning,
        breached,
        breaches,
        approaching,
      });
    },
  }),
);
