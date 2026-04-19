import { registerAction, ActionContext, ActionResult } from './index';
import { supabase } from '../../../../../backend/src/lib/supabase';

function wrapUntrusted(source: string, content: string): string {
  const sanitized = content
    .replace(/system:/gi, 's_ystem:')
    .replace(/user:/gi, 'u_ser:')
    .replace(/assistant:/gi, 'a_ssistant:')
    .replace(/<\|im_start\|>/g, '')
    .replace(/<\|im_sep\|>/g, '');
  return `<untrusted_data source="${source}">\n${sanitized}\n</untrusted_data>`;
}

registerAction(
  {
    name: 'getProjectVulnerabilities',
    description: 'List vulnerabilities for a project, sorted by Depscore (highest risk first)',
    parameters: { type: 'object', properties: { projectId: { type: 'string', description: 'Project ID' } }, required: ['projectId'] },
  },
  async (params: { projectId: string }, ctx: ActionContext): Promise<ActionResult> => {
    const { data, error } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('*, project_dependencies!inner(dependency_id, dependencies!inner(name)), dependency_vulnerabilities!inner(osv_id, severity, summary)')
      .eq('project_id', params.projectId)
      .order('depscore', { ascending: false })
      .limit(20);
    if (error) return { success: false, error: error.message };
    return { success: true, data: (data || []).map(v => ({
      osvId: v.dependency_vulnerabilities?.osv_id,
      severity: v.dependency_vulnerabilities?.severity,
      summary: v.dependency_vulnerabilities?.summary,
      package: v.project_dependencies?.dependencies?.name,
      depscore: v.depscore,
      epssScore: v.epss_score,
      cisaKev: v.cisa_kev,
      isReachable: v.is_reachable,
      suppressed: v.suppressed,
      riskAccepted: v.risk_accepted,
    })) };
  }
);

registerAction(
  {
    name: 'getVulnerabilityDetail',
    description: 'Get full detail for a specific vulnerability by OSV ID',
    parameters: { type: 'object', properties: { projectId: { type: 'string', description: 'Project ID' }, osvId: { type: 'string', description: 'OSV vulnerability ID (e.g. GHSA-xxx)' } }, required: ['projectId', 'osvId'] },
  },
  async (params: { projectId: string; osvId: string }): Promise<ActionResult> => {
    const { data } = await supabase
      .from('dependency_vulnerabilities')
      .select('*')
      .eq('osv_id', params.osvId)
      .single();
    if (!data) return { success: false, error: 'Vulnerability not found' };

    const { data: projectVuln } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('*, project_dependencies!inner(dependency_id, version, dependencies!inner(name))')
      .eq('project_id', params.projectId)
      .single();

    return { success: true, data: {
      osvId: data.osv_id,
      severity: data.severity,
      summary: data.summary,
      details: data.details,
      affectedVersions: data.affected_versions,
      fixedVersions: data.fixed_versions,
      references: data.references,
      projectContext: projectVuln ? {
        package: projectVuln.project_dependencies?.dependencies?.name,
        currentVersion: projectVuln.project_dependencies?.version,
        depscore: projectVuln.depscore,
        epssScore: projectVuln.epss_score,
        cisaKev: projectVuln.cisa_kev,
        isReachable: projectVuln.is_reachable,
      } : null,
    }};
  }
);

registerAction(
  {
    name: 'explainVulnerability',
    description: 'Get an AI explanation of a vulnerability in plain English. Pass the OSV ID.',
    parameters: { type: 'object', properties: { osvId: { type: 'string', description: 'OSV vulnerability ID' } }, required: ['osvId'] },
  },
  async (params: { osvId: string }): Promise<ActionResult> => {
    const { data } = await supabase
      .from('dependency_vulnerabilities')
      .select('osv_id, severity, summary, details')
      .eq('osv_id', params.osvId)
      .single();
    if (!data) return { success: false, error: 'Vulnerability not found' };

    return { success: true, data: {
      instruction: 'Explain this vulnerability to the user in clear, non-technical language. Include severity, impact, and recommended actions.',
      context: wrapUntrusted('advisory', `${data.osv_id} (${data.severity}): ${data.summary}\n\n${data.details || ''}`),
    }};
  }
);

registerAction(
  {
    name: 'suggestFixPriority',
    description: 'Suggest which vulnerabilities and issues to fix first for a project, with reasoning',
    parameters: { type: 'object', properties: { projectId: { type: 'string', description: 'Project ID' } }, required: ['projectId'] },
  },
  async (params: { projectId: string }): Promise<ActionResult> => {
    const { data: vulns } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('depscore, epss_score, cisa_kev, is_reachable, suppressed, sla_status, sla_deadline_at, dependency_vulnerabilities!inner(osv_id, severity), project_dependencies!inner(dependencies!inner(name))')
      .eq('project_id', params.projectId)
      .eq('suppressed', false)
      .eq('risk_accepted', false)
      .order('depscore', { ascending: false })
      .limit(20);

    const { data: semgrep } = await supabase
      .from('project_semgrep_findings')
      .select('rule_id, severity, message, path')
      .eq('project_id', params.projectId)
      .limit(5);

    const { data: secrets } = await supabase
      .from('project_secret_findings')
      .select('detector_type, file_path, verified, is_current')
      .eq('project_id', params.projectId)
      .eq('is_current', true)
      .limit(5);

    const vulnList = (vulns || []).map((v: any) => ({
      osvId: v.dependency_vulnerabilities?.osv_id,
      severity: v.dependency_vulnerabilities?.severity,
      package: v.project_dependencies?.dependencies?.name,
      depscore: v.depscore,
      epss: v.epss_score,
      cisaKev: v.cisa_kev,
      reachable: v.is_reachable,
      sla_status: v.sla_status ?? null,
      sla_deadline_at: v.sla_deadline_at ?? null,
    }));
    const slaOrder = (a: { sla_status?: string | null }, b: { sla_status?: string | null }) => {
      const order = (s: string | null) => (s === 'breached' ? 0 : s === 'warning' ? 1 : 2);
      return order(a.sla_status ?? null) - order(b.sla_status ?? null);
    };
    vulnList.sort(slaOrder);

    return { success: true, data: {
      instruction: 'Analyze these findings and suggest a prioritized fix order with reasoning. Breached SLA items must be prioritized first, then warning, then by depscore.',
      vulnerabilities: vulnList.slice(0, 10),
      codeIssues: (semgrep || []).map(f => ({ ruleId: f.rule_id, severity: f.severity, path: f.path })),
      exposedSecrets: (secrets || []).map(s => ({ type: s.detector_type, file: s.file_path, verified: s.verified })),
    }};
  }
);

registerAction(
  {
    name: 'analyzeReachability',
    description: 'Assess whether a vulnerability is actually reachable based on import analysis data',
    parameters: { type: 'object', properties: { projectId: { type: 'string', description: 'Project ID' }, osvId: { type: 'string', description: 'OSV vulnerability ID' } }, required: ['projectId', 'osvId'] },
  },
  async (params: { projectId: string; osvId: string }): Promise<ActionResult> => {
    const { data: vuln } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('is_reachable, project_dependencies!inner(id, dependency_id, files_importing_count, dependencies!inner(name))')
      .eq('project_id', params.projectId)
      .single();

    if (!vuln) return { success: false, error: 'Vulnerability not found in project' };

    const pdId = vuln.project_dependencies?.id;
    const { data: files } = await supabase
      .from('project_dependency_files')
      .select('file_path')
      .eq('project_dependency_id', pdId)
      .limit(20);

    const { data: functions } = await supabase
      .from('project_dependency_functions')
      .select('function_name, import_type')
      .eq('project_dependency_id', pdId)
      .limit(20);

    return { success: true, data: {
      package: vuln.project_dependencies?.dependencies?.name,
      isReachable: vuln.is_reachable,
      filesImporting: vuln.project_dependencies?.files_importing_count || 0,
      importingFiles: (files || []).map(f => f.file_path),
      importedFunctions: (functions || []).map(f => ({ name: f.function_name, type: f.import_type })),
    }};
  }
);

registerAction(
  {
    name: 'getSemgrepFindings',
    description: 'List Semgrep code security findings for a project',
    parameters: { type: 'object', properties: { projectId: { type: 'string', description: 'Project ID' } }, required: ['projectId'] },
  },
  async (params: { projectId: string }): Promise<ActionResult> => {
    const { data, error } = await supabase
      .from('project_semgrep_findings')
      .select('id, rule_id, severity, message, path, line_start, line_end')
      .eq('project_id', params.projectId)
      .order('severity', { ascending: true })
      .limit(20);
    if (error) return { success: false, error: error.message };
    return { success: true, data: data || [] };
  }
);

registerAction(
  {
    name: 'explainSemgrepFinding',
    description: 'Get an AI explanation of a Semgrep code finding',
    parameters: { type: 'object', properties: { findingId: { type: 'string', description: 'Semgrep finding ID' } }, required: ['findingId'] },
  },
  async (params: { findingId: string }): Promise<ActionResult> => {
    const { data } = await supabase
      .from('project_semgrep_findings')
      .select('rule_id, severity, message, path, line_start, line_end')
      .eq('id', params.findingId)
      .single();
    if (!data) return { success: false, error: 'Finding not found' };
    return { success: true, data: {
      instruction: 'Explain this Semgrep code security finding and suggest remediation.',
      context: wrapUntrusted('semgrep', `Rule: ${data.rule_id} (${data.severity})\nFile: ${data.path}:${data.line_start}\nMessage: ${data.message}`),
    }};
  }
);

registerAction(
  {
    name: 'getSecretFindings',
    description: 'List detected secret exposures in a project (redacted values only)',
    parameters: { type: 'object', properties: { projectId: { type: 'string', description: 'Project ID' } }, required: ['projectId'] },
  },
  async (params: { projectId: string }): Promise<ActionResult> => {
    const { data, error } = await supabase
      .from('project_secret_findings')
      .select('id, detector_type, file_path, line_number, verified, is_current')
      .eq('project_id', params.projectId)
      .eq('is_current', true)
      .limit(20);
    if (error) return { success: false, error: error.message };
    return { success: true, data: data || [] };
  }
);

registerAction(
  {
    name: 'explainSecretFinding',
    description: 'Get an AI explanation of a secret finding and recommended remediation (no secret values exposed)',
    parameters: { type: 'object', properties: { findingId: { type: 'string', description: 'Secret finding ID' } }, required: ['findingId'] },
  },
  async (params: { findingId: string }): Promise<ActionResult> => {
    const { data } = await supabase
      .from('project_secret_findings')
      .select('detector_type, file_path, line_number, verified, is_current')
      .eq('id', params.findingId)
      .single();
    if (!data) return { success: false, error: 'Finding not found' };
    return { success: true, data: {
      instruction: 'Explain the risk of this secret exposure and suggest remediation steps. You do NOT have access to the secret value.',
      context: wrapUntrusted('secret', `Type: ${data.detector_type}\nFile: ${data.file_path}:${data.line_number}\nVerified: ${data.verified}\nCurrent: ${data.is_current}`),
    }};
  }
);

registerAction(
  {
    name: 'generateSecurityReport',
    description: 'Generate a comprehensive markdown security report for a project',
    parameters: { type: 'object', properties: { projectId: { type: 'string', description: 'Project ID' } }, required: ['projectId'] },
  },
  async (params: { projectId: string }): Promise<ActionResult> => {
    const { data: project } = await supabase
      .from('projects')
      .select('name, health_score, status_id, organization_statuses(name)')
      .eq('id', params.projectId)
      .single();

    const { data: vulnCount } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('id', { count: 'exact' })
      .eq('project_id', params.projectId)
      .eq('suppressed', false);

    const { data: semgrepCount } = await supabase
      .from('project_semgrep_findings')
      .select('id', { count: 'exact' })
      .eq('project_id', params.projectId);

    const { data: secretCount } = await supabase
      .from('project_secret_findings')
      .select('id', { count: 'exact' })
      .eq('project_id', params.projectId)
      .eq('is_current', true);

    const { data: topVulns } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('depscore, dependency_vulnerabilities!inner(osv_id, severity, summary), project_dependencies!inner(dependencies!inner(name))')
      .eq('project_id', params.projectId)
      .eq('suppressed', false)
      .order('depscore', { ascending: false })
      .limit(5);

    return { success: true, data: {
      instruction: 'Generate a comprehensive security report in markdown format. Include executive summary, key metrics, top risks, and recommended actions.',
      project: { name: project?.name, healthScore: project?.health_score, status: (project as any)?.organization_statuses?.name },
      metrics: {
        vulnerabilities: vulnCount ?? 0,
        semgrepFindings: semgrepCount ?? 0,
        secretExposures: secretCount ?? 0,
      },
      topVulnerabilities: (topVulns || []).map(v => ({
        osvId: v.dependency_vulnerabilities?.osv_id,
        severity: v.dependency_vulnerabilities?.severity,
        summary: v.dependency_vulnerabilities?.summary,
        package: v.project_dependencies?.dependencies?.name,
        depscore: v.depscore,
      })),
    }};
  }
);

registerAction(
  {
    name: 'getVersionCandidates',
    description: 'Get upgrade version recommendations for a dependency in a project',
    parameters: { type: 'object', properties: { projectId: { type: 'string', description: 'Project ID' }, packageName: { type: 'string', description: 'Package name' } }, required: ['projectId', 'packageName'] },
  },
  async (params: { projectId: string; packageName: string }): Promise<ActionResult> => {
    const { data } = await supabase
      .from('project_version_candidates')
      .select('*, dependencies!inner(name)')
      .eq('project_id', params.projectId)
      .eq('dependencies.name', params.packageName)
      .single();
    if (!data) return { success: false, error: 'No version candidates found for this package' };
    return { success: true, data: {
      package: params.packageName,
      sameMajorSafe: data.same_major_safe,
      fullySafe: data.fully_safe,
      latest: data.latest,
    }};
  }
);

registerAction(
  {
    name: 'triggerAiFix',
    description: 'Trigger AI-powered fixing for a vulnerability, Semgrep finding, or secret. Returns job ID for tracking.',
    parameters: {
      type: 'object',
      properties: {
        projectId: { type: 'string', description: 'Project ID' },
        strategy: { type: 'string', enum: ['bump_version', 'code_patch', 'add_wrapper', 'pin_transitive', 'remove_unused', 'fix_semgrep', 'remediate_secret'], description: 'Fix strategy' },
        osvId: { type: 'string', description: 'OSV ID for vulnerability fixes' },
        dependencyId: { type: 'string', description: 'Dependency ID' },
        projectDependencyId: { type: 'string', description: 'Project dependency ID' },
        targetVersion: { type: 'string', description: 'Target version for bump_version strategy' },
        semgrepFindingId: { type: 'string', description: 'Semgrep finding ID for fix_semgrep strategy' },
        secretFindingId: { type: 'string', description: 'Secret finding ID for remediate_secret strategy' },
      },
      required: ['projectId', 'strategy'],
    },
  },
  async (params: {
    projectId: string;
    strategy: string;
    osvId?: string;
    dependencyId?: string;
    projectDependencyId?: string;
    targetVersion?: string;
    semgrepFindingId?: string;
    secretFindingId?: string;
  }, ctx: ActionContext): Promise<ActionResult> => {
    const { requestFix, checkExistingFix } = await import('../../ai-fix-engine');

    const fixType = params.semgrepFindingId ? 'semgrep' as const : params.secretFindingId ? 'secret' as const : 'vulnerability' as const;

    const existing = await checkExistingFix(params.projectId, {
      type: fixType,
      osvId: params.osvId,
      semgrepFindingId: params.semgrepFindingId,
      secretFindingId: params.secretFindingId,
    });

    if (existing.hasActiveFix) {
      return { success: true, data: {
        alreadyRunning: true,
        status: existing.fix?.status,
        message: existing.message,
        jobId: existing.fix?.id,
      }};
    }

    if (existing.hasCompletedFix) {
      return { success: true, data: {
        alreadyCompleted: true,
        prUrl: existing.fix?.pr_url,
        prNumber: existing.fix?.pr_number,
        message: existing.message,
      }};
    }

    const result = await requestFix({
      projectId: params.projectId,
      organizationId: ctx.organizationId,
      userId: ctx.userId,
      strategy: params.strategy as any,
      vulnerabilityOsvId: params.osvId,
      dependencyId: params.dependencyId,
      projectDependencyId: params.projectDependencyId,
      targetVersion: params.targetVersion,
      semgrepFindingId: params.semgrepFindingId,
      secretFindingId: params.secretFindingId,
    });

    if (!result.success) {
      return { success: false, error: result.error };
    }

    return { success: true, data: {
      jobId: result.jobId,
      message: `Fix job queued. Strategy: ${params.strategy}. I'll track the progress.`,
    }};
  }
);

registerAction(
  {
    name: 'getFixStatus',
    description: 'Get the status of AI fix jobs for a project, optionally filtered by vulnerability or finding',
    parameters: {
      type: 'object',
      properties: {
        projectId: { type: 'string', description: 'Project ID' },
        osvId: { type: 'string', description: 'Filter by OSV ID' },
        semgrepFindingId: { type: 'string', description: 'Filter by Semgrep finding ID' },
        secretFindingId: { type: 'string', description: 'Filter by secret finding ID' },
      },
      required: ['projectId'],
    },
  },
  async (params: { projectId: string; osvId?: string; semgrepFindingId?: string; secretFindingId?: string }): Promise<ActionResult> => {
    const { getFixHistory } = await import('../../ai-fix-engine');
    const fixes = await getFixHistory(params.projectId, {
      osvId: params.osvId,
      semgrepFindingId: params.semgrepFindingId,
      secretFindingId: params.secretFindingId,
    });

    return { success: true, data: fixes.map(f => ({
      id: f.id,
      status: f.status,
      strategy: f.strategy,
      osvId: f.osv_id,
      prUrl: f.pr_url,
      prNumber: f.pr_number,
      errorMessage: f.error_message,
      errorCategory: f.error_category,
      createdAt: f.created_at,
      completedAt: f.completed_at,
    }))};
  }
);
