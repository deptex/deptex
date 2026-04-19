import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../../../backend/src/lib/supabase';
import { getCached, setCached } from '../../cache';

registerAegisTool(
  'getComplianceStatus',
  { category: 'compliance', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Get compliance summary for a project. Counts policy violations from project_dependencies.policy_result.',
    parameters: z.object({
      projectId: z.string().uuid(),
    }),
    execute: async ({ projectId }) => {
      const { data: deps, error } = await supabase
        .from('project_dependencies')
        .select('id, policy_result')
        .eq('project_id', projectId);
      if (error) return JSON.stringify({ error: error.message });
      let violations = 0;
      const violationReasons: string[] = [];
      for (const d of deps ?? []) {
        const pr = d.policy_result as { allowed?: boolean; reasons?: string[] } | null;
        if (pr && pr.allowed === false) {
          violations++;
          if (pr.reasons?.length) violationReasons.push(...pr.reasons.slice(0, 3));
        }
      }
      const { data: project } = await supabase.from('projects').select('name, status_id, status_violations').eq('id', projectId).single();
      return JSON.stringify({
        projectId,
        projectName: project?.name,
        totalDependencies: deps?.length ?? 0,
        policyViolations: violations,
        violationReasons: violationReasons.slice(0, 10),
        statusViolations: project?.status_violations ?? [],
      });
    },
  })
);

registerAegisTool(
  'generateSBOM',
  { category: 'compliance', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Return a link or path to the SBOM JSON for a project from Supabase Storage.',
    parameters: z.object({
      projectId: z.string().uuid(),
    }),
    execute: async ({ projectId }) => {
      const { data: latestJob } = await supabase
        .from('extraction_jobs')
        .select('id, completed_at')
        .eq('project_id', projectId)
        .eq('status', 'completed')
        .order('completed_at', { ascending: false })
        .limit(1)
        .single();
      if (!latestJob) return JSON.stringify({ error: 'No SBOM available. Run an extraction first.' });
      const path = `${projectId}/${latestJob.id}/sbom.json`;
      const { data: urlData } = await supabase.storage.from('project-imports').createSignedUrl(path, 3600);
      return JSON.stringify({
        projectId,
        storagePath: `project-imports/${path}`,
        signedUrl: urlData?.signedUrl ?? null,
        completedAt: latestJob.completed_at,
        message: urlData?.signedUrl ? 'Use the signedUrl to download. Expires in 1 hour.' : 'Could not create signed URL.',
      });
    },
  })
);

registerAegisTool(
  'generateVEX',
  { category: 'compliance', permissionLevel: 'moderate', requiredRbacPermissions: ['manage_compliance'] },
  tool({
    description: 'Generate a VEX (Vulnerability Exploitability eXchange) document. Unreachable vulns -> not_affected, reachable -> affected.',
    parameters: z.object({
      projectId: z.string().uuid(),
      osvIds: z.array(z.string()).optional(),
    }),
    execute: async ({ projectId, osvIds }) => {
      const { data: pdvs } = await supabase
        .from('project_dependency_vulnerabilities')
        .select('osv_id, reachability_level, is_reachable')
        .eq('project_id', projectId);
      if (!pdvs?.length) return JSON.stringify({ error: 'No vulnerability data for this project.' });
      const filtered = osvIds?.length ? pdvs.filter((p: any) => osvIds.includes(p.osv_id)) : pdvs;
      const entries: Array<{ osv_id: string; status: string; justification?: string }> = filtered.map((p: any) => {
        const reachable = p.reachability_level === 'data_flow' || p.reachability_level === 'function' || p.reachability_level === 'confirmed' || p.is_reachable;
        return {
          osv_id: p.osv_id,
          status: reachable ? 'affected' : 'not_affected',
          justification: reachable ? 'Code is reachable' : 'Vulnerable code is not reachable from application entry points',
        };
      });
      const vex = {
        vex_version: '1.0',
        timestamp: new Date().toISOString(),
        project_id: projectId,
        vulnerabilities: entries,
      };
      return JSON.stringify(vex);
    },
  })
);

registerAegisTool(
  'generateLicenseNotice',
  { category: 'compliance', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Get the license notice (THIRD-PARTY-NOTICES) for a project. Reuses cached logic.',
    parameters: z.object({
      projectId: z.string().uuid(),
    }),
    execute: async ({ projectId }) => {
      const cacheKey = `legal-notice:${projectId}`;
      let notice = await getCached<string>(cacheKey);
      if (notice) return JSON.stringify({ notice, cached: true });
      const { data: project } = await supabase.from('projects').select('name').eq('id', projectId).single();
      const { data: deps } = await supabase.from('project_dependencies').select('name, version, license').eq('project_id', projectId);
      if (!deps?.length) return JSON.stringify({ error: 'No dependencies found. Run an extraction first.' });
      const { data: obligations } = await supabase
        .from('license_obligations')
        .select('license_spdx_id, summary, full_text, is_copyleft, is_weak_copyleft');
      const obligationMap = new Map<string, any>();
      for (const ob of obligations ?? []) obligationMap.set(ob.license_spdx_id, ob);
      const lines: string[] = [
        'THIRD-PARTY SOFTWARE NOTICES AND INFORMATION',
        `Project: ${project?.name ?? 'project'}`,
        `Generated: ${new Date().toISOString()}`,
        'Generated by: Deptex',
        '',
        'This project incorporates components from the projects listed below.',
        '',
        '='.repeat(70),
        '',
      ];
      const grouped = new Map<string, typeof deps>();
      for (const dep of deps) {
        const license = dep.license || 'Unknown';
        if (!grouped.has(license)) grouped.set(license, []);
        grouped.get(license)!.push(dep);
      }
      for (const license of [...grouped.keys()].sort()) {
        const pkgs = grouped.get(license)!;
        const ob = obligationMap.get(license);
        lines.push(`LICENSE: ${license}`);
        if (ob?.summary) lines.push(`Obligations: ${ob.summary}`);
        lines.push('-'.repeat(70));
        for (const pkg of pkgs.sort((a: any, b: any) => a.name.localeCompare(b.name))) {
          lines.push(`  - ${pkg.name}@${pkg.version}`);
          lines.push('    Copyright: see package metadata');
        }
        lines.push('');
        if (ob?.full_text && (ob.is_copyleft || ob.is_weak_copyleft)) {
          lines.push(`Full License Text (${license}):`);
          lines.push(ob.full_text);
          lines.push('');
        }
      }
      lines.push('='.repeat(70));
      lines.push(`Generated by Deptex at ${new Date().toISOString()}`);
      notice = lines.join('\n');
      await setCached(cacheKey, notice, 3600);
      return JSON.stringify({ notice, cached: false });
    },
  })
);

registerAegisTool(
  'generateAuditPackage',
  { category: 'compliance', permissionLevel: 'moderate', requiredRbacPermissions: ['manage_compliance'] },
  tool({
    description: 'Bundle SBOM + VEX + license notice into an audit package and store in Supabase Storage.',
    parameters: z.object({
      projectId: z.string().uuid(),
      framework: z.string().optional(),
    }),
    execute: async ({ projectId, framework }) => {
      const { data: project } = await supabase.from('projects').select('name').eq('id', projectId).single();
      if (!project) return JSON.stringify({ error: 'Project not found' });
      const auditId = `audit-${Date.now()}`;
      const basePath = `audit-packages/${projectId}/${auditId}`;
      const { data: latestJob } = await supabase
        .from('extraction_jobs')
        .select('id')
        .eq('project_id', projectId)
        .eq('status', 'completed')
        .order('completed_at', { ascending: false })
        .limit(1)
        .single();
      const sbomPath = latestJob ? `${projectId}/${latestJob.id}/sbom.json` : null;
      const { data: sbomBlob } = sbomPath
        ? await supabase.storage.from('project-imports').download(sbomPath)
        : { data: null };
      if (sbomBlob) {
        await supabase.storage.from('project-imports').upload(`${basePath}/sbom.json`, sbomBlob, { upsert: true });
      }
      const { data: pdvs } = await supabase
        .from('project_dependency_vulnerabilities')
        .select('osv_id, reachability_level, is_reachable')
        .eq('project_id', projectId);
      const vexEntries = (pdvs ?? []).map((p: any) => ({
        osv_id: p.osv_id,
        status: (p.reachability_level === 'data_flow' || p.reachability_level === 'function' || p.reachability_level === 'confirmed' || p.is_reachable) ? 'affected' : 'not_affected',
        justification: 'VEX assessment',
      }));
      const vex = { vex_version: '1.0', timestamp: new Date().toISOString(), project_id: projectId, vulnerabilities: vexEntries };
      await supabase.storage.from('project-imports').upload(`${basePath}/vex.json`, Buffer.from(JSON.stringify(vex, null, 2)), {
        contentType: 'application/json',
        upsert: true,
      });
      const cacheKey = `legal-notice:${projectId}`;
      let notice = await getCached<string>(cacheKey);
      if (!notice) {
        const { data: deps } = await supabase.from('project_dependencies').select('name, version, license').eq('project_id', projectId);
        const { data: obligations } = await supabase.from('license_obligations').select('license_spdx_id, summary, full_text, is_copyleft, is_weak_copyleft');
        const obMap = new Map((obligations ?? []).map(o => [o.license_spdx_id, o]));
        const lineList = ['THIRD-PARTY SOFTWARE NOTICES', `Project: ${project.name}`, `Generated: ${new Date().toISOString()}`, ''];
        const byLicense = new Map<string, any[]>();
        for (const d of deps ?? []) {
          const lic = d.license || 'Unknown';
          if (!byLicense.has(lic)) byLicense.set(lic, []);
          byLicense.get(lic)!.push(d);
        }
        for (const lic of [...byLicense.keys()].sort()) {
          lineList.push(`LICENSE: ${lic}`);
          for (const p of byLicense.get(lic)!.sort((a, b) => (a.name as string).localeCompare(b.name as string))) {
            lineList.push(`  - ${p.name}@${p.version}`);
          }
          lineList.push('');
        }
        notice = lineList.join('\n');
      }
      await supabase.storage.from('project-imports').upload(`${basePath}/THIRD-PARTY-NOTICES.txt`, Buffer.from(notice, 'utf8'), { upsert: true });
      const manifest = { framework: framework ?? 'general', projectId, projectName: project.name, generatedAt: new Date().toISOString(), files: ['sbom.json', 'vex.json', 'THIRD-PARTY-NOTICES.txt'] };
      await supabase.storage.from('project-imports').upload(`${basePath}/manifest.json`, Buffer.from(JSON.stringify(manifest, null, 2)), {
        contentType: 'application/json',
        upsert: true,
      });
      const { data: signed } = await supabase.storage.from('project-imports').createSignedUrl(`${basePath}/manifest.json`, 86400);
      return JSON.stringify({
        success: true,
        auditId,
        storagePath: `project-imports/${basePath}`,
        manifestUrl: signed?.signedUrl,
        files: ['sbom.json', 'vex.json', 'THIRD-PARTY-NOTICES.txt', 'manifest.json'],
        message: 'Audit package created. Use manifest.json URL to access. Expires in 24 hours.',
      });
    },
  })
);
