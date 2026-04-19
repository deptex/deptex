// @ts-nocheck
import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../lib/supabase';

registerAegisTool(
  'getPackageReputation',
  { category: 'intelligence', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Get reputation score and breakdown for a package. Queries dependencies and optionally package_reputation_scores.',
    parameters: z.object({
      packageName: z.string(),
    }),
    execute: async ({ packageName }) => {
      const { data: dep } = await supabase
        .from('dependencies')
        .select('id, name, score, openssf_score, weekly_downloads, license, last_published_at, releases_last_12_months, ecosystem')
        .eq('name', packageName)
        .single();
      if (!dep) return JSON.stringify({ error: `Package "${packageName}" not found.` });
      const { data: rep } = await supabase
        .from('package_reputation_scores')
        .select('*')
        .eq('dependency_id', dep.id)
        .single();
      const result = {
        packageName: dep.name,
        score: dep.score ?? rep?.score ?? null,
        openssfScore: dep.openssf_score,
        weeklyDownloads: dep.weekly_downloads,
        license: dep.license,
        lastPublishedAt: dep.last_published_at,
        releasesLast12Months: dep.releases_last_12_months,
        ecosystem: dep.ecosystem,
        breakdown: rep?.signals ?? null,
      };
      return JSON.stringify(result);
    },
  })
);

registerAegisTool(
  'analyzeUpgradePath',
  { category: 'intelligence', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Analyze upgrade options for a package. Finds safe versions considering vulnerabilities.',
    parameters: z.object({
      packageName: z.string(),
      currentVersion: z.string(),
    }),
    execute: async ({ packageName, currentVersion }) => {
      const { data: dep } = await supabase.from('dependencies').select('id, name, latest_version').eq('name', packageName).single();
      if (!dep) return JSON.stringify({ error: `Package "${packageName}" not found.` });
      const { data: versions } = await supabase
        .from('dependency_versions')
        .select('id, version, critical_vulns, high_vulns, medium_vulns, low_vulns')
        .eq('dependency_id', dep.id)
        .order('version', { ascending: false })
        .limit(50);
      const vulnMap = new Map<string, { critical: number; high: number; medium: number; low: number }>();
      for (const v of versions ?? []) {
        vulnMap.set(v.version, {
          critical: v.critical_vulns ?? 0,
          high: v.high_vulns ?? 0,
          medium: v.medium_vulns ?? 0,
          low: v.low_vulns ?? 0,
        });
      }
      const safeVersions = (versions ?? []).filter((v: any) => (v.critical_vulns ?? 0) === 0 && (v.high_vulns ?? 0) === 0);
      const upgradePath = safeVersions.length > 0
        ? { recommended: safeVersions[0].version, safeCount: safeVersions.length, allSafe: safeVersions.slice(0, 10).map((x: any) => x.version) }
        : { recommended: dep.latest_version, safeCount: 0, note: 'No vulnerability-free version found; latest may still be safer.' };
      return JSON.stringify({
        packageName,
        currentVersion,
        latestVersion: dep.latest_version,
        upgradePath,
        versionCount: versions?.length ?? 0,
      });
    },
  })
);

registerAegisTool(
  'getEPSSTrends',
  { category: 'intelligence', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Get EPSS score data for a vulnerability across projects.',
    parameters: z.object({
      osvId: z.string(),
    }),
    execute: async ({ osvId }) => {
      const { data: pdvs } = await supabase
        .from('project_dependency_vulnerabilities')
        .select('epss_score, cvss_score, project_id')
        .eq('osv_id', osvId);
      const scores = (pdvs ?? []).map((p: any) => ({ epss: p.epss_score, cvss: p.cvss_score, projectId: p.project_id })).filter((s: any) => s.epss != null || s.cvss != null);
      const avgEpss = scores.length ? scores.reduce((a: number, s: any) => a + (s.epss ?? 0), 0) / scores.filter((s: any) => s.epss != null).length : null;
      return JSON.stringify({ osvId, epssScores: scores, avgEpss, count: scores.length });
    },
  })
);

registerAegisTool(
  'checkCISAKEV',
  { category: 'intelligence', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Check if a vulnerability is in CISA KEV catalog.',
    parameters: z.object({
      osvId: z.string(),
    }),
    execute: async ({ osvId }) => {
      const { data: pdvs } = await supabase
        .from('project_dependency_vulnerabilities')
        .select('cisa_kev, severity')
        .eq('osv_id', osvId)
        .limit(1);
      const p = pdvs?.[0] as { cisa_kev?: boolean; severity?: string } | undefined;
      return JSON.stringify({
        osvId,
        inCisaKev: p?.cisa_kev ?? false,
        severity: p?.severity ?? null,
        message: p?.cisa_kev ? 'This vulnerability is in CISA KEV - prioritize remediation.' : 'Not listed in CISA KEV.',
      });
    },
  })
);

registerAegisTool(
  'searchPackages',
  { category: 'intelligence', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Search for packages by name. Uses ILIKE on dependencies table.',
    parameters: z.object({
      query: z.string(),
      ecosystem: z.string().optional(),
    }),
    execute: async ({ query, ecosystem }) => {
      let q = supabase
        .from('dependencies')
        .select('name, ecosystem, score, latest_version, weekly_downloads')
        .ilike('name', `%${query}%`)
        .limit(20);
      if (ecosystem) q = q.eq('ecosystem', ecosystem);
      const { data, error } = await q;
      if (error) return JSON.stringify({ error: error.message });
      return JSON.stringify({ query, ecosystem: ecosystem ?? 'any', packages: data ?? [], count: data?.length ?? 0 });
    },
  })
);

registerAegisTool(
  'analyzeNewDependency',
  { category: 'intelligence', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Risk assessment for adding a new dependency. Aggregates reputation, vulnerabilities, license.',
    parameters: z.object({
      packageName: z.string(),
      ecosystem: z.string().optional(),
    }),
    execute: async ({ packageName, ecosystem }) => {
      const { data: dep } = await supabase
        .from('dependencies')
        .select('id, name, score, openssf_score, license, weekly_downloads, is_malicious, ecosystem')
        .eq('name', packageName)
        .single();
      if (!dep) return JSON.stringify({ error: `Package "${packageName}" not found. Run extraction or add to a project first.` });
      const { data: vulns } = await supabase
        .from('dependency_vulnerabilities')
        .select('osv_id, severity')
        .eq('dependency_id', dep.id);
      const critical = (vulns ?? []).filter((v: any) => v.severity === 'critical').length;
      const high = (vulns ?? []).filter((v: any) => v.severity === 'high').length;
      const riskScore = dep.is_malicious ? 100 : Math.min(100, (critical * 25) + (high * 10) + (dep.score != null ? 100 - dep.score : 30));
      const recommendation = dep.is_malicious ? 'DO NOT ADD - flagged as malicious'
        : critical > 0 ? 'High risk - has critical vulnerabilities'
        : high > 0 ? 'Moderate risk - has high severity vulnerabilities'
        : (dep.score ?? 50) < 40 ? 'Caution - low reputation score'
        : 'Generally acceptable - review license and maintenance';
      return JSON.stringify({
        packageName: dep.name,
        ecosystem: dep.ecosystem ?? ecosystem,
        license: dep.license,
        score: dep.score,
        openssfScore: dep.openssf_score,
        weeklyDownloads: dep.weekly_downloads,
        vulnCount: vulns?.length ?? 0,
        criticalCount: critical,
        highCount: high,
        isMalicious: dep.is_malicious ?? false,
        riskScore,
        recommendation,
      });
    },
  })
);
