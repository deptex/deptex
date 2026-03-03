import express from 'express';
import { supabase as getSupabaseClient } from '../lib/supabase';

const router = express.Router();

const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY?.trim();

function requireInternalKey(req: express.Request, res: express.Response, next: express.NextFunction) {
  const raw =
    (req.headers['x-internal-api-key'] as string) ||
    (req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.slice(7)
      : undefined);
  const key = raw?.trim();
  if (!INTERNAL_API_KEY || key !== INTERNAL_API_KEY) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
}

router.use(requireInternalKey);

const MAX_PROJECTS_PER_RUN = 10;
const TIMEOUT_MS = 90_000;
const MAX_REGISTRY_CALLS_PER_PROJECT = 30;

router.post('/', async (_req, res) => {
  const startTime = Date.now();
  const supabase = getSupabaseClient;

  try {
    const { data: dueProjects, error: queryError } = await supabase
      .from('projects')
      .select('id, organization_id, last_vuln_check_at, vuln_check_frequency')
      .or('last_vuln_check_at.is.null,last_vuln_check_at.lt.' + getCheckCutoff())
      .order('last_vuln_check_at', { ascending: true, nullsFirst: true })
      .limit(MAX_PROJECTS_PER_RUN);

    if (queryError) {
      console.error('[VulnCheck] Query error:', queryError.message);
      return res.status(500).json({ error: queryError.message });
    }

    if (!dueProjects?.length) {
      return res.json({ processed: 0, message: 'No projects due for vulnerability check' });
    }

    let processed = 0;
    const results: Array<{ projectId: string; newVulns: number; resolvedVulns: number; error?: string }> = [];

    for (const project of dueProjects) {
      if (Date.now() - startTime > TIMEOUT_MS) {
        console.log(`[VulnCheck] Timeout approaching after ${processed} projects, stopping`);
        break;
      }

      try {
        const result = await checkProjectVulnerabilities(supabase, project.id, project.organization_id);
        results.push({ projectId: project.id, ...result });

        await supabase
          .from('projects')
          .update({ last_vuln_check_at: new Date().toISOString() })
          .eq('id', project.id);

        processed++;
      } catch (err: any) {
        console.error(`[VulnCheck] Error checking project ${project.id}:`, err.message);
        results.push({ projectId: project.id, newVulns: 0, resolvedVulns: 0, error: err.message });
      }
    }

    console.log(`[VulnCheck] Processed ${processed}/${dueProjects.length} projects`);
    res.json({ processed, total_due: dueProjects.length, results });
  } catch (error: any) {
    console.error('[VulnCheck] Error:', error);
    res.status(500).json({ error: error.message || 'Vulnerability check failed' });
  }
});

function getCheckCutoff(): string {
  const cutoff = new Date(Date.now() - 12 * 60 * 60 * 1000);
  return cutoff.toISOString();
}

async function checkProjectVulnerabilities(
  supabase: any,
  projectId: string,
  organizationId: string
): Promise<{ newVulns: number; resolvedVulns: number }> {
  const { data: deps } = await supabase
    .from('project_dependencies')
    .select('id, dependency_id, version, dependencies!inner(name, ecosystem)')
    .eq('project_id', projectId)
    .eq('is_direct', true);

  if (!deps?.length) return { newVulns: 0, resolvedVulns: 0 };

  const packages = deps.map((d: any) => ({
    package: { name: d.dependencies.name, ecosystem: mapEcosystem(d.dependencies.ecosystem) },
    version: d.version,
  }));

  // Batch OSV query (max 1000 per batch)
  const batches: any[][] = [];
  for (let i = 0; i < packages.length; i += 1000) {
    batches.push(packages.slice(i, i + 1000));
  }

  let newVulns = 0;
  let resolvedVulns = 0;
  let registryCalls = 0;

  for (const batch of batches) {
    try {
      const response = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: batch }),
      });

      if (!response.ok) {
        console.warn(`[VulnCheck] OSV batch query returned ${response.status}`);
        continue;
      }

      const result = (await response.json()) as { results?: Array<{ vulns?: { id: string }[] }> };
      const results = result.results || [];

      for (let i = 0; i < results.length; i++) {
        const osvVulns = results[i]?.vulns || [];
        const dep = deps[i];
        if (!dep) continue;

        const { data: existingVulns } = await supabase
          .from('project_dependency_vulnerabilities')
          .select('id, dependency_vulnerabilities!inner(osv_id)')
          .eq('project_id', projectId)
          .eq('project_dependency_id', dep.id);

        const existingOsvIds = new Set((existingVulns || []).map((v: any) => v.dependency_vulnerabilities?.osv_id));
        const currentOsvIds = new Set(osvVulns.map((v: any) => v.id));

        // Detect new vulnerabilities
        for (const osv of osvVulns) {
          if (!existingOsvIds.has(osv.id)) {
            newVulns++;

            // Log detected event (idempotent via dedup)
            await supabase.from('project_vulnerability_events').upsert({
              project_id: projectId,
              osv_id: osv.id,
              event_type: 'detected',
              project_dependency_id: dep.id,
            }, { onConflict: 'project_id,osv_id,event_type', ignoreDuplicates: true }).then(() => {});
          }
        }

        // Detect resolved vulnerabilities
        for (const existing of (existingVulns || [])) {
          const osvId = existing.dependency_vulnerabilities?.osv_id;
          if (osvId && !currentOsvIds.has(osvId)) {
            resolvedVulns++;

            await supabase.from('project_vulnerability_events').upsert({
              project_id: projectId,
              osv_id: osvId,
              event_type: 'resolved',
              project_dependency_id: dep.id,
            }, { onConflict: 'project_id,osv_id,event_type', ignoreDuplicates: true }).then(() => {});
          }
        }

        // Check for version candidates if vulnerable
        if (osvVulns.length > 0 && registryCalls < MAX_REGISTRY_CALLS_PER_PROJECT) {
          registryCalls++;
        }
      }
    } catch (err: any) {
      console.warn(`[VulnCheck] OSV batch error:`, err.message);
    }
  }

  return { newVulns, resolvedVulns };
}

function mapEcosystem(ecosystem: string): string {
  const mapping: Record<string, string> = {
    npm: 'npm',
    pypi: 'PyPI',
    maven: 'Maven',
    golang: 'Go',
    cargo: 'crates.io',
    gem: 'RubyGems',
    composer: 'Packagist',
    nuget: 'NuGet',
    pub: 'Pub',
    hex: 'Hex',
    swift: 'SwiftURL',
  };
  return mapping[ecosystem] || ecosystem;
}

export default router;
