/**
 * Extraction pipeline: clone -> cdxgen -> parse SBOM -> upsert deps -> queue populate -> AST import analysis -> dep-scan -> Semgrep -> TruffleHog -> upload -> update status
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync, spawnSync } from 'child_process';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { cloneRepository, cleanupRepository, cloneByProvider } from './clone';
import { parseSbom, getBomRefToNameVersion, type ParsedSbomDep, type ParsedSbomRelationship } from './sbom';
import { calculateDepscore, SEVERITY_TO_CVSS } from './depscore';
import { calculateDexcore, type AssetTier } from './dexcore';
import { analyzeRepository } from './ast-parser';
import { storeAstAnalysisResults } from './ast-storage';

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 2000;

async function retry<T>(fn: () => Promise<T>, stepName: string): Promise<T> {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (e: any) {
      console.error(`[${stepName}] Attempt ${attempt}/${MAX_RETRIES} failed:`, e.message);
      if (attempt === MAX_RETRIES) throw e;
      await new Promise((r) => setTimeout(r, RETRY_DELAY_MS * attempt));
    }
  }
  throw new Error('Unreachable');
}

function getSupabase(): SupabaseClient {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
  return createClient(url, key);
}

async function updateStep(
  supabase: SupabaseClient,
  projectId: string,
  step: string,
  status?: string
): Promise<void> {
  await supabase
    .from('project_repositories')
    .update({
      extraction_step: step,
      ...(status ? { status, extraction_error: null } : {}),
      updated_at: new Date().toISOString(),
    })
    .eq('project_id', projectId);
}

async function setError(
  supabase: SupabaseClient,
  projectId: string,
  message: string
): Promise<void> {
  await supabase
    .from('project_repositories')
    .update({
      status: 'error',
      extraction_error: message,
      extraction_step: null,
      updated_at: new Date().toISOString(),
    })
    .eq('project_id', projectId);
}

function runCdxgen(workspacePath: string): string {
  const outPath = path.join(workspacePath, 'sbom.json');
  try {
    execSync(`npx --yes @cyclonedx/cdxgen --path "${workspacePath}" -o "${outPath}"`, {
      stdio: 'pipe',
      timeout: 300000,
      maxBuffer: 50 * 1024 * 1024,
    });
  } catch (e: any) {
    throw new Error(`cdxgen failed: ${e.message}`);
  }
  return outPath;
}

async function callQueuePopulate(
  backendBaseUrl: string,
  workerSecret: string | undefined,
  projectId: string,
  organizationId: string,
  deps: Array<{ dependencyId: string; name: string }>,
  ecosystem: string
): Promise<void> {
  const url = `${backendBaseUrl.replace(/\/$/, '')}/api/workers/queue-populate`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (workerSecret) {
    headers['X-Worker-Secret'] = workerSecret;
  }
  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      projectId,
      organizationId,
      ecosystem,
      dependencies: deps.map((d) => ({ dependencyId: d.dependencyId, name: d.name, ecosystem })),
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`queue-populate failed: ${res.status} ${text}`);
  }
}

export interface ExtractionJob {
  projectId: string;
  organizationId: string;
  repo_full_name: string;
  installation_id: string;
  default_branch: string;
  package_json_path?: string;
  ecosystem?: string;
  provider?: string;
  integration_id?: string;
}

const log = (step: string, msg: string, data?: Record<string, unknown>) => {
  const extra = data ? ` ${JSON.stringify(data)}` : '';
  console.log(`[EXTRACT] [${step}] ${msg}${extra}`);
};

export async function runPipeline(job: ExtractionJob): Promise<void> {
  const supabase = getSupabase();
  const projectId = job.projectId;
  const organizationId = job.organizationId;
  const packageJsonPath = (job.package_json_path ?? '').trim();

  log('init', `Starting pipeline for project ${projectId}, repo ${job.repo_full_name}`, {
    package_json_path: packageJsonPath || '(root)',
  });

  let repoPath: string | null = null;

  try {
    await updateStep(supabase, projectId, 'cloning', 'extracting');
    log('clone', 'Cloning repository...');

    repoPath = await retry(
      () =>
        cloneByProvider(job),
      'clone'
    );

    log('clone', 'Repository cloned', { path: repoPath });

    const workspaceRoot = packageJsonPath
      ? path.join(repoPath, packageJsonPath)
      : repoPath;

    if (!fs.existsSync(workspaceRoot)) {
      throw new Error(`Workspace path does not exist: ${packageJsonPath || '(root)'}`);
    }

    await updateStep(supabase, projectId, 'sbom');
    log('sbom', 'Running cdxgen...');

    const sbomPath = await retry(() => Promise.resolve(runCdxgen(workspaceRoot)), 'cdxgen');
    const sbomContent = fs.readFileSync(sbomPath as string, 'utf8');
    const sbom = JSON.parse(sbomContent) as Parameters<typeof parseSbom>[0];

    const runId = Date.now().toString();
    const storagePath = `${projectId}/${runId}/sbom.json`;

    log('sbom', 'Uploading SBOM to storage', { path: storagePath });
    const { error: uploadError } = await supabase.storage
      .from('project-imports')
      .upload(storagePath, sbomContent, {
        contentType: 'application/json',
        upsert: true,
      });

    if (uploadError) {
      log('sbom', 'SBOM upload failed', { error: uploadError.message });
    }

    const { dependencies, relationships } = parseSbom(sbom);
    const bomRefMap = getBomRefToNameVersion(sbom);

    log('sbom', 'SBOM parsed', {
      components: dependencies.length,
      relationships: relationships.length,
    });

    if (dependencies.length === 0) {
      throw new Error('No dependencies found in SBOM');
    }

    await updateStep(supabase, projectId, 'deps_synced');
    log('deps', 'Upserting dependencies and project_dependencies...');

    const uniqueDeps = new Map<string, ParsedSbomDep>();
    for (const d of dependencies) {
      const key = `${d.name}@${d.version}`;
      if (!uniqueDeps.has(key)) uniqueDeps.set(key, d);
    }
    const uniqueNames = [...new Set(Array.from(uniqueDeps.values()).map((d) => d.name))];

    const nameToDependencyId = new Map<string, string>();
    const BATCH = 50;
    for (let i = 0; i < uniqueNames.length; i += BATCH) {
      const batch = uniqueNames.slice(i, i + BATCH);
      const { data } = await supabase.from('dependencies').select('id, name').in('name', batch);
      if (data) for (const r of data) nameToDependencyId.set(r.name, r.id);
    }
    const namesToCreate = uniqueNames.filter((n) => !nameToDependencyId.has(n));

    const nameToLicense = new Map<string, string | null>();
    for (const [, d] of uniqueDeps) {
      if (!nameToLicense.has(d.name)) nameToLicense.set(d.name, d.license);
    }

    const jobEcosystem = job.ecosystem || 'npm';

    for (let i = 0; i < namesToCreate.length; i += 100) {
      const batch = namesToCreate.slice(i, i + 100);
      const rows = batch.map((name) => ({
        name,
        license: nameToLicense.get(name) ?? null,
        ecosystem: jobEcosystem,
      }));
      const { data: inserted, error } = await supabase
        .from('dependencies')
        .insert(rows)
        .select('id, name');
      if (error) throw error;
      if (inserted) for (const r of inserted) nameToDependencyId.set(r.name, r.id);
    }

    const keyToVersionId = new Map<string, string>();
    const entries: Array<{ key: string; dependency_id: string; name: string; version: string }> = [];
    for (const [key, d] of uniqueDeps) {
      const did = nameToDependencyId.get(d.name);
      if (did) entries.push({ key, dependency_id: did, name: d.name, version: d.version });
    }

    const depIds = [...new Set(entries.map((e) => e.dependency_id))];
    const { data: existingVersions } = await supabase
      .from('dependency_versions')
      .select('id, dependency_id, version')
      .in('dependency_id', depIds);
    const existingMap = new Map<string, string>();
    if (existingVersions) {
      for (const r of existingVersions) {
        existingMap.set(`${r.dependency_id}|${r.version}`, r.id);
      }
    }

    const toInsert: Array<{ dependency_id: string; version: string }> = [];
    for (const e of entries) {
      const mapKey = `${e.dependency_id}|${e.version}`;
      const id = existingMap.get(mapKey);
      if (id) {
        keyToVersionId.set(e.key, id);
      } else {
        toInsert.push({ dependency_id: e.dependency_id, version: e.version });
      }
    }

    if (toInsert.length > 0) {
      const { data: insertedRows, error } = await supabase
        .from('dependency_versions')
        .insert(toInsert)
        .select('id, dependency_id, version');
      if (error) throw error;
      if (insertedRows) {
        for (const r of insertedRows) {
          existingMap.set(`${r.dependency_id}|${r.version}`, r.id);
        }
        for (const e of entries) {
          const id = existingMap.get(`${e.dependency_id}|${e.version}`);
          if (id) keyToVersionId.set(e.key, id);
        }
      }
    }

    const directNames = new Set(dependencies.filter((d) => d.is_direct).map((d) => d.name));
    const newDepsToPopulate = namesToCreate
      .filter((n) => directNames.has(n))
      .map((n) => ({ dependencyId: nameToDependencyId.get(n)!, name: n }))
      .filter((d) => d.dependencyId);

    const backendBaseUrl = process.env.BACKEND_URL || process.env.API_BASE_URL || 'http://localhost:3001';
    const workerSecret = process.env.EXTRACTION_WORKER_SECRET;
    if (newDepsToPopulate.length > 0) {
      log('populate', `Queuing populate for ${newDepsToPopulate.length} direct dependencies`);
      await callQueuePopulate(backendBaseUrl, workerSecret, projectId, organizationId, newDepsToPopulate, jobEcosystem);
    } else {
      log('populate', 'No new direct dependencies to populate');
    }

    await supabase.from('project_dependencies').delete().eq('project_id', projectId);
    log('deps', 'Cleared existing project_dependencies');

    const projectDepsRaw = dependencies.map((d) => {
      const key = `${d.name}@${d.version}`;
      return {
        project_id: projectId,
        dependency_id: nameToDependencyId.get(d.name) ?? null,
        dependency_version_id: keyToVersionId.get(key) ?? null,
        name: d.name,
        version: d.version,
        is_direct: d.is_direct,
        source: d.source,
        environment: d.source === 'dependencies' ? 'prod' : d.source === 'devDependencies' ? 'dev' : null,
      };
    });

    const dedupeKey = (r: { name: string; version: string; is_direct: boolean; source: string }) =>
      `${r.name}|${r.version}|${r.is_direct}|${r.source}`;
    const seenProjDep = new Set<string>();
    const projectDepsToInsert = projectDepsRaw.filter((r) => {
      const k = dedupeKey(r);
      if (seenProjDep.has(k)) return false;
      seenProjDep.add(k);
      return true;
    });

    log('deps', 'Inserting project_dependencies', {
      raw: projectDepsRaw.length,
      deduped: projectDepsToInsert.length,
    });

    for (let i = 0; i < projectDepsToInsert.length; i += 500) {
      const chunk = projectDepsToInsert.slice(i, i + 500);
      const { error } = await supabase.from('project_dependencies').insert(chunk);
      if (error) throw error;
    }

    const edgesToInsert: Array<{ parent_version_id: string; child_version_id: string }> = [];
    const seenEdges = new Set<string>();
    for (const rel of relationships) {
      const parentInfo = bomRefMap.get(rel.parentBomRef);
      const childInfo = bomRefMap.get(rel.childBomRef);
      if (!parentInfo || !childInfo) continue;
      const parentKey = `${parentInfo.name}@${parentInfo.version}`;
      const childKey = `${childInfo.name}@${childInfo.version}`;
      const parentVersionId = keyToVersionId.get(parentKey);
      const childVersionId = keyToVersionId.get(childKey);
      if (parentVersionId && childVersionId) {
        const edgeKey = `${parentVersionId}|${childVersionId}`;
        if (!seenEdges.has(edgeKey)) {
          seenEdges.add(edgeKey);
          edgesToInsert.push({ parent_version_id: parentVersionId, child_version_id: childVersionId });
        }
      }
    }

    for (let i = 0; i < edgesToInsert.length; i += 500) {
      const chunk = edgesToInsert.slice(i, i + 500);
      await supabase
        .from('dependency_version_edges')
        .upsert(chunk, { onConflict: 'parent_version_id,child_version_id', ignoreDuplicates: true });
    }

    // AST import analysis (JS/TS only; non-blocking -- failures do not abort the pipeline)
    let astParsedSuccessfully = false;
    await updateStep(supabase, projectId, 'ast_parsing');
    log('ast', 'Running AST import analysis...');
    try {
      const analysisResults = analyzeRepository(workspaceRoot);
      if (analysisResults.length > 0) {
        const storeResult = await storeAstAnalysisResults(supabase, projectId, organizationId, analysisResults);
        if (storeResult.success) {
          astParsedSuccessfully = true;
          log('ast', `AST analysis stored`, { filesWithImports: analysisResults.length });
        } else {
          log('ast', `AST storage failed (non-fatal): ${storeResult.error}`);
        }
      } else {
        astParsedSuccessfully = true;
        log('ast', 'No JS/TS imports found (repo may use a different ecosystem)');
      }
    } catch (e: any) {
      log('ast', `AST parsing failed (non-fatal): ${e.message}`);
    }

    await updateStep(supabase, projectId, 'scanning');
    log('scan', 'Running dep-scan...');

    const reportsDir = path.join(workspaceRoot, 'depscan-reports');
    try {
      fs.mkdirSync(reportsDir, { recursive: true });
      // Prefer native paths for spawnSync; depscan accepts Windows paths.
      const bomArg = sbomPath;
      const outArg = reportsDir;

      // On Windows, resolve depscan.exe without relying on PATH.
      let depScanExe = 'depscan';
      if (process.platform === 'win32') {
        // 1) Try "where depscan.exe" (fast path if Scripts is on PATH)
        try {
          const whereOut = execSync('where depscan.exe', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
          const first = whereOut.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)[0];
          if (first && fs.existsSync(first)) depScanExe = first;
        } catch {
          // ignore
        }

        // 2) Try locating via Python launcher if available
        if (depScanExe === 'depscan') {
          try {
            const scriptsDir = execSync('py -c "import sysconfig; print(sysconfig.get_path(\'scripts\'))"', {
              encoding: 'utf8',
              stdio: ['pipe', 'pipe', 'pipe'],
            }).trim();
            const exePath = path.join(scriptsDir, 'depscan.exe');
            if (fs.existsSync(exePath)) depScanExe = exePath;
          } catch {
            // ignore
          }
        }
      }

      const ecosystem = job.ecosystem || 'npm';
      const depScanArgs = [
        '--bom',
        bomArg,
        '--reports-dir',
        outArg,
        '-t',
        ecosystem,
        '--no-banner',
        '--vulnerability-analyzer',
        'VDRAnalyzer',
      ];
      if (process.env.DEPSCAN_EXPLAIN === '1') depScanArgs.push('--explain');

      log('scan', 'dep-scan command', { exe: depScanExe, args: depScanArgs });

      const res = spawnSync(depScanExe, depScanArgs, {
        cwd: workspaceRoot,
        encoding: 'utf8',
        timeout: 90 * 60 * 1000,
      });

      const stdoutTail = res.stdout ? res.stdout.slice(-2000) : null;
      const stderrTail = res.stderr ? res.stderr.slice(-2000) : null;
      log('scan', 'dep-scan finished', { status: res.status, stdoutTail, stderrTail });

      if (res.error || res.status !== 0) {
        throw new Error(res.error?.message || `dep-scan exited with status ${res.status}`);
      }
    } catch (e: unknown) {
      const err = e as { message?: string; stderr?: string };
      log('scan', 'dep-scan failed (not installed or error)', {
        hint: 'Run: pip install owasp-depscan (and on Windows ensure depscan.exe is on PATH)',
        error: String(err?.message ?? e),
      });
    }

    // dep-scan v6 creates .vdr.json; older versions may create dep-scan.json. It may write to -o, cwd, or a nested reports directory.
    const listVdrFiles = (dir: string): string[] => {
      try {
        return fs
          .readdirSync(dir, { withFileTypes: true })
          .filter((d) => d.isFile() && (d.name.endsWith('.vdr.json') || d.name === 'dep-scan.json'))
          .map((d) => path.join(dir, d.name));
      } catch {
        return [];
      }
    };

    const vdrInReports = listVdrFiles(reportsDir);
    const vdrInRoot = listVdrFiles(workspaceRoot);
    let vdrFiles = [...vdrInReports, ...vdrInRoot];

    // As a fallback, recursively search under workspaceRoot for any VDR JSON output
    if (vdrFiles.length === 0) {
      const isVdrFile = (name: string) => name.endsWith('.vdr.json') || name === 'dep-scan.json';
      const seenDirs = new Set<string>();
      const stack: string[] = [workspaceRoot];
      const found: string[] = [];
      const MAX_DIRS = 5000;

      while (stack.length > 0 && seenDirs.size < MAX_DIRS && found.length === 0) {
        const dir = stack.pop()!;
        if (seenDirs.has(dir)) continue;
        seenDirs.add(dir);
        let entries: fs.Dirent[];
        try {
          entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch {
          continue;
        }
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            stack.push(fullPath);
          } else if (entry.isFile() && isVdrFile(entry.name)) {
            found.push(fullPath);
          }
        }
      }

      if (found.length > 0) {
        vdrFiles = found;
      }
    }

    const tryParseJson = (p: string): Record<string, unknown> | null => {
      try {
        const content = fs.readFileSync(p, 'utf8');
        return JSON.parse(content) as Record<string, unknown>;
      } catch {
        return null;
      }
    };

    // In some dep-scan configurations, the VDR content is written to a plain .json (e.g. sbom.json) rather than *.vdr.json.
    // Prefer explicit VDR outputs, but fall back to "any JSON in reportsDir that actually contains a vulnerabilities array".
    const candidatePaths: string[] = [];
    const addCandidate = (p: string) => {
      if (!p) return;
      if (candidatePaths.includes(p)) return;
      if (!fs.existsSync(p)) return;
      candidatePaths.push(p);
    };

    for (const p of vdrFiles) addCandidate(p);

    try {
      for (const d of fs.readdirSync(reportsDir, { withFileTypes: true })) {
        if (d.isFile() && d.name.endsWith('.json')) addCandidate(path.join(reportsDir, d.name));
      }
    } catch {
      // ignore
    }

    let depScanPath: string | null = null;
    for (const p of candidatePaths) {
      const parsed = tryParseJson(p);
      const vulns = parsed && (parsed as { vulnerabilities?: unknown }).vulnerabilities;
      if (Array.isArray(vulns)) {
        depScanPath = p;
        break;
      }
    }

    if (!depScanPath) {
      // Legacy fallback paths
      depScanPath = vdrFiles[0] ?? path.join(workspaceRoot, 'dep-scan.json');
    }

    const reportExists = fs.existsSync(depScanPath);

    if (!reportExists) {
      const reportsDirContents = (() => {
        try {
          return fs.readdirSync(reportsDir, { withFileTypes: true }).map((d) => d.isFile() ? d.name : `${d.name}/`);
        } catch {
          return ['(dir missing or unreadable)'];
        }
      })();
      const rootContents = (() => {
        try {
          return fs.readdirSync(workspaceRoot, { withFileTypes: true })
            .filter((d) => d.name.endsWith('.json') || d.name.endsWith('.vdr.json'))
            .map((d) => d.name);
        } catch {
          return [];
        }
      })();
      log('scan', 'dep-scan report not found; skipping vulnerability upload', {
        reportsDir,
        reportsDirContents,
        workspaceRootJsonFiles: rootContents,
        hint: 'dep-scan may not be installed (pip install owasp-depscan)',
      });
    }

    if (reportExists) {
      log('scan', 'dep-scan report found; uploading and processing vulnerabilities');
      try {
        const depScanContent = fs.readFileSync(depScanPath, 'utf8');
        await supabase.storage
          .from('project-imports')
          .upload(`${projectId}/${runId}/dep-scan.json`, depScanContent, {
            contentType: 'application/json',
            upsert: true,
          });

        const depScan = JSON.parse(depScanContent) as Record<string, unknown>;

        const parsePurl = (ref: string): { name: string; version: string } | null => {
          if (!ref || typeof ref !== 'string') return null;
          const match = ref.match(/^pkg:[^/]+\/(.+?)@([^?#]+)/);
          if (!match) return null;
          return { name: decodeURIComponent(match[1]), version: decodeURIComponent(match[2]) };
        };

        type CycloneAffect = { ref?: string; versions?: Array<{ version?: string; status?: string; range?: string }> };
        type CycloneVuln = {
          id?: string;
          description?: string;
          detail?: string;
          ratings?: Array<{ severity?: string; score?: number }>;
          affects?: CycloneAffect[];
          properties?: Array<{ name?: string; value?: string }>;
          published?: string;
        };

        type LegacyVuln = {
          vuln_id?: string;
          id?: string;
          severity?: string;
          summary?: string;
          aliases?: string[];
          fixed_version?: string;
          fixedVersions?: string[];
          epss?: number;
          component?: string;
          version?: string;
          ratings?: Array<{ severity?: string }>;
        };

        const topLevelVulns = Array.isArray(depScan.vulnerabilities) ? (depScan.vulnerabilities as unknown[]) : [];
        const isCycloneVdr =
          topLevelVulns.length > 0 &&
          typeof topLevelVulns[0] === 'object' &&
          topLevelVulns[0] !== null &&
          Array.isArray((topLevelVulns[0] as any).affects);

        const vulnsCyclone = (isCycloneVdr ? (topLevelVulns as CycloneVuln[]) : []) ?? [];
        const vulnsLegacy: LegacyVuln[] = (!isCycloneVdr ? (depScan.vulnerabilities as LegacyVuln[]) : []) || [];

        const { data: pdRows } = await supabase
          .from('project_dependencies')
          .select('id, name, version')
          .eq('project_id', projectId);

        const pdByNameVersion = new Map<string, string>();
        if (pdRows) {
          for (const r of pdRows) {
            pdByNameVersion.set(`${r.name}@${r.version}`, r.id);
          }
        }

        let kevCveSet = new Set<string>();
        try {
          const kevRes = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
          if (kevRes.ok) {
            const kevJson = (await kevRes.json()) as { vulnerabilities?: Array<{ cveID?: string }> };
            for (const entry of kevJson.vulnerabilities ?? []) {
              if (entry.cveID) kevCveSet.add(entry.cveID);
            }
            log('scan', 'CISA KEV catalog loaded', { count: kevCveSet.size });
          }
        } catch (e) {
          log('scan', 'CISA KEV fetch failed (non-fatal)', { error: String(e) });
        }

        const VALID_ASSET_TIERS: AssetTier[] = ['CROWN_JEWELS', 'EXTERNAL', 'INTERNAL', 'NON_PRODUCTION'];
        let assetTier: AssetTier = 'EXTERNAL';
        {
          const { data: projRow } = await supabase
            .from('projects')
            .select('asset_tier')
            .eq('id', projectId)
            .single();
          const raw = (projRow as { asset_tier?: string } | null)?.asset_tier;
          if (raw && VALID_ASSET_TIERS.includes(raw as AssetTier)) assetTier = raw as AssetTier;
        }

        let assetCriticality = 2;
        if (assetTier === 'EXTERNAL') assetCriticality = 1;
        else if (assetTier === 'INTERNAL') assetCriticality = 2;
        else if (assetTier === 'NON_PRODUCTION') assetCriticality = 3;
        else assetCriticality = 1;

        const vulnRows: Array<{
          project_id: string;
          project_dependency_id: string;
          osv_id: string;
          severity: string | null;
          summary: string | null;
          aliases: string[] | null;
          fixed_versions: string[] | null;
          is_reachable: boolean;
          epss_score: number | null;
          cvss_score: number | null;
          cisa_kev: boolean;
          depscore: number | null;
          dexcore: number | null;
          published_at: string | null;
        }> = [];
        if (isCycloneVdr) {
          for (const v of vulnsCyclone) {
            const osvId = (v.id ?? 'unknown').toString();
            const severity = v.ratings?.[0]?.severity ?? null;
            const summary = (v.description ?? v.detail ?? null) as string | null;

            const insights = (v.properties || []).find((p) => p?.name === 'depscan:insights')?.value ?? null;
            const isReachable = typeof insights === 'string' ? insights.startsWith('Used in') : false;
            const epssProp = (v.properties || []).find((p) => p?.name === 'depscan:epss' || p?.name === 'epss')?.value;
            const epssFromVdr = epssProp != null ? parseFloat(String(epssProp)) : null;
            const epssFromVdrNum = Number.isFinite(epssFromVdr) ? epssFromVdr : null;

            const cvssRaw = v.ratings?.[0]?.score;
            const cvssFromVdr = cvssRaw != null && Number.isFinite(cvssRaw)
              ? cvssRaw
              : (severity ? (SEVERITY_TO_CVSS[severity] ?? null) : null);

            const fixedSet = new Set<string>();
            for (const a of v.affects || []) {
              for (const ver of a.versions || []) {
                if (ver?.status === 'unaffected' && ver?.version) fixedSet.add(ver.version);
              }
            }
            const fixed_versions = fixedSet.size > 0 ? Array.from(fixedSet) : null;

            for (const a of v.affects || []) {
              const parsed = parsePurl(a.ref ?? '');
              if (!parsed) continue;
              const pdId = pdByNameVersion.get(`${parsed.name}@${parsed.version}`);
              if (!pdId) continue;
              vulnRows.push({
                project_id: projectId,
                project_dependency_id: pdId,
                osv_id: osvId,
                severity,
                summary,
                aliases: null,
                fixed_versions,
                is_reachable: isReachable,
                epss_score: epssFromVdrNum,
                cvss_score: cvssFromVdr,
                cisa_kev: false,
                depscore: null,
                dexcore: null,
                published_at: v.published ?? null,
              });
            }
          }
        } else {
          for (const v of vulnsLegacy) {
            const compName = (v.component ?? '').trim();
            const compVersion = (v.version ?? '').trim();
            const pdId = pdByNameVersion.get(`${compName}@${compVersion}`);
            if (!pdId) continue;
            const severity = v.severity ?? v.ratings?.[0]?.severity ?? null;
            vulnRows.push({
              project_id: projectId,
              project_dependency_id: pdId,
              osv_id: (v.vuln_id ?? v.id ?? 'unknown').toString(),
              severity,
              summary: v.summary ?? null,
              aliases: v.aliases ?? null,
              fixed_versions: v.fixed_version ? [v.fixed_version] : null,
              is_reachable: true,
              epss_score: v.epss ?? null,
              cvss_score: severity ? (SEVERITY_TO_CVSS[severity] ?? null) : null,
              cisa_kev: false,
              depscore: null,
              dexcore: null,
              published_at: null,
            });
          }
        }

        // Enrich EPSS from FIRST API for CVEs that don't have a score yet (max 2000 chars per request)
        const CVE_ID_RE = /^CVE-\d{4}-\d+$/i;
        const cvesToFetch = [...new Set(vulnRows.map((r) => r.osv_id).filter((id) => CVE_ID_RE.test(id)))];
        if (cvesToFetch.length > 0) {
          const epssByCve = new Map<string, number>();
          const BATCH_SIZE = 80;
          for (let i = 0; i < cvesToFetch.length; i += BATCH_SIZE) {
            const batch = cvesToFetch.slice(i, i + BATCH_SIZE);
            const cveParam = batch.join(',');
            try {
              const res = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveParam)}`);
              if (!res.ok) continue;
              const json = (await res.json()) as { data?: Array<{ cve?: string; epss?: string }> };
              for (const row of json.data ?? []) {
                const cve = row?.cve;
                const epssStr = row?.epss;
                if (cve && epssStr != null) {
                  const score = parseFloat(epssStr);
                  if (Number.isFinite(score)) epssByCve.set(cve, score);
                }
              }
            } catch (e) {
              log('scan', 'EPSS API fetch failed (non-fatal)', { error: String(e) });
            }
          }
          for (const row of vulnRows) {
            if (row.epss_score != null) continue;
            const score = epssByCve.get(row.osv_id);
            if (score != null) row.epss_score = score;
          }
          const filled = vulnRows.filter((r) => r.epss_score != null).length;
          if (filled > 0) log('scan', 'EPSS scores enriched from FIRST API', { cves: cvesToFetch.length, filled });
        }

        for (const row of vulnRows) {
          const allIds = [row.osv_id, ...(row.aliases ?? [])];
          row.cisa_kev = allIds.some((id) => CVE_ID_RE.test(id) && kevCveSet.has(id));

          const cvss = row.cvss_score ?? (row.severity ? (SEVERITY_TO_CVSS[row.severity] ?? 0) : 0);
          const epss = row.epss_score ?? 0;
          row.depscore = calculateDepscore({
            cvss,
            epss,
            cisaKev: row.cisa_kev,
            isReachable: row.is_reachable,
            assetCriticality,
          });
          row.dexcore = calculateDexcore({
            cvss,
            epss,
            cisaKev: row.cisa_kev,
            isReachable: row.is_reachable,
            assetTier,
          });
        }
        log('scan', 'Depscore calculated', {
          total: vulnRows.length,
          withCvss: vulnRows.filter((r) => r.cvss_score != null).length,
          kevMatches: vulnRows.filter((r) => r.cisa_kev).length,
        });

        if (vulnRows.length > 0) {
          log('scan', 'Upserting vulnerabilities', { count: vulnRows.length });
          for (let i = 0; i < vulnRows.length; i += 100) {
            await supabase
              .from('project_dependency_vulnerabilities')
              .upsert(vulnRows.slice(i, i + 100), {
                onConflict: 'project_id,project_dependency_id,osv_id',
                ignoreDuplicates: true,
              });
          }
        }
      } catch (e) {
        log('scan', 'dep-scan parse/insert failed', { error: String(e) });
      }
    }

    log('scan', 'Running Semgrep...');
    try {
      execSync(`semgrep scan --config auto --json --output "${path.join(workspaceRoot, 'semgrep.json')}" "${workspaceRoot}" 2>/dev/null || true`, {
        stdio: 'pipe',
        timeout: 60000,
      });
    } catch {
      log('scan', 'Semgrep not installed or failed; skipping');
    }
    const semgrepPath = path.join(workspaceRoot, 'semgrep.json');
    if (fs.existsSync(semgrepPath)) {
      log('scan', 'Uploading Semgrep report');
      const content = fs.readFileSync(semgrepPath, 'utf8');
      await supabase.storage
        .from('project-imports')
        .upload(`${projectId}/${runId}/semgrep.json`, content, { contentType: 'application/json', upsert: true });
    }

    log('scan', 'Running TruffleHog...');
    try {
      const trufflehogOut = path.join(workspaceRoot, 'trufflehog.json');
      const result = execSync(`trufflehog filesystem "${workspaceRoot}" --json 2>/dev/null || echo "[]"`, {
        encoding: 'utf8',
        timeout: 60000,
        maxBuffer: 10 * 1024 * 1024,
      });
      if (result && typeof result === 'string') {
        fs.writeFileSync(trufflehogOut, result, 'utf8');
      }
      if (fs.existsSync(trufflehogOut)) {
        log('scan', 'Uploading TruffleHog report');
        const content = fs.readFileSync(trufflehogOut, 'utf8');
        await supabase.storage
          .from('project-imports')
          .upload(`${projectId}/${runId}/trufflehog.json`, content, { contentType: 'application/json', upsert: true });
      }
    } catch {
      log('scan', 'TruffleHog not installed or failed; skipping');
    }

    await updateStep(supabase, projectId, 'uploading');
    log('upload', 'Updating project status...');

    const status = newDepsToPopulate.length > 0 ? 'analyzing' : 'ready';
    await supabase
      .from('project_repositories')
      .update({
        status,
        extraction_step: 'completed',
        extraction_error: null,
        ...(astParsedSuccessfully ? { ast_parsed_at: new Date().toISOString() } : {}),
        updated_at: new Date().toISOString(),
      })
      .eq('project_id', projectId);

    await supabase
      .from('projects')
      .update({
        dependencies_count: projectDepsToInsert.length,
        updated_at: new Date().toISOString(),
      })
      .eq('id', projectId)
      .eq('organization_id', organizationId);

    log('done', `Pipeline complete`, { deps: projectDepsToInsert.length, status });
  } catch (error: any) {
    log('error', `Pipeline failed: ${error.message}`, { projectId, code: (error as any).code, details: (error as any).details });
    await setError(supabase, projectId, error.message);
    throw error;
  } finally {
    if (repoPath) {
      if (process.env.KEEP_EXTRACT_WORKSPACE === '1') {
        log('done', 'KEEP_EXTRACT_WORKSPACE=1; skipping workspace cleanup', { repoPath });
      } else {
        cleanupRepository(repoPath);
      }
    }
  }
}
