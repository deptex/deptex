/**
 * Extraction pipeline: clone -> cdxgen -> parse SBOM -> upsert deps -> queue populate -> AST import analysis -> dep-scan -> Semgrep -> TruffleHog -> upload -> update status
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync, spawnSync } from 'child_process';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { cloneRepository, cleanupRepository, cloneByProvider } from './clone';
import { parseSbom, getBomRefToNameVersion, type ParsedSbomDep, type ParsedSbomRelationship } from './sbom';
import { calculateDepscore, SEVERITY_TO_CVSS, type AssetTier } from './depscore';
import { analyzeRepository } from './ast-parser';
import { storeAstAnalysisResults } from './ast-storage';
import { ExtractionLogger } from './logger';

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

function classifyCloneError(message: string): string {
  if (/401|403|authentication|authorization/i.test(message)) {
    return 'Authentication failed — your source code integration may need to be reconnected in Organization Settings';
  }
  if (/404|not found/i.test(message)) {
    return 'Repository not found — it may have been deleted or made private';
  }
  if (/could not find remote branch|unknown revision/i.test(message)) {
    return `Branch not found in repository`;
  }
  if (/ENOSPC|no space left/i.test(message)) {
    return 'Repository is too large to scan';
  }
  return `Clone failed: ${message.slice(0, 200)}`;
}

function classifyCdxgenError(message: string): string {
  if (/timeout|timed out/i.test(message)) {
    return 'SBOM generation timed out — the repository may be too large or complex';
  }
  return `SBOM generation failed: ${message.slice(0, 200)}`;
}

export async function runPipeline(
  job: ExtractionJob,
  logger?: ExtractionLogger,
  checkCancelled?: () => Promise<boolean>
): Promise<void> {
  const supabase = getSupabase();
  const projectId = job.projectId;
  const organizationId = job.organizationId;
  const packageJsonPath = (job.package_json_path ?? '').trim();

  const log = logger ?? {
    info: async () => {},
    success: async () => {},
    warn: async () => {},
    error: async () => {},
  } as any;

  let repoPath: string | null = null;
  let projectDepsCount = 0;

  try {
    // === STEP: Clone (CRITICAL) ===
    if (checkCancelled && await checkCancelled()) return;
    await updateStep(supabase, projectId, 'cloning', 'extracting');
    await log.info('cloning', `Cloning repository from ${(job.provider || 'github').charAt(0).toUpperCase() + (job.provider || 'github').slice(1)}...`);

    const cloneStart = Date.now();
    try {
      repoPath = await retry(() => cloneByProvider(job), 'clone');
    } catch (e: any) {
      const userMsg = classifyCloneError(e.message);
      await log.error('cloning', userMsg, e);
      await setError(supabase, projectId, userMsg);
      throw new Error(userMsg);
    }
    await log.success('cloning', 'Repository cloned successfully', Date.now() - cloneStart);

    const workspaceRoot = packageJsonPath
      ? path.join(repoPath, packageJsonPath)
      : repoPath;

    if (!fs.existsSync(workspaceRoot)) {
      const msg = `No package manifest found at '${packageJsonPath || '(root)'}' — check your project's package path setting`;
      await log.error('cloning', msg);
      await setError(supabase, projectId, msg);
      throw new Error(msg);
    }

    // === STEP: SBOM (CRITICAL) ===
    if (checkCancelled && await checkCancelled()) return;
    await updateStep(supabase, projectId, 'sbom');
    await log.info('sbom', 'Generating software bill of materials...');

    const sbomStart = Date.now();
    let sbomPath: string;
    try {
      sbomPath = await retry(() => Promise.resolve(runCdxgen(workspaceRoot)), 'cdxgen');
    } catch (e: any) {
      const userMsg = classifyCdxgenError(e.message);
      await log.error('sbom', userMsg, e);
      await setError(supabase, projectId, userMsg);
      throw new Error(userMsg);
    }

    const sbomContent = fs.readFileSync(sbomPath, 'utf8');
    const sbom = JSON.parse(sbomContent) as Parameters<typeof parseSbom>[0];

    const runId = Date.now().toString();
    const storagePath = `${projectId}/${runId}/sbom.json`;

    try {
      await supabase.storage
        .from('project-imports')
        .upload(storagePath, sbomContent, {
          contentType: 'application/json',
          upsert: true,
        });
    } catch {
      await log.warn('sbom', 'SBOM upload to storage failed (non-fatal)');
    }

    const { dependencies, relationships } = parseSbom(sbom);
    const bomRefMap = getBomRefToNameVersion(sbom);

    if (dependencies.length === 0) {
      const msg = "No dependencies found — the package manifest may be empty or in an unsupported format";
      await log.error('sbom', msg);
      await setError(supabase, projectId, msg);
      throw new Error(msg);
    }

    await log.success('sbom', `SBOM generated — found ${dependencies.length} dependencies`, Date.now() - sbomStart, {
      components: dependencies.length,
      relationships: relationships.length,
    });

    // === STEP: Dependency sync (CRITICAL) ===
    if (checkCancelled && await checkCancelled()) return;
    await updateStep(supabase, projectId, 'deps_synced');
    await log.info('deps_sync', 'Syncing dependencies to database...');

    const syncStart = Date.now();

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
      try {
        await callQueuePopulate(backendBaseUrl, workerSecret, projectId, organizationId, newDepsToPopulate, jobEcosystem);
      } catch (e: any) {
        await log.warn('populate', `Failed to queue dependency population: ${e.message}`);
      }
    }

    await supabase.from('project_dependencies').delete().eq('project_id', projectId);

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

    for (let i = 0; i < projectDepsToInsert.length; i += 500) {
      const chunk = projectDepsToInsert.slice(i, i + 500);
      const { error } = await supabase.from('project_dependencies').insert(chunk);
      if (error) throw error;
    }
    projectDepsCount = projectDepsToInsert.length;

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

    const directCount = projectDepsToInsert.filter((d) => d.is_direct).length;
    const transitiveCount = projectDepsToInsert.length - directCount;
    await log.success('deps_sync', `Dependencies synced (${directCount} direct, ${transitiveCount} transitive)`, Date.now() - syncStart);

    // === STEP: AST import analysis (OPTIONAL) ===
    if (checkCancelled && await checkCancelled()) return;
    let astParsedSuccessfully = false;
    await updateStep(supabase, projectId, 'ast_parsing');
    await log.info('ast_parsing', 'Analyzing code imports...');

    const astStart = Date.now();
    try {
      const analysisResults = analyzeRepository(workspaceRoot);
      if (analysisResults.length > 0) {
        const storeResult = await storeAstAnalysisResults(supabase, projectId, organizationId, analysisResults);
        if (storeResult.success) {
          astParsedSuccessfully = true;
          await log.success('ast_parsing', `Import analysis complete — ${analysisResults.length} files analyzed`, Date.now() - astStart);
        } else {
          await log.warn('ast_parsing', `Import analysis storage failed (non-fatal): ${storeResult.error}`);
        }
      } else {
        astParsedSuccessfully = true;
        await log.success('ast_parsing', 'No JS/TS imports found (repo may use a different ecosystem)', Date.now() - astStart);
      }
    } catch (e: any) {
      await log.warn('ast_parsing', `Import analysis failed (non-fatal): ${e.message}`);
    }

    // === STEP: Vulnerability scan (OPTIONAL) ===
    if (checkCancelled && await checkCancelled()) return;
    await updateStep(supabase, projectId, 'scanning');
    await log.info('vuln_scan', 'Running vulnerability scan...');

    const scanStart = Date.now();
    const reportsDir = path.join(workspaceRoot, 'depscan-reports');
    let depScanSucceeded = false;

    try {
      fs.mkdirSync(reportsDir, { recursive: true });
      const bomArg = path.join(workspaceRoot, 'sbom.json');
      const outArg = reportsDir;

      let depScanExe = 'depscan';
      if (process.platform === 'win32') {
        try {
          const whereOut = execSync('where depscan.exe', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
          const first = whereOut.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)[0];
          if (first && fs.existsSync(first)) depScanExe = first;
        } catch { /* ignore */ }

        if (depScanExe === 'depscan') {
          try {
            const scriptsDir = execSync('py -c "import sysconfig; print(sysconfig.get_path(\'scripts\'))"', {
              encoding: 'utf8',
              stdio: ['pipe', 'pipe', 'pipe'],
            }).trim();
            const exePath = path.join(scriptsDir, 'depscan.exe');
            if (fs.existsSync(exePath)) depScanExe = exePath;
          } catch { /* ignore */ }
        }
      }

      const ecosystem = job.ecosystem || 'npm';
      const depScanArgs = [
        '--bom', bomArg,
        '--reports-dir', outArg,
        '-t', ecosystem,
        '--no-banner',
        '--vulnerability-analyzer', 'VDRAnalyzer',
      ];
      if (process.env.DEPSCAN_EXPLAIN === '1') depScanArgs.push('--explain');

      const res = spawnSync(depScanExe, depScanArgs, {
        cwd: workspaceRoot,
        encoding: 'utf8',
        timeout: 90 * 60 * 1000,
      });

      if (res.error) {
        if ((res.error as any).code === 'ENOENT') {
          await log.warn('vuln_scan', 'Vulnerability scanning unavailable (dep-scan not installed)');
        } else {
          throw res.error;
        }
      } else if (res.status !== 0) {
        const stderrFirst = (res.stderr ?? '').split('\n')[0] || 'unknown error';
        if (res.status === 137) {
          await log.warn('vuln_scan', 'Vulnerability scan ran out of memory — scanning skipped');
        } else {
          await log.warn('vuln_scan', `Vulnerability scan failed: ${stderrFirst}`);
        }
      } else {
        depScanSucceeded = true;
      }
    } catch (e: any) {
      if (/timed out|timeout/i.test(e.message)) {
        await log.warn('vuln_scan', 'Vulnerability scan timed out');
      } else {
        await log.warn('vuln_scan', `Vulnerability scan failed: ${e.message}`);
      }
    }

    // Process dep-scan results (same logic as before, but with logger)
    const listVdrFiles = (dir: string): string[] => {
      try {
        return fs
          .readdirSync(dir, { withFileTypes: true })
          .filter((d) => d.isFile() && (d.name.endsWith('.vdr.json') || d.name === 'dep-scan.json'))
          .map((d) => path.join(dir, d.name));
      } catch { return []; }
    };

    const vdrInReports = listVdrFiles(reportsDir);
    const vdrInRoot = listVdrFiles(workspaceRoot);
    let vdrFiles = [...vdrInReports, ...vdrInRoot];

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
        let fsEntries: fs.Dirent[];
        try { fsEntries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
        for (const entry of fsEntries) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) stack.push(fullPath);
          else if (entry.isFile() && isVdrFile(entry.name)) found.push(fullPath);
        }
      }
      if (found.length > 0) vdrFiles = found;
    }

    const tryParseJson = (p: string): Record<string, unknown> | null => {
      try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
    };

    const candidatePaths: string[] = [];
    const addCandidate = (p: string) => {
      if (!p || candidatePaths.includes(p) || !fs.existsSync(p)) return;
      candidatePaths.push(p);
    };
    for (const p of vdrFiles) addCandidate(p);
    try {
      for (const d of fs.readdirSync(reportsDir, { withFileTypes: true })) {
        if (d.isFile() && d.name.endsWith('.json')) addCandidate(path.join(reportsDir, d.name));
      }
    } catch { /* ignore */ }

    let depScanPath: string | null = null;
    for (const p of candidatePaths) {
      const parsed = tryParseJson(p);
      const vulns = parsed && (parsed as { vulnerabilities?: unknown }).vulnerabilities;
      if (Array.isArray(vulns)) { depScanPath = p; break; }
    }
    if (!depScanPath) depScanPath = vdrFiles[0] ?? path.join(workspaceRoot, 'dep-scan.json');

    const reportExists = fs.existsSync(depScanPath);

    if (reportExists) {
      try {
        const depScanContent = fs.readFileSync(depScanPath, 'utf8');
        try {
          await supabase.storage
            .from('project-imports')
            .upload(`${projectId}/${runId}/dep-scan.json`, depScanContent, {
              contentType: 'application/json',
              upsert: true,
            });
        } catch { /* upload failure is non-fatal */ }

        const depScan = JSON.parse(depScanContent) as Record<string, unknown>;
        const parsePurl = (ref: string): { name: string; version: string } | null => {
          if (!ref || typeof ref !== 'string') return null;
          const match = ref.match(/^pkg:[^/]+\/(.+?)@([^?#]+)/);
          if (!match) return null;
          return { name: decodeURIComponent(match[1]), version: decodeURIComponent(match[2]) };
        };

        type CycloneAffect = { ref?: string; versions?: Array<{ version?: string; status?: string; range?: string }> };
        type CycloneVuln = {
          id?: string; description?: string; detail?: string;
          ratings?: Array<{ severity?: string; score?: number }>;
          affects?: CycloneAffect[];
          properties?: Array<{ name?: string; value?: string }>;
          published?: string;
        };
        type LegacyVuln = {
          vuln_id?: string; id?: string; severity?: string; summary?: string;
          aliases?: string[]; fixed_version?: string; fixedVersions?: string[];
          epss?: number; component?: string; version?: string;
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
          for (const r of pdRows) pdByNameVersion.set(`${r.name}@${r.version}`, r.id);
        }

        let kevCveSet = new Set<string>();
        try {
          const kevRes = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
          if (kevRes.ok) {
            const kevJson = (await kevRes.json()) as { vulnerabilities?: Array<{ cveID?: string }> };
            for (const entry of kevJson.vulnerabilities ?? []) {
              if (entry.cveID) kevCveSet.add(entry.cveID);
            }
          }
        } catch { /* non-fatal */ }

        const VALID_ASSET_TIERS: AssetTier[] = ['CROWN_JEWELS', 'EXTERNAL', 'INTERNAL', 'NON_PRODUCTION'];
        let assetTier: AssetTier = 'EXTERNAL';
        {
          const { data: projRow } = await supabase.from('projects').select('asset_tier').eq('id', projectId).single();
          const raw = (projRow as { asset_tier?: string } | null)?.asset_tier;
          if (raw && VALID_ASSET_TIERS.includes(raw as AssetTier)) assetTier = raw as AssetTier;
        }

        const vulnRows: Array<{
          project_id: string; project_dependency_id: string; osv_id: string;
          severity: string | null; summary: string | null; aliases: string[] | null;
          fixed_versions: string[] | null; is_reachable: boolean; epss_score: number | null;
          cvss_score: number | null; cisa_kev: boolean; depscore: number | null; published_at: string | null;
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
            const cvssFromVdr = cvssRaw != null && Number.isFinite(cvssRaw) ? cvssRaw : (severity ? (SEVERITY_TO_CVSS[severity] ?? null) : null);
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
                project_id: projectId, project_dependency_id: pdId, osv_id: osvId,
                severity, summary, aliases: null, fixed_versions, is_reachable: isReachable,
                epss_score: epssFromVdrNum, cvss_score: cvssFromVdr, cisa_kev: false,
                depscore: null, published_at: v.published ?? null,
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
              project_id: projectId, project_dependency_id: pdId,
              osv_id: (v.vuln_id ?? v.id ?? 'unknown').toString(), severity,
              summary: v.summary ?? null, aliases: v.aliases ?? null,
              fixed_versions: v.fixed_version ? [v.fixed_version] : null,
              is_reachable: true, epss_score: v.epss ?? null,
              cvss_score: severity ? (SEVERITY_TO_CVSS[severity] ?? null) : null,
              cisa_kev: false, depscore: null, published_at: null,
            });
          }
        }

        const CVE_ID_RE = /^CVE-\d{4}-\d+$/i;
        const cvesToFetch = [...new Set(vulnRows.map((r) => r.osv_id).filter((id) => CVE_ID_RE.test(id)))];
        if (cvesToFetch.length > 0) {
          const epssByCve = new Map<string, number>();
          const EPSS_BATCH = 80;
          for (let i = 0; i < cvesToFetch.length; i += EPSS_BATCH) {
            const batch = cvesToFetch.slice(i, i + EPSS_BATCH);
            try {
              const epssRes = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(batch.join(','))}`);
              if (epssRes.ok) {
                const json = (await epssRes.json()) as { data?: Array<{ cve?: string; epss?: string }> };
                for (const row of json.data ?? []) {
                  if (row?.cve && row?.epss != null) {
                    const score = parseFloat(row.epss);
                    if (Number.isFinite(score)) epssByCve.set(row.cve, score);
                  }
                }
              }
            } catch { /* non-fatal */ }
          }
          for (const row of vulnRows) {
            if (row.epss_score != null) continue;
            const score = epssByCve.get(row.osv_id);
            if (score != null) row.epss_score = score;
          }
        }

        for (const row of vulnRows) {
          const allIds = [row.osv_id, ...(row.aliases ?? [])];
          row.cisa_kev = allIds.some((id) => CVE_ID_RE.test(id) && kevCveSet.has(id));
          const cvss = row.cvss_score ?? (row.severity ? (SEVERITY_TO_CVSS[row.severity] ?? 0) : 0);
          const epss = row.epss_score ?? 0;
          row.depscore = calculateDepscore({ cvss, epss, cisaKev: row.cisa_kev, isReachable: row.is_reachable, assetTier });
        }

        if (vulnRows.length > 0) {
          for (let i = 0; i < vulnRows.length; i += 100) {
            await supabase
              .from('project_dependency_vulnerabilities')
              .upsert(vulnRows.slice(i, i + 100), {
                onConflict: 'project_id,project_dependency_id,osv_id',
                ignoreDuplicates: true,
              });
          }
        }

        const critCount = vulnRows.filter((r) => r.severity === 'critical').length;
        const highCount = vulnRows.filter((r) => r.severity === 'high').length;
        const severitySummary = vulnRows.length > 0
          ? ` (${critCount} critical, ${highCount} high)`
          : '';
        await log.success('vuln_scan', `Vulnerability scan complete — found ${vulnRows.length} vulnerabilities${severitySummary}`, Date.now() - scanStart);
      } catch (e: any) {
        await log.warn('vuln_scan', `Vulnerability processing failed: ${e.message}`);
      }
    } else if (!depScanSucceeded) {
      await log.warn('vuln_scan', 'No vulnerability scan results available');
    }

    // === STEP: Semgrep (OPTIONAL) ===
    if (checkCancelled && await checkCancelled()) return;
    await log.info('semgrep', 'Running static code analysis...');
    const semgrepStart = Date.now();
    let semgrepFindings = 0;
    try {
      execSync(`semgrep scan --config auto --json --output "${path.join(workspaceRoot, 'semgrep.json')}" "${workspaceRoot}" 2>/dev/null || true`, {
        stdio: 'pipe',
        timeout: 60000,
      });
      const semgrepPath = path.join(workspaceRoot, 'semgrep.json');
      if (fs.existsSync(semgrepPath)) {
        const content = fs.readFileSync(semgrepPath, 'utf8');
        try {
          const parsed = JSON.parse(content);
          semgrepFindings = Array.isArray(parsed?.results) ? parsed.results.length : 0;
        } catch { /* ignore parse errors */ }
        try {
          await supabase.storage
            .from('project-imports')
            .upload(`${projectId}/${runId}/semgrep.json`, content, { contentType: 'application/json', upsert: true });
        } catch { /* upload failure non-fatal */ }
        await log.success('semgrep', `Static analysis complete — ${semgrepFindings} findings`, Date.now() - semgrepStart);
      } else {
        await log.warn('semgrep', 'Static analysis skipped (Semgrep not installed)');
      }
    } catch (e: any) {
      if (e.status === 137) {
        await log.warn('semgrep', 'Static analysis ran out of memory — scanning skipped');
      } else {
        await log.warn('semgrep', 'Static analysis skipped (Semgrep not installed or failed)');
      }
    }

    // === STEP: TruffleHog (OPTIONAL) ===
    if (checkCancelled && await checkCancelled()) return;
    await log.info('trufflehog', 'Scanning for exposed secrets...');
    const thStart = Date.now();
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
        const content = fs.readFileSync(trufflehogOut, 'utf8');
        try {
          await supabase.storage
            .from('project-imports')
            .upload(`${projectId}/${runId}/trufflehog.json`, content, { contentType: 'application/json', upsert: true });
        } catch { /* upload failure non-fatal */ }
        await log.success('trufflehog', 'Secret scan complete — no secrets found', Date.now() - thStart);
      } else {
        await log.warn('trufflehog', 'Secret scanning unavailable (TruffleHog not installed)');
      }
    } catch {
      await log.warn('trufflehog', 'Secret scanning skipped (TruffleHog not installed or failed)');
    }

    // === STEP: Finalize ===
    if (checkCancelled && await checkCancelled()) return;
    await updateStep(supabase, projectId, 'uploading');
    await log.info('uploading', 'Updating project status...');

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
        dependencies_count: projectDepsCount,
        updated_at: new Date().toISOString(),
      })
      .eq('id', projectId)
      .eq('organization_id', organizationId);

  } catch (error: any) {
    await setError(supabase, projectId, error.message);
    throw error;
  } finally {
    if (repoPath) {
      if (process.env.KEEP_EXTRACT_WORKSPACE === '1') {
        console.log('[EXTRACT] KEEP_EXTRACT_WORKSPACE=1; skipping workspace cleanup');
      } else {
        cleanupRepository(repoPath);
      }
    }
  }
}
