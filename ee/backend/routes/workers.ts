import express from 'express';
import semver from 'semver';
import { supabase } from '../../../backend/src/lib/supabase';
import { createInstallationToken, getRepositoryFileContent } from '../lib/github';
import {
  queuePopulateDependencyBatch,
  queueBackfillDependencyTrees,
  verifyQStashSignature,
  isQStashConfigured,
} from '../lib/qstash';
import { resolveAndUpsertTransitiveEdges } from '../../../backend/src/lib/transitive-edges';
import {
  type GhsaVuln,
  getGitHubToken,
  fetchGhsaVulnerabilitiesBatch,
  ghsaVulnToRow,
} from '../../../backend/src/lib/ghsa';
import {
  invalidateDependencyVersionsCacheByDependencyId,
  invalidateLatestSafeVersionCacheByDependencyId,
  invalidateProjectCaches,
} from '../lib/cache';

const router = express.Router();

// ============================================================================
// TYPES
// ============================================================================

interface DependencyRow {
  name: string;
  version: string;
  license: string | null;
  is_direct: boolean;
  source: string;
}

interface DependencyRelationship {
  parentName: string;
  parentVersion: string;
  childName: string;
  childVersion: string;
}

interface ParsedLockData {
  directDependencies: string[];
  directDevDependencies: string[];
  transitiveEntries: Array<{ name: string; version: string; license: string | null }>;
  relationships: DependencyRelationship[];
  packages: Record<string, any>;
  dependenciesRoot: Record<string, any>;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

const normalizeLicense = (license: any): string | null => {
  if (!license) return null;
  if (typeof license === 'string') return license;
  if (Array.isArray(license)) {
    const values = license
      .map((entry) => normalizeLicense(entry))
      .filter(Boolean) as string[];
    return values.length > 0 ? values.join(', ') : null;
  }
  if (typeof license === 'object') {
    if (typeof license.type === 'string') return license.type;
  }
  return null;
};

/** True if version is a stable release (no canary/experimental/alpha/beta/rc prerelease tag). */
function isStableVersion(version: string): boolean {
  if (!semver.valid(version)) return false;
  return !semver.prerelease(version);
}

/** Delay between npm API calls to avoid rate limiting (registry + downloads share this). */
const NPM_DELAY_MS = 600;
let lastNpmCallTime = 0;

async function waitForNpmRateLimit(): Promise<void> {
  const now = Date.now();
  const elapsed = now - lastNpmCallTime;
  if (elapsed < NPM_DELAY_MS && lastNpmCallTime > 0) {
    await new Promise((r) => setTimeout(r, NPM_DELAY_MS - elapsed));
  }
}

function recordNpmCall(): void {
  lastNpmCallTime = Date.now();
}

const fetchNpmLicense = async (name: string, version: string | null): Promise<string | null> => {
  await waitForNpmRateLimit();
  const url = `https://registry.npmjs.org/${encodeURIComponent(name)}`;
  console.log('[NPM] GET', url, { package: name, version: version ?? 'latest' });
  const encodedName = encodeURIComponent(name);
  try {
    const response = await fetch(url, {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'Deptex-App',
      },
    });
    recordNpmCall(); // after fetch so delay is between response and next request

    if (!response.ok) {
      console.log('[NPM] GET', url, { status: response.status });
      return null;
    }

    const data = (await response.json()) as Record<string, unknown>;
    if (version && (data?.versions as Record<string, { license?: string }> | undefined)?.[version]) {
      return normalizeLicense((data.versions as Record<string, { license?: string }>)[version].license);
    }

    return normalizeLicense((data?.license as string) ?? null);
  } catch (e) {
    recordNpmCall();
    console.warn('[NPM] GET', url, { error: (e as Error).message });
    return null;
  }
};

/** NPM metadata for the dependencies table (package-level, one row per name) */
interface NpmDependencyMetadata {
  license: string | null;
  github_url: string | null;
  weekly_downloads: number | null;
  last_published_at: string | null; // ISO
}

async function fetchNpmDependencyMetadata(name: string): Promise<NpmDependencyMetadata> {
  const out: NpmDependencyMetadata = {
    license: null,
    github_url: null,
    weekly_downloads: null,
    last_published_at: null,
  };
  const encoded = encodeURIComponent(name);
  const encodedForDownloads = name.startsWith('@') ? name : encodeURIComponent(name);
  const registryUrl = `https://registry.npmjs.org/${encoded}`;
  const downloadsUrl = `https://api.npmjs.org/downloads/point/last-week/${encodedForDownloads}`;
  try {
    await waitForNpmRateLimit();
    console.log('[NPM] GET', registryUrl, { package: name, api: 'registry' });
    const metaRes = await fetch(registryUrl, {
      headers: { Accept: 'application/json', 'User-Agent': 'Deptex-App' },
    });
    recordNpmCall();
    if (!metaRes.ok) {
      if (metaRes.status === 404) console.warn(`[NPM] GET`, registryUrl, { status: 404 });
      else console.warn(`[NPM] GET`, registryUrl, { status: metaRes.status });
      return out;
    }
    const meta = (await metaRes.json()) as Record<string, unknown>;
    out.license = normalizeLicense((meta?.license as string) ?? null);
    const repo = (meta?.repository as { url?: string } | undefined)?.url || (meta?.repository as string);
    if (typeof repo === 'string') {
      const m = repo.match(/github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?$/i);
      if (m) out.github_url = `https://github.com/${m[1]}/${m[2]}`;
    }
    const distTags = meta?.['dist-tags'] as { latest?: string } | undefined;
    const versions = meta?.versions as Record<string, { time?: string }> | undefined;
    const latestTag = distTags?.latest;
    const latest = latestTag && versions?.[latestTag];
    const latestObj = latest && typeof latest === 'object' ? latest : null;
    if (latestObj?.time) out.last_published_at = new Date(latestObj.time).toISOString();
    else if ((meta?.time as { modified?: string } | undefined)?.modified) out.last_published_at = new Date((meta.time as { modified: string }).modified).toISOString();

    await waitForNpmRateLimit();
    console.log('[NPM] GET', downloadsUrl, { package: name, api: 'downloads' });
    const dlRes = await fetch(downloadsUrl, {
      headers: { 'User-Agent': 'Deptex-App' },
    });
    recordNpmCall();
    if (dlRes.ok) {
      const dl = (await dlRes.json()) as { downloads?: number };
      out.weekly_downloads = dl.downloads ?? null;
    } else if (dlRes.status === 429) {
      console.warn('[NPM] GET', downloadsUrl, { status: 429, rateLimited: true });
    }
  } catch (e) {
    console.warn('[NPM] fetchNpmDependencyMetadata', { package: name, error: (e as Error).message });
  }
  return out;
}

const parsePackageLock = (lockJson: any): ParsedLockData => {
  const packages = lockJson?.packages || {};
  const rootPackage = packages[''] || {};

  const directDependencies = Object.keys(rootPackage.dependencies || {});
  const directDevDependencies = Object.keys(rootPackage.devDependencies || {});

  // Build a map of package paths to their resolved name and version
  const packageInfoMap = new Map<string, { name: string; version: string }>();

  const transitiveEntries = Object.entries(packages)
    .filter(([path]) => path !== '' && path.includes('node_modules/'))
    .map(([path, entry]: [string, any]) => {
      const lastSegmentIndex = path.lastIndexOf('node_modules/');
      const nameFromPath = path.slice(lastSegmentIndex + 'node_modules/'.length);
      const name = entry?.name || nameFromPath;
      const version = entry?.version || null;

      // Store in map for relationship lookups
      if (name && version) {
        packageInfoMap.set(path, { name, version });
      }

      return {
        name,
        version,
        license: normalizeLicense(entry?.license),
      };
    })
    .filter((dep): dep is { name: string; version: string; license: string | null } =>
      dep.name && dep.version !== null
    );

  // Extract parent-child relationships from nested node_modules paths
  // Example: "node_modules/express/node_modules/body-parser" means express depends on body-parser
  const relationships: DependencyRelationship[] = [];
  const seenRelationships = new Set<string>();

  for (const [path, entry] of Object.entries(packages)) {
    if (path === '' || !path.includes('node_modules/')) continue;

    // Split by /node_modules/ to get the nesting levels
    const parts = path.split('/node_modules/');
    // parts[0] is empty string, parts[1..n] are package names at each nesting level

    if (parts.length >= 3) {
      // This package has a parent - it's nested under another package
      // Example: ['', 'express', 'body-parser'] -> express is parent of body-parser
      const childName = (entry as { name?: string })?.name || parts[parts.length - 1];
      const childVersion = (entry as { version?: string })?.version;

      if (!childName || !childVersion) continue;

      // Find the parent - it's at node_modules/<all parts except last>
      const parentParts = parts.slice(0, -1);
      const parentPath = parentParts.join('/node_modules/');
      const parentInfo = packageInfoMap.get(parentPath);

      if (parentInfo) {
        const relationKey = `${parentInfo.name}@${parentInfo.version}|${childName}@${childVersion}`;
        if (!seenRelationships.has(relationKey)) {
          seenRelationships.add(relationKey);
          relationships.push({
            parentName: parentInfo.name,
            parentVersion: parentInfo.version,
            childName,
            childVersion,
          });
        }
      }
    }
  }

  // Also extract relationships from the "dependencies" field within each package entry
  // This catches dependencies that are hoisted but still declared as dependencies
  for (const [path, entry] of Object.entries(packages)) {
    const deps = (entry as { dependencies?: Record<string, string> })?.dependencies;
    if (path === '' || !deps) continue;

    const parentInfo = packageInfoMap.get(path);
    if (!parentInfo) continue;

    for (const childName of Object.keys(deps)) {
      // Find the child package - could be at various levels due to hoisting
      // First check if it's nested directly under this package
      const nestedPath = `${path}/node_modules/${childName}`;
      let childInfo = packageInfoMap.get(nestedPath);

      // If not nested, check if it's hoisted to the root
      if (!childInfo) {
        const rootPath = `node_modules/${childName}`;
        childInfo = packageInfoMap.get(rootPath);
      }

      if (childInfo) {
        const relationKey = `${parentInfo.name}@${parentInfo.version}|${childInfo.name}@${childInfo.version}`;
        if (!seenRelationships.has(relationKey)) {
          seenRelationships.add(relationKey);
          relationships.push({
            parentName: parentInfo.name,
            parentVersion: parentInfo.version,
            childName: childInfo.name,
            childVersion: childInfo.version,
          });
        }
      }
    }
  }

  return {
    directDependencies,
    directDevDependencies,
    transitiveEntries,
    relationships,
    packages,
    dependenciesRoot: lockJson?.dependencies || {},
  };
};

const buildDependencyRows = async (
  lockData: ParsedLockData
): Promise<DependencyRow[]> => {
  const rows: DependencyRow[] = [];

  const resolveDirectVersion = (name: string) => {
    const packageEntry = lockData.packages?.[`node_modules/${name}`];
    if (packageEntry?.version) return packageEntry.version as string;
    const legacyEntry = lockData.dependenciesRoot?.[name];
    if (legacyEntry?.version) return legacyEntry.version as string;
    return null;
  };

  const resolveDirectLicense = (name: string): string | null => {
    const packageEntry = lockData.packages?.[`node_modules/${name}`];
    return packageEntry ? normalizeLicense(packageEntry.license) : null;
  };

  // Build list of direct deps; use lockfile license when present, else fetch from npm
  const directDeps: Array<{ name: string; version: string; source: string; licenseFromLockfile: string | null }> = [];

  for (const name of lockData.directDependencies) {
    const version = resolveDirectVersion(name);
    if (version) {
      directDeps.push({
        name,
        version,
        source: 'dependencies',
        licenseFromLockfile: resolveDirectLicense(name),
      });
    }
  }

  for (const name of lockData.directDevDependencies) {
    const version = resolveDirectVersion(name);
    if (version) {
      directDeps.push({
        name,
        version,
        source: 'devDependencies',
        licenseFromLockfile: resolveDirectLicense(name),
      });
    }
  }

  const depsNeedingFetch = directDeps.filter(
    (d) => d.licenseFromLockfile == null || d.licenseFromLockfile === ''
  );

  const licenseResults = new Map<string, string | null>();
  for (const dep of depsNeedingFetch) {
    const cacheKey = `${dep.name}@${dep.version}`;
    const license = await fetchNpmLicense(dep.name, dep.version);
    licenseResults.set(cacheKey, license);
  }

  for (const dep of directDeps) {
    const cacheKey = `${dep.name}@${dep.version}`;
    const license =
      dep.licenseFromLockfile != null && dep.licenseFromLockfile !== ''
        ? dep.licenseFromLockfile
        : licenseResults.get(cacheKey) ?? null;
    rows.push({
      name: dep.name,
      version: dep.version,
      license,
      is_direct: true,
      source: dep.source,
    });
  }

  // Add transitive deps (no license fetch needed - use what's in lockfile)
  lockData.transitiveEntries.forEach((dep) => {
    rows.push({
      name: dep.name,
      version: dep.version,
      license: dep.license,
      is_direct: false,
      source: 'transitive',
    });
  });

  return rows;
};

// ============================================================================
// EXPORTED FUNCTION - Used by projects.ts for direct import
// ============================================================================

export async function extractDependencies(
  projectId: string,
  organizationId: string,
  repoRecord: { installation_id: number; repo_full_name: string; default_branch: string; package_json_path?: string }
): Promise<{ success: boolean; dependencies_count: number; analyzing_count: number }> {
  const package_json_path = repoRecord.package_json_path ?? '';
  const extractStart = Date.now();
  const log = (msg: string, data?: Record<string, unknown>) => {
    const elapsedMs = Date.now() - extractStart;
    const payload = { ...(data || {}), elapsedMs };
    console.log(`[EXTRACT] ${new Date().toISOString()} ${msg}`, payload);
  };
  try {
    log('start');
    const t0 = Date.now();
    const installationToken = await createInstallationToken(String(repoRecord.installation_id));
    log('got GitHub token', { elapsedMs: Date.now() - extractStart, tokenMs: Date.now() - t0 });

    const lockPath = package_json_path ? `${package_json_path}/package-lock.json` : 'package-lock.json';
    const t1 = Date.now();
    let lockContent: string;
    try {
      lockContent = await getRepositoryFileContent(
        installationToken,
        repoRecord.repo_full_name,
        lockPath,
        repoRecord.default_branch
      );
    } catch (err: any) {
      if (err?.message?.includes('404')) {
        throw new Error(`No package-lock.json found at ${lockPath}. This workspace may use a different package manager (pnpm/yarn) or has no lockfile.`);
      }
      throw err;
    }
    log('got lockfile', { length: lockContent?.length ?? 0, lockPath, elapsedMs: Date.now() - extractStart, fetchMs: Date.now() - t1 });

    const t2 = Date.now();
    const lockJson = JSON.parse(lockContent);
    const lockData = parsePackageLock(lockJson);
    const rawDependencies = await buildDependencyRows(lockData);
    log('parsed lockfile', { rawCount: rawDependencies.length, elapsedMs: Date.now() - extractStart, parseMs: Date.now() - t2 });

    // Deduplicate dependencies by unique key (name, version, is_direct, source)
    const seen = new Set<string>();
    const dependencies = rawDependencies.filter((dep) => {
      const key = `${dep.name}|${dep.version}|${dep.is_direct}|${dep.source}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Unique name@version for project (and unique package names)
    const uniqueDeps = new Map<string, { name: string; version: string; license: string | null }>();
    for (const dep of dependencies) {
      const key = `${dep.name}@${dep.version}`;
      if (!uniqueDeps.has(key)) {
        uniqueDeps.set(key, { name: dep.name, version: dep.version, license: dep.license });
      }
    }
    const uniqueNames = [...new Set(Array.from(uniqueDeps.values()).map(d => d.name))];
    log('unique names and name@version', { uniqueNames: uniqueNames.length, uniqueDeps: uniqueDeps.size, elapsedMs: Date.now() - extractStart });

    // 1) Resolve or create dependency rows (one per package name) – refactored schema
    const tResolve = Date.now();
    const nameToDependencyId = new Map<string, string>();
    const NAME_BATCH_SIZE = 50;
    for (let i = 0; i < uniqueNames.length; i += NAME_BATCH_SIZE) {
      const nameBatch = uniqueNames.slice(i, i + NAME_BATCH_SIZE);
      const { data } = await supabase.from('dependencies').select('id, name').in('name', nameBatch);
      if (data) for (const row of data) nameToDependencyId.set(row.name, row.id);
    }
    const namesToCreate = uniqueNames.filter((n) => !nameToDependencyId.has(n));
    log('dependencies: existing vs to create', { existing: nameToDependencyId.size, toCreate: namesToCreate.length, resolveBatchMs: Date.now() - tResolve });

    // Insert new dependencies in batches (name + license only; no npm fetch here).
    const tCreateDeps = Date.now();
    const nameToLicense = new Map<string, string | null>();
    for (const [key, dep] of uniqueDeps) if (!nameToLicense.has(dep.name)) nameToLicense.set(dep.name, dep.license);
    const DEP_INSERT_BATCH = 100;
    for (let i = 0; i < namesToCreate.length; i += DEP_INSERT_BATCH) {
      const batch = namesToCreate.slice(i, i + DEP_INSERT_BATCH);
      const rows = batch.map((name) => ({ name, license: nameToLicense.get(name) ?? null }));
      const { data: inserted, error } = await supabase
        .from('dependencies')
        .insert(rows)
        .select('id, name');
      if (error) throw error;
      if (inserted) for (const row of inserted) nameToDependencyId.set(row.name, row.id);
    }
    if (namesToCreate.length > 0) log('dependencies created (no npm fetch)', { created: namesToCreate.length, createDepsMs: Date.now() - tCreateDeps, elapsedMs: Date.now() - extractStart });

    // 2) Get or create dependency_versions in batches (batch select existing, then batch insert missing).
    const tVersions = Date.now();
    const keyToVersionId = new Map<string, string>(); // name@version -> dependency_version.id
    const versionsToCreate: Array<{ dependency_id: string; name: string; version: string }> = [];
    const versionBatchSize = 100;
    const entries: Array<{ key: string; dependency_id: string; name: string; version: string }> = [];
    for (const [key, dep] of uniqueDeps) {
      const dependencyId = nameToDependencyId.get(dep.name);
      if (dependencyId) entries.push({ key, dependency_id: dependencyId, name: dep.name, version: dep.version });
    }
    log('dependency_versions: batch resolve/create', { total: entries.length, batchSize: versionBatchSize });

    for (let i = 0; i < entries.length; i += versionBatchSize) {
      const batch = entries.slice(i, i + versionBatchSize);
      const batchNum = Math.floor(i / versionBatchSize) + 1;
      const totalBatches = Math.ceil(entries.length / versionBatchSize);
      const dependencyIds = [...new Set(batch.map((e) => e.dependency_id))];

      // Fetch existing dependency_versions for these dependency_ids (all versions we might need are in batch)
      const { data: existingRows, error: selectErr } = await supabase
        .from('dependency_versions')
        .select('id, dependency_id, version')
        .in('dependency_id', dependencyIds);
      if (selectErr) throw selectErr;
      const existingMap = new Map<string, string>(); // "dependency_id|version" -> id
      if (existingRows) for (const r of existingRows) existingMap.set(`${r.dependency_id}|${r.version}`, r.id);

      const toInsert: Array<{ dependency_id: string; version: string }> = [];
      for (const e of batch) {
        const mapKey = `${e.dependency_id}|${e.version}`;
        const id = existingMap.get(mapKey);
        if (id) {
          keyToVersionId.set(e.key, id);
        } else {
          toInsert.push({ dependency_id: e.dependency_id, version: e.version });
          versionsToCreate.push({ dependency_id: e.dependency_id, name: e.name, version: e.version });
        }
      }

      if (toInsert.length > 0) {
        const { data: insertedRows, error: insertErr } = await supabase
          .from('dependency_versions')
          .insert(toInsert)
          .select('id, dependency_id, version');
        if (insertErr) throw insertErr;
        if (insertedRows) {
          for (const r of insertedRows) existingMap.set(`${r.dependency_id}|${r.version}`, r.id);
          for (const e of batch) {
            const id = existingMap.get(`${e.dependency_id}|${e.version}`);
            if (id) keyToVersionId.set(e.key, id);
          }
        }
      }

      if (batchNum % 2 === 0 || batchNum === totalBatches) {
        log(`dependency_versions batch ${batchNum}/${totalBatches}`, { processed: Math.min(i + versionBatchSize, entries.length), phaseMs: Date.now() - tVersions, elapsedMs: Date.now() - extractStart });
      }
    }
    log('dependency_versions done', { total: entries.length, toAnalyze: versionsToCreate.length, dependencyVersionsPhaseMs: Date.now() - tVersions, elapsedMs: Date.now() - extractStart });

    // Queue population for newly created dependencies only (package-level, not per-version).
    // Only queue populate for package names that are direct in this project (not transitive-only).
    const directNames = new Set(dependencies.filter((d) => d.is_direct).map((d) => d.name));
    let populatingCount = 0;
    const qstashOk = isQStashConfigured();
    const newDepsToPopulate = namesToCreate
      .filter((name) => directNames.has(name))
      .map((name) => ({ dependencyId: nameToDependencyId.get(name)!, name }))
      .filter((d) => d.dependencyId);
    if (newDepsToPopulate.length > 0 && qstashOk) {
      const { queued } = await queuePopulateDependencyBatch(newDepsToPopulate);
      populatingCount = queued;
      log('Queued dependency population', { queued, total: newDepsToPopulate.length, note: 'each new package queued once' });
    } else if (newDepsToPopulate.length > 0 && !qstashOk) {
      log('QStash not configured - new dependencies remain pending', { pending: newDepsToPopulate.length });
    }

    // 3) Clear and re-insert project_dependencies with dependency_id + dependency_version_id
    const tProjDeps = Date.now();
    log('project_dependencies: delete old, insert new...');
    await supabase.from('project_dependencies').delete().eq('project_id', projectId);
    const deleteMs = Date.now() - tProjDeps;

    const projectDepsToInsert = dependencies.map((dep) => {
      const key = `${dep.name}@${dep.version}`;
      return {
        project_id: projectId,
        dependency_id: nameToDependencyId.get(dep.name) ?? null,
        dependency_version_id: keyToVersionId.get(key) ?? null,
        name: dep.name,
        version: dep.version,
        is_direct: dep.is_direct,
        source: dep.source,
        environment: dep.source === 'dependencies' ? 'prod' : dep.source === 'devDependencies' ? 'dev' : null,
      };
    });

    const chunkSize = 500;
    const insertedProjectDeps: Array<{ id: string; name: string; version: string }> = [];

    for (let i = 0; i < projectDepsToInsert.length; i += chunkSize) {
      const chunk = projectDepsToInsert.slice(i, i + chunkSize);
      const { data: insertedChunk, error: upsertError } = await supabase
        .from('project_dependencies')
        .insert(chunk)
        .select('id, name, version');

      if (upsertError) {
        throw upsertError;
      }

      if (insertedChunk) {
        insertedProjectDeps.push(...insertedChunk);
      }
    }
    log('project_dependencies inserted', { count: insertedProjectDeps.length, deleteMs, insertMs: Date.now() - tProjDeps - deleteMs, projectDepsPhaseMs: Date.now() - tProjDeps, elapsedMs: Date.now() - extractStart });

    // Upsert dependency version edges (global table linking dependency_versions, not project-scoped)
    const tRels = Date.now();
    if (lockData.relationships.length > 0) {
      const edgesToInsert: Array<{
        parent_version_id: string;
        child_version_id: string;
      }> = [];
      const seenEdges = new Set<string>();

      for (const rel of lockData.relationships) {
        const parentKey = `${rel.parentName}@${rel.parentVersion}`;
        const childKey = `${rel.childName}@${rel.childVersion}`;

        const parentVersionId = keyToVersionId.get(parentKey);
        const childVersionId = keyToVersionId.get(childKey);

        if (parentVersionId && childVersionId) {
          const edgeKey = `${parentVersionId}|${childVersionId}`;
          if (!seenEdges.has(edgeKey)) {
            seenEdges.add(edgeKey);
            edgesToInsert.push({
              parent_version_id: parentVersionId,
              child_version_id: childVersionId,
            });
          }
        }
      }

      // Upsert edges in chunks (ignore conflicts since edges are global/shared)
      for (let i = 0; i < edgesToInsert.length; i += chunkSize) {
        const chunk = edgesToInsert.slice(i, i + chunkSize);
        const { error: edgeError } = await supabase
          .from('dependency_version_edges')
          .upsert(chunk, { onConflict: 'parent_version_id,child_version_id', ignoreDuplicates: true });

        if (edgeError) {
          console.error('Failed to upsert dependency version edges:', edgeError);
          // Don't throw - edges are supplementary data
        }
      }

      log('dependency_version_edges upserted', { count: edgesToInsert.length, edgesPhaseMs: Date.now() - tRels, elapsedMs: Date.now() - extractStart });
    }

    const status = populatingCount > 0 ? 'analyzing' : 'ready';

    await supabase
      .from('project_repositories')
      .update({
        status,
        updated_at: new Date().toISOString(),
      })
      .eq('project_id', projectId);

    await supabase
      .from('projects')
      .update({
        dependencies_count: dependencies.length,
        updated_at: new Date().toISOString(),
      })
      .eq('id', projectId)
      .eq('organization_id', organizationId);

    const totalMs = Date.now() - extractStart;
    log('extract complete', { dependencies_count: dependencies.length, populating_count: populatingCount, totalMs, elapsedMs: totalMs });
    return {
      success: true,
      dependencies_count: dependencies.length,
      analyzing_count: populatingCount,
    };
  } catch (error: any) {
    console.error('[EXTRACT] Dependency extraction failed:', error);
    await supabase
      .from('project_repositories')
      .update({
        status: 'error',
        updated_at: new Date().toISOString(),
      })
      .eq('project_id', projectId);
    throw error;
  }
}

// ============================================================================
// SCORING ALGORITHM
// ============================================================================

interface ScoreBreakdown {
  score: number;
  openssfPenalty: number;
  popularityPenalty: number;
  maintenancePenalty: number;
  slsaMultiplier: number;
  maliciousMultiplier: number;
}

function calculateDependencyScore(data: {
  openssfScore: number | null;
  weeklyDownloads: number | null;
  releasesLast12Months: number | null;
  slsaLevel: number | null;
  isMalicious: boolean;
}): ScoreBreakdown {
  // Reputation score = 100 - penalties from three components (~33 pts each)
  // Then multiplied by SLSA bonus and malicious penalty.

  // OpenSSF Scorecard penalty (~33 pts max)
  let openssfPenalty = 0;
  if (data.openssfScore !== null) {
    openssfPenalty = (10 - data.openssfScore) * 3.3;
  } else {
    openssfPenalty = 11;
  }

  // Popularity penalty (~33 pts max)
  let popularityPenalty = 0;
  if (data.weeklyDownloads !== null) {
    const logDownloads = Math.log10(data.weeklyDownloads + 1);
    popularityPenalty = Math.max(0, Math.min(33, 34 - logDownloads * 7));
  } else {
    popularityPenalty = 16;
  }

  // Maintenance penalty (~33 pts max)
  let maintenancePenalty = 0;
  if (data.releasesLast12Months !== null) {
    const releases = data.releasesLast12Months;
    if (releases >= 12) maintenancePenalty = 0;
    else if (releases >= 6) maintenancePenalty = 8;
    else if (releases >= 3) maintenancePenalty = 16;
    else if (releases >= 1) maintenancePenalty = 24;
    else maintenancePenalty = 33;
  } else {
    maintenancePenalty = 16;
  }

  const baseScore = 100 - openssfPenalty - popularityPenalty - maintenancePenalty;

  // SLSA bonus: reward packages with provenance attestations (no penalty for missing)
  const slsaMultiplier = data.slsaLevel != null
    ? (data.slsaLevel >= 3 ? 1.1 : data.slsaLevel >= 1 ? 1.05 : 1.0)
    : 1.0;

  // Malicious penalty: confirmed GHSA MALWARE classification
  const maliciousMultiplier = data.isMalicious ? 0.15 : 1.0;

  const score = Math.max(0, Math.min(100,
    Math.round(baseScore * slsaMultiplier * maliciousMultiplier)));

  return {
    score,
    openssfPenalty: Math.round(openssfPenalty * 10) / 10,
    popularityPenalty: Math.round(popularityPenalty * 10) / 10,
    maintenancePenalty: Math.round(maintenancePenalty * 10) / 10,
    slsaMultiplier,
    maliciousMultiplier,
  };
}

// ============================================================================
// API HELPERS
// ============================================================================

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { ecosystem: string; name: string };
    ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string }> }>;
    versions?: string[];
  }>;
  published?: string;
  modified?: string;
}

async function fetchOsvVulnerabilities(
  packageName: string,
  version: string
): Promise<OsvVulnerability[]> {
  try {
    const response = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        package: {
          ecosystem: 'npm',
          name: packageName,
        },
        version: version,
      }),
    });

    if (!response.ok) {
      console.error(`OSV API error for ${packageName}@${version}:`, response.status);
      return [];
    }

    const data = (await response.json()) as { vulns?: OsvVulnerability[] };
    return data.vulns || [];
  } catch (error) {
    console.error(`Failed to fetch OSV vulnerabilities for ${packageName}@${version}:`, error);
    return [];
  }
}

function classifyVulnerabilitySeverity(vuln: OsvVulnerability): string {
  // Try to extract CVSS score from severity array
  const cvss = vuln.severity?.find(s => s.type === 'CVSS_V3' || s.type === 'CVSS_V2');
  if (cvss?.score) {
    const score = parseFloat(cvss.score);
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
  }

  // Fallback: check if the ID indicates severity
  const id = vuln.id.toUpperCase();
  if (id.includes('CRITICAL')) return 'critical';
  if (id.includes('HIGH')) return 'high';
  if (id.includes('MEDIUM') || id.includes('MODERATE')) return 'medium';

  // Default to medium if unknown
  return 'medium';
}

// GHSA functions imported from ../lib/ghsa (fetchGhsaVulnerabilitiesBatch,
// filterGhsaVulnsByVersion, ghsaSeverityToLevel, ghsaVulnToRow, GhsaVuln, getGitHubToken)

/**
 * Fetch SLSA provenance level from npm attestations API.
 * Only works for npm packages. Returns null for non-npm or packages without provenance.
 */
async function fetchSlsaLevel(packageName: string, version: string): Promise<number | null> {
  try {
    await waitForNpmRateLimit();
    const encoded = encodeURIComponent(`${packageName}@${version}`);
    const attestUrl = `https://registry.npmjs.org/-/npm/v1/attestations/${encoded}`;
    const res = await fetch(attestUrl, {
      headers: { 'User-Agent': 'Deptex-App' },
    });
    recordNpmCall();
    if (!res.ok) return null;

    const data = (await res.json()) as {
      attestations?: Array<{
        predicateType?: string;
        bundle?: { dsseEnvelope?: { payload?: string } };
      }>;
    };

    const slsaAttestation = data.attestations?.find((a) =>
      a.predicateType?.includes('slsa') || a.predicateType?.includes('provenance')
    );
    if (!slsaAttestation) return null;

    // Try to extract build level from the payload
    try {
      const payload = slsaAttestation.bundle?.dsseEnvelope?.payload;
      if (payload) {
        const decoded = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
        const buildLevel = decoded?.predicate?.buildDefinition?.buildType;
        if (typeof buildLevel === 'string') {
          const levelMatch = buildLevel.match(/L(\d)/i);
          if (levelMatch) return parseInt(levelMatch[1], 10);
        }
      }
    } catch { /* payload parse failure is non-fatal */ }

    // Has provenance but can't determine exact level — assume level 1
    return 1;
  } catch {
    recordNpmCall();
    return null;
  }
}

/**
 * Update is_outdated and versions_behind for all project_dependencies using this dependency.
 */
async function updateOutdatedStatus(
  dependencyId: string,
  latestVersion: string | null,
  allVersions: string[]
): Promise<void> {
  if (!latestVersion) return;

  const { data: projDeps } = await supabase
    .from('project_dependencies')
    .select('id, version')
    .eq('dependency_id', dependencyId);
  if (!projDeps || projDeps.length === 0) return;

  for (const pd of projDeps) {
    const current = semver.valid(semver.coerce(pd.version));
    const latest = semver.valid(semver.coerce(latestVersion));
    if (!current || !latest) continue;

    const isOutdated = semver.lt(current, latest);
    let versionsBehind = 0;
    if (isOutdated && allVersions.length > 0) {
      const stableVersions = allVersions.filter((v) => {
        const parsed = semver.valid(semver.coerce(v));
        return parsed && semver.gt(parsed, current) && semver.lte(parsed, latest);
      });
      versionsBehind = stableVersions.length;
    }

    await supabase
      .from('project_dependencies')
      .update({ is_outdated: isOutdated, versions_behind: versionsBehind })
      .eq('id', pd.id);
  }
}

interface OpenssfScorecardResult {
  score: number | null;
  data: Record<string, any> | null;  // Full scorecard JSON for storage
}

/** Call OpenSSF Scorecard API only (no npm). Use when you already have github_url from npm. */
async function fetchOpenssfScorecardForRepo(githubUrl: string | null): Promise<OpenssfScorecardResult> {
  if (!githubUrl || typeof githubUrl !== 'string') return { score: null, data: null };
  try {
    const project = githubUrl.replace(/^https?:\/\//, '').replace(/\.git$/i, '').trim();
    if (!project.startsWith('github.com/')) return { score: null, data: null };
    const scorecardResponse = await fetch(
      `https://api.securityscorecards.dev/projects/${project}`,
      { headers: { 'User-Agent': 'Deptex-App' } }
    );
    if (!scorecardResponse.ok) return { score: null, data: null };
    const scorecardData = (await scorecardResponse.json()) as Record<string, unknown>;
    return { score: (scorecardData.score as number | null) ?? null, data: scorecardData as Record<string, unknown> | null };
  } catch (error) {
    return { score: null, data: null };
  }
}

interface NpmPackageInfo {
  weeklyDownloads: number | null;
  lastPublishedAt: Date | null;
  versions: string[];
  versionTimestamps: Record<string, string>; // version -> ISO date
  releasesLast12Months: number;
  github_url: string | null;
  latest_version: string | null;
  latest_release_date: string | null; // ISO
  description: string | null;
}

async function fetchNpmPackageInfo(packageName: string): Promise<NpmPackageInfo> {
  const result: NpmPackageInfo = {
    weeklyDownloads: null,
    lastPublishedAt: null,
    versions: [],
    versionTimestamps: {},
    releasesLast12Months: 0,
    github_url: null,
    latest_version: null,
    latest_release_date: null,
    description: null,
  };

  // For scoped packages like @types/node, npm API needs different encoding:
  // - Registry API: @types%2Fnode (encodeURIComponent handles this)
  // - Downloads API: @types/node (no encoding of the slash)
  const encodedForRegistry = encodeURIComponent(packageName);
  // For downloads API, scoped packages use the format: @scope/package (slash not encoded)
  const encodedForDownloads = packageName.startsWith('@')
    ? packageName  // Keep as-is for scoped packages
    : encodeURIComponent(packageName);

  const registryUrl = `https://registry.npmjs.org/${encodedForRegistry}`;
  const downloadsUrl = `https://api.npmjs.org/downloads/point/last-week/${encodedForDownloads}`;
  try {
    await waitForNpmRateLimit();
    console.log('[NPM] GET', registryUrl, { package: packageName, api: 'registry', usage: 'packageInfo' });
    const metaResponse = await fetch(registryUrl, {
      headers: { 'User-Agent': 'Deptex-App' },
    });

    recordNpmCall();
    if (metaResponse.ok) {
      const metaData = (await metaResponse.json()) as Record<string, unknown>;

      // Get package description
      if (typeof metaData.description === 'string' && metaData.description.trim()) {
        result.description = metaData.description.trim();
      }

      // Get last published date
      const metaTime = metaData.time as { modified?: string; [k: string]: unknown } | undefined;
      if (metaTime?.modified) {
        result.lastPublishedAt = new Date(metaTime.modified);
      }

      // Get version list for fetching past vulnerabilities (stable releases only, newest first)
      const metaVersions = metaData.versions as Record<string, unknown> | undefined;
      if (metaVersions) {
        const all = Object.keys(metaVersions);
        const stable = all.filter((v) => isStableVersion(v));
        result.versions = stable.length > 0 ? semver.rsort(stable) : all.reverse();
      }

      // Get version timestamps and count stable releases in last 12 months
      if (metaTime) {
        const now = new Date();
        const oneYearAgo = new Date(now);
        oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
        let recentCount = 0;
        for (const [ver, dateStr] of Object.entries(metaTime)) {
          if (ver === 'created' || ver === 'modified') continue; // skip metadata keys
          if (typeof dateStr === 'string') {
            result.versionTimestamps[ver] = dateStr;
            if (isStableVersion(ver)) {
              const d = new Date(dateStr);
              if (d >= oneYearAgo) recentCount++;
            }
          }
        }
        result.releasesLast12Months = recentCount;
      }

      // GitHub URL from repository field
      const metaRepo = metaData?.repository as { url?: string } | string | undefined;
      const repo = (typeof metaRepo === 'object' && metaRepo?.url) ? metaRepo.url : metaRepo;
      if (typeof repo === 'string') {
        const m = repo.match(/github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?$/i);
        if (m) result.github_url = `https://github.com/${m[1]}/${m[2]}`;
      }

      // Latest version and its release date (for dependencies table)
      const distTags = metaData?.['dist-tags'] as { latest?: string } | undefined;
      const latest = distTags?.latest;
      if (latest) {
        result.latest_version = latest;
        const timeMap = metaData?.time as Record<string, string> | undefined;
        const time = timeMap?.[latest];
        if (time) result.latest_release_date = new Date(time).toISOString();
      }
    }

    await waitForNpmRateLimit();
    console.log('[NPM] GET', downloadsUrl, { package: packageName, api: 'downloads', usage: 'packageInfo' });
    let downloadsResponse = await fetch(downloadsUrl, { headers: { 'User-Agent': 'Deptex-App' } });
    recordNpmCall();

    // Retry up to 2 times with increasing backoff if rate limited
    if (downloadsResponse.status === 429) {
      console.warn('[NPM] GET', downloadsUrl, { status: 429, retryIn: '2s' });
      await new Promise(resolve => setTimeout(resolve, 2000));
      await waitForNpmRateLimit();
      console.log('[NPM] GET', downloadsUrl, { package: packageName, api: 'downloads', retry: 1 });
      downloadsResponse = await fetch(downloadsUrl, { headers: { 'User-Agent': 'Deptex-App' } });
      recordNpmCall();

      if (downloadsResponse.status === 429) {
        console.warn('[NPM] GET', downloadsUrl, { status: 429, retryIn: '5s' });
        await new Promise(resolve => setTimeout(resolve, 5000));
        await waitForNpmRateLimit();
        console.log('[NPM] GET', downloadsUrl, { package: packageName, api: 'downloads', retry: 2 });
        downloadsResponse = await fetch(downloadsUrl, { headers: { 'User-Agent': 'Deptex-App' } });
        recordNpmCall();
      }
    }

    if (downloadsResponse.ok) {
      const downloadsData = (await downloadsResponse.json()) as { downloads?: number };
      result.weeklyDownloads = downloadsData.downloads ?? null;
    }
  } catch (error: any) {
    console.error(`Failed to fetch npm info for ${packageName}:`, error);
  }

  return result;
}

// ============================================================================
// ROUTES
// ============================================================================

// Middleware to verify extraction worker (shared secret)
const verifyWorkerSecret = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const secret = process.env.EXTRACTION_WORKER_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === 'development') return next();
    return res.status(500).json({ error: 'EXTRACTION_WORKER_SECRET not configured' });
  }
  const headerSecret = (req.headers['x-worker-secret'] as string) || (req.headers.authorization?.replace(/^Bearer\s+/i, ''));
  if (!headerSecret || headerSecret !== secret) {
    return res.status(401).json({ error: 'Invalid or missing worker secret' });
  }
  next();
};

// Middleware to verify QStash signatures
const verifyQStash = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const signature = req.headers['upstash-signature'] as string;

  if (!signature) {
    // Allow requests without signature in dev mode (when QStash not configured)
    if (!isQStashConfigured()) {
      return next();
    }
    return res.status(401).json({ error: 'Missing QStash signature' });
  }

  // Use the raw body captured by express.json verify callback
  // This is critical - QStash signs the exact raw body, not re-stringified JSON
  const rawBody = (req as any).rawBody || JSON.stringify(req.body);
  const isValid = await verifyQStashSignature(signature, rawBody);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid QStash signature' });
  }

  next();
};

// Helper function to populate a single dependency (package-level)
// Fetches registry info, creates version rows, fetches GHSA vulns, OpenSSF, and calculates reputation score
async function populateSingleDependency(
  dependencyId: string,
  name: string,
  preFetchedGhsaVulns?: GhsaVuln[],
  ecosystem?: string
): Promise<{ success: boolean; score?: number; error?: string }> {
  const eco = ecosystem || 'npm';
  try {
    await supabase
      .from('dependencies')
      .update({ status: 'analyzing', updated_at: new Date().toISOString() })
      .eq('id', dependencyId);

    // 1. Fetch registry data (routes to ecosystem-specific fetcher)
    let npmInfo: NpmPackageInfo;
    if (eco === 'npm') {
      npmInfo = await fetchNpmPackageInfo(name);
    } else {
      const { fetchRegistryInfo } = await import('../../../backend/src/lib/registry-fetchers');
      const regInfo = await fetchRegistryInfo(eco, name);
      npmInfo = regInfo ? {
        versions: regInfo.versions,
        weeklyDownloads: regInfo.weeklyDownloads,
        github_url: regInfo.github_url,
        lastPublishedAt: regInfo.lastPublishedAt,
        latest_version: regInfo.latest_version,
        latest_release_date: regInfo.latest_release_date,
        releasesLast12Months: regInfo.releasesLast12Months,
        description: regInfo.description,
        versionTimestamps: regInfo.versionTimestamps,
      } : await fetchNpmPackageInfo(name);
    }

    // 2. Take the 20 most recent stable versions from npm and create dependency_versions rows
    const recentVersions = npmInfo.versions.slice(0, 20);
    if (recentVersions.length > 0) {
      const versionRows = recentVersions.map((v) => ({
        dependency_id: dependencyId,
        version: v,
      }));
      // Upsert to avoid conflicts if some versions already exist
      await supabase
        .from('dependency_versions')
        .upsert(versionRows, { onConflict: 'dependency_id,version', ignoreDuplicates: true });
    }

    // 3. Fetch GHSA vulnerabilities for this package (ecosystem-aware)
    let ghsaVulnsForPackage: GhsaVuln[] = preFetchedGhsaVulns ?? [];
    if (ghsaVulnsForPackage.length === 0) {
      const m = await fetchGhsaVulnerabilitiesBatch([name], eco);
      ghsaVulnsForPackage = m.get(name) ?? [];
    }

    // 4. Vuln counts are derived at read time from dependency_vulnerabilities (no longer stored on dependency_versions).

    // Invalidate latest safe version cache for this dependency
    await invalidateLatestSafeVersionCacheByDependencyId(dependencyId);
    await invalidateDependencyVersionsCacheByDependencyId(dependencyId);

    // 5. Store ALL GHSA vulnerability details in dependency_vulnerabilities (not just those affecting top 20 versions).
    // Otherwise packages like React with only old-version advisories would show zero vulns in the DB.
    const { data: existingVulnIds } = await supabase
      .from('dependency_vulnerabilities')
      .select('osv_id')
      .eq('dependency_id', dependencyId);
    const existingOsvIds = new Set((existingVulnIds || []).map((r: any) => r.osv_id));

    const toInsert = ghsaVulnsForPackage.filter((v) => !existingOsvIds.has(v.ghsaId));
    if (toInsert.length > 0) {
      const vulnInserts = toInsert.map((v) => ghsaVulnToRow(dependencyId, v));
      await supabase
        .from('dependency_vulnerabilities')
        .upsert(vulnInserts, { onConflict: 'dependency_id,osv_id' });
    }

    // 5b. Check if any advisory has MALWARE classification -> flag dependency
    const isMalicious = ghsaVulnsForPackage.some((v) => v.classification === 'MALWARE');

    // 6. Fetch OpenSSF scorecard
    const openssfResult = await fetchOpenssfScorecardForRepo(npmInfo.github_url);
    const openssfScore = openssfResult.score;
    const openssfData = openssfResult.data;

    // 6b. Fetch SLSA provenance for latest version (npm only)
    let latestSlsaLevel: number | null = null;
    if (eco === 'npm' && npmInfo.latest_version) {
      latestSlsaLevel = await fetchSlsaLevel(name, npmInfo.latest_version);
      if (latestSlsaLevel != null) {
        await supabase
          .from('dependency_versions')
          .update({ slsa_level: latestSlsaLevel })
          .eq('dependency_id', dependencyId)
          .eq('version', npmInfo.latest_version);
      }
    }

    // 6c. Update outdated status for all project_dependencies using this package
    try {
      await updateOutdatedStatus(dependencyId, npmInfo.latest_version, npmInfo.versions);
    } catch (e: any) {
      console.warn(`[POPULATE] Failed to update outdated status for ${name}:`, e.message);
    }

    // 7. Calculate reputation score (OpenSSF + popularity + maintenance + SLSA + malicious)
    const scoreBreakdown = calculateDependencyScore({
      openssfScore,
      weeklyDownloads: npmInfo.weeklyDownloads,
      releasesLast12Months: npmInfo.releasesLast12Months,
      slsaLevel: latestSlsaLevel,
      isMalicious,
    });

    // 8. Update dependencies with all package-level data
    const { error: depUpdateError } = await supabase
      .from('dependencies')
      .update({
        status: 'ready',
        score: scoreBreakdown.score,
        is_malicious: isMalicious,
        openssf_score: openssfScore,
        openssf_data: openssfData,
        weekly_downloads: npmInfo.weeklyDownloads,
        last_published_at: npmInfo.lastPublishedAt?.toISOString() || null,
        github_url: npmInfo.github_url || null,
        latest_version: npmInfo.latest_version || null,
        latest_release_date: npmInfo.latest_release_date || null,
        releases_last_12_months: npmInfo.releasesLast12Months,
        description: npmInfo.description || null,
        openssf_penalty: Math.round(scoreBreakdown.openssfPenalty),
        popularity_penalty: Math.round(scoreBreakdown.popularityPenalty),
        maintenance_penalty: Math.round(scoreBreakdown.maintenancePenalty),
        slsa_multiplier: Math.round((scoreBreakdown.slsaMultiplier ?? 1) * 100) / 100,
        malicious_multiplier: Math.round((scoreBreakdown.maliciousMultiplier ?? 1) * 100) / 100,
        analyzed_at: new Date().toISOString(),
        error_message: null,
        updated_at: new Date().toISOString(),
      })
      .eq('id', dependencyId);

    if (depUpdateError) {
      console.error(`Failed to update dependency ${name}:`, depUpdateError);
      throw new Error(`Database update failed: ${depUpdateError.message}`);
    }

    console.log(`Populated ${name}: score=${scoreBreakdown.score}, versions=${recentVersions.length}, releases12mo=${npmInfo.releasesLast12Months}`);

    return { success: true, score: scoreBreakdown.score };
  } catch (error: any) {
    console.error(`Failed to populate dependency ${name}:`, error);

    await supabase
      .from('dependencies')
      .update({
        status: 'error',
        error_message: error.message || 'Population failed',
        updated_at: new Date().toISOString(),
      })
      .eq('id', dependencyId);

    return { success: false, error: error.message || 'Population failed' };
  }
}

// Only one populate-dependencies run at a time to avoid npm/GitHub 429s when multiple projects queue together.
let populateDependenciesInFlight = false;

// POST /api/workers/queue-populate - Called by extraction worker to queue populate jobs for new deps
// Auth: X-Worker-Secret or Authorization: Bearer <EXTRACTION_WORKER_SECRET>
router.post('/queue-populate', verifyWorkerSecret, async (req: express.Request, res: express.Response) => {
  const { projectId, organizationId, dependencies, ecosystem: bodyEcosystem } = req.body || {};

  if (!projectId || !organizationId || !dependencies || !Array.isArray(dependencies)) {
    return res.status(400).json({ error: 'projectId, organizationId, and dependencies array are required' });
  }

  const fallbackEcosystem = bodyEcosystem || 'npm';
  const deps = (dependencies as Array<{ dependencyId: string; name: string; ecosystem?: string }>)
    .filter((d) => d.dependencyId && d.name)
    .map((d) => ({ dependencyId: d.dependencyId, name: d.name, ecosystem: d.ecosystem || fallbackEcosystem }));

  if (deps.length === 0) {
    return res.json({ queued: 0, failed: 0, messages: 0 });
  }

  try {
    const result = await queuePopulateDependencyBatch(deps, projectId, organizationId);
    res.json(result);
  } catch (err: any) {
    console.error('queue-populate failed:', err);
    res.status(500).json({ error: err?.message || 'Failed to queue populate' });
  }
});

// POST /api/workers/populate-dependencies - Called by QStash to populate a BATCH of new dependencies
// Fetches npm info, creates version rows, GHSA vulns, OpenSSF, and calculates reputation score
router.post('/populate-dependencies', verifyQStash, async (req: express.Request, res: express.Response) => {
  const { dependencies, ecosystem: batchEcosystem, projectId, organizationId } = req.body || {};

  if (!dependencies || !Array.isArray(dependencies) || dependencies.length === 0) {
    return res.status(400).json({ error: 'dependencies array is required' });
  }

  if (populateDependenciesInFlight) {
    res.status(503).setHeader('Retry-After', '60').json({
      error: 'Another populate batch is in progress. QStash will retry.',
      code: 'POPULATE_BUSY',
    });
    return;
  }

  populateDependenciesInFlight = true;
  const eco = batchEcosystem || 'npm';
  try {
    console.log(`Populating batch of ${dependencies.length} dependencies (ecosystem: ${eco})`);

    // GHSA batch query (ecosystem-aware)
    const uniqueNames = [...new Set((dependencies as Array<{ name?: string }>).map((d) => d.name).filter(Boolean))] as string[];
    const ghsaBatch = new Map<string, GhsaVuln[]>();
    const numChunks = Math.ceil(uniqueNames.length / 100);
    for (let i = 0; i < uniqueNames.length; i += 100) {
      const chunk = uniqueNames.slice(i, i + 100);
      const m = await fetchGhsaVulnerabilitiesBatch(chunk, eco);
      m.forEach((vulns, name) => ghsaBatch.set(name, vulns));
    }
    if (uniqueNames.length > 0) {
      console.log(`[GHSA] Fetched vulns for ${uniqueNames.length} ${eco} packages in ${numChunks} request(s) (batch)`);
    }

    const results: Array<{ name: string; success: boolean; score?: number; error?: string }> = [];

    for (const dep of dependencies) {
      if (!dep.dependencyId || !dep.name) {
        results.push({ name: dep.name || 'unknown', success: false, error: 'Missing required fields' });
        continue;
      }

      const depEcosystem = dep.ecosystem || eco;
      const preFetched = ghsaBatch.get(dep.name) ?? [];
      const result = await populateSingleDependency(dep.dependencyId, dep.name, preFetched, depEcosystem);
      results.push({
        name: dep.name,
        ...result,
      });

      await new Promise(resolve => setTimeout(resolve, 900));
    }

    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;

    console.log(`Populate batch complete: ${successful} succeeded, ${failed} failed`);

    // Enqueue backfill for each successfully populated dependency (fire-and-forget)
    if (isQStashConfigured()) {
      for (let i = 0; i < results.length; i++) {
        if (results[i].success && dependencies[i]?.dependencyId && dependencies[i]?.name) {
          queueBackfillDependencyTrees(dependencies[i].dependencyId, dependencies[i].name).catch((err) =>
            console.error(`Failed to queue backfill for ${dependencies[i].name}:`, err)
          );
        }
      }
    }

    // Run policy evaluation after populate completes (Phase 4)
    if (projectId && organizationId && successful > 0) {
      try {
        const { evaluateProjectPolicies } = await import('../lib/policy-engine');
        console.log(`[Policy] Evaluating policies for project ${projectId} after populate...`);
        const evalResult = await evaluateProjectPolicies(projectId, organizationId);
        console.log(`[Policy] Project ${projectId}: status=${evalResult.statusName}, deps evaluated=${evalResult.depResults}, violations=${evalResult.violations.length}`);

        await supabase
          .from('project_repositories')
          .update({ status: 'ready' })
          .eq('project_id', projectId);
      } catch (policyErr: any) {
        console.error(`[Policy] Failed to evaluate policies for project ${projectId}:`, policyErr?.message);
      }
    }

    res.json({
      success: failed === 0,
      total: dependencies.length,
      successful,
      failed,
      results,
    });
  } catch (err: any) {
    console.error('populate-dependencies batch failed:', err);
    if (!res.headersSent) res.status(500).json({ error: err?.message || 'Batch failed' });
  } finally {
    populateDependenciesInFlight = false;
  }
});

// POST /api/workers/backfill-dependency-trees - Populate transitive edges for versions with none (runs after populate)
router.post('/backfill-dependency-trees', verifyQStash, async (req: express.Request, res: express.Response) => {
  const { dependencyId, name } = req.body || {};

  if (!dependencyId || !name) {
    return res.status(400).json({ error: 'dependencyId and name are required' });
  }

  const BACKFILL_DELAY_MS = 1100;

  try {
    const { data: allVersions, error: versionsError } = await supabase
      .from('dependency_versions')
      .select('id, version')
      .eq('dependency_id', dependencyId);

    if (versionsError) {
      throw versionsError;
    }

    if (!allVersions || allVersions.length === 0) {
      return res.json({ versionsProcessed: 0, edgesAdded: 0, message: 'No versions to backfill' });
    }

    const versionIds = (allVersions as { id: string }[]).map((v) => v.id);
    const { data: versionsWithEdges } = await supabase
      .from('dependency_version_edges')
      .select('parent_version_id')
      .in('parent_version_id', versionIds);

    const hasEdges = new Set((versionsWithEdges || []).map((e: { parent_version_id: string }) => e.parent_version_id));
    const toProcess = (allVersions as { id: string; version: string }[]).filter((v) => !hasEdges.has(v.id));

    let totalEdges = 0;
    for (let i = 0; i < toProcess.length; i++) {
      const dv = toProcess[i];
      const edges = await resolveAndUpsertTransitiveEdges(supabase, dv.id, name, dv.version);
      totalEdges += edges;
      if (i < toProcess.length - 1) {
        await new Promise((r) => setTimeout(r, BACKFILL_DELAY_MS));
      }
    }

    console.log(
      `[backfill] ${name}: ${toProcess.length} versions processed, ${totalEdges} edges added`
    );

    return res.json({
      versionsProcessed: toProcess.length,
      edgesAdded: totalEdges,
    });
  } catch (err: any) {
    console.error('backfill-dependency-trees failed:', err);
    if (!res.headersSent) {
      return res.status(500).json({ error: err?.message || 'Backfill failed' });
    }
  }
});

// POST /api/workers/extract-deps - Legacy endpoint (kept for compatibility)
router.post('/extract-deps', async (req: express.Request, res: express.Response) => {
  const expectedToken = process.env.QSTASH_TOKEN;
  if (expectedToken) {
    const authHeader = req.headers.authorization || '';
    if (authHeader !== `Bearer ${expectedToken}`) {
      return res.status(401).json({ error: 'Unauthorized worker request' });
    }
  }

  const { projectId, organizationId } = req.body || {};
  if (!projectId || !organizationId) {
    return res.status(400).json({ error: 'projectId and organizationId are required' });
  }

  try {
    const { data: repoRecord, error: repoError } = await supabase
      .from('project_repositories')
      .select('*')
      .eq('project_id', projectId)
      .single();

    if (repoError || !repoRecord) {
      return res.status(404).json({ error: 'Project repository not found' });
    }

    const result = await extractDependencies(projectId, organizationId, {
      installation_id: repoRecord.installation_id,
      repo_full_name: repoRecord.repo_full_name,
      default_branch: repoRecord.default_branch,
      package_json_path: repoRecord.package_json_path ?? '',
    });
    await invalidateProjectCaches(organizationId, projectId).catch(() => {});

    res.json(result);
  } catch (error: any) {
    console.error('Dependency extraction worker failed:', error);
    res.status(500).json({ error: error.message || 'Dependency extraction failed' });
  }
});

export default router;
