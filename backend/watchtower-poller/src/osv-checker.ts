/**
 * OSV Vulnerability Checker for Watchtower Poller
 *
 * Handles:
 * 1. Checking npm registry for new version releases
 * 2. Querying OSV API for package vulnerabilities
 * 3. Querying npm registry advisory API for vulnerabilities (second source)
 * 4. Detecting newly disclosed vulnerabilities
 */

import semver from 'semver';

/** NPM advisory item as returned by the bulk advisories endpoint */
export interface NpmAdvisory {
  id?: number;
  url?: string;
  title?: string;
  severity?: string;
  vulnerable_versions?: string;
  patched_versions?: string;
  overview?: string;
  recommendation?: string;
  references?: string[];
  cwe?: string[];
  cvss?: { score?: number; vector?: string };
  found_by?: unknown;
  deleted?: unknown;
}

export interface NpmAdvisoryWithId {
  id: string;
  advisory: NpmAdvisory;
}

export interface OsvVulnerability {
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

export interface ProcessedVulnerability {
  osvId: string;
  severity: string;
  summary: string | null;
  details: string | null;
  aliases: string[];
  affectedVersions: any;
  fixedVersions: string[];
  publishedAt: string | null;
  modifiedAt: string | null;
}

export interface NpmVersionInfo {
  latestVersion: string | null;
  publishedAt: string | null;
}

export interface OsvCheckResult {
  newVulnerabilities: ProcessedVulnerability[];
  allVulnerabilities: ProcessedVulnerability[];
  latestNpmVersion: string | null;
  isNewVersion: boolean;
  error?: string;
}

/**
 * Fetch the latest **stable** version from npm registry (no canary/rc/experimental).
 * If dist-tags.latest is a prerelease, we resolve the latest stable from versions + time.
 */
export async function fetchLatestNpmVersion(packageName: string): Promise<NpmVersionInfo> {
  try {
    const encodedName = encodeURIComponent(packageName);
    const response = await fetch(`https://registry.npmjs.org/${encodedName}`, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Deptex-Watchtower-Poller',
      },
    });

    if (!response.ok) {
      console.log(`[${new Date().toISOString()}] ⚠️ npm registry returned ${response.status} for ${packageName}`);
      return { latestVersion: null, publishedAt: null };
    }

    const data = (await response.json()) as {
      'dist-tags'?: { latest?: string };
      time?: Record<string, string>;
      versions?: Record<string, unknown>;
    };
    let latestVersion = data['dist-tags']?.latest || null;

    if (latestVersion && (!semver.valid(latestVersion) || semver.prerelease(latestVersion))) {
      latestVersion = resolveLatestStable(data.versions, data.time);
    }

    const publishedAt =
      latestVersion && data.time?.[latestVersion] ? data.time[latestVersion] : null;
    return { latestVersion, publishedAt };
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Failed to fetch npm info for ${packageName}:`, error.message);
    return { latestVersion: null, publishedAt: null };
  }
}

function resolveLatestStable(
  versions: Record<string, unknown> | undefined,
  time: Record<string, string> | undefined
): string | null {
  if (!versions || !time) return null;
  const candidates = Object.keys(versions)
    .filter((v) => semver.valid(v) && !semver.prerelease(v))
    .map((v) => ({ v, t: time[v] }))
    .filter((x) => x.t)
    .sort((a, b) => new Date(b.t).getTime() - new Date(a.t).getTime());
  return candidates.length > 0 ? candidates[0].v : null;
}

const NPM_ADVISORY_BULK_URL = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk';

/**
 * Fetch npm security advisories for a package and versions (second vuln source alongside OSV).
 * Uses the same bulk endpoint npm audit uses. Versions must be non-empty; use at least latest_version.
 */
export async function fetchNpmAdvisories(
  packageName: string,
  versions: string[]
): Promise<NpmAdvisoryWithId[]> {
  if (versions.length === 0) return [];
  try {
    const body: Record<string, string[]> = { [packageName]: versions };
    const response = await fetch(NPM_ADVISORY_BULK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Deptex-Watchtower-Poller',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      if (response.status === 404 || response.status === 400) return [];
      console.log(`[${new Date().toISOString()}] ⚠️ npm advisory API returned ${response.status} for ${packageName}`);
      return [];
    }

    const data = (await response.json()) as Record<string, Record<string, NpmAdvisory> | NpmAdvisory[]>;
    const byPkg = data[packageName];
    if (!byPkg) return [];

    if (Array.isArray(byPkg)) {
      return byPkg.map((adv, i) => ({
        id: String(adv.id ?? adv.url ?? i),
        advisory: adv,
      }));
    }
    return Object.entries(byPkg).map(([id, adv]) => ({ id, advisory: adv }));
  } catch (error: any) {
    console.log(`[${new Date().toISOString()}] ⚠️ npm advisories for ${packageName}: ${error.message}`);
    return [];
  }
}

/**
 * Convert npm advisory to our storage format. Uses osv_id = "npm-{id}" so it doesn't conflict with OSV ids.
 */
export function processNpmAdvisory(item: NpmAdvisoryWithId): ProcessedVulnerability {
  const advisory = item.advisory;
  const severity = (advisory.severity || 'moderate').toLowerCase();
  const fixedVersions: string[] = advisory.patched_versions
    ? advisory.patched_versions.split(/\s*,\s*/).filter(Boolean)
    : [];
  const osvId = `npm-${item.id}`;
  const aliases: string[] = [];
  if (advisory.url) aliases.push(advisory.url);
  if (advisory.cwe?.length) aliases.push(...advisory.cwe.map((c) => `CWE-${c}`));

  return {
    osvId,
    severity: severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low' ? severity : 'medium',
    summary: advisory.title || advisory.overview || null,
    details: advisory.overview || advisory.recommendation || null,
    aliases,
    affectedVersions: advisory.vulnerable_versions ? { vulnerable_versions: advisory.vulnerable_versions } : null,
    fixedVersions,
    publishedAt: null,
    modifiedAt: null,
  };
}

/**
 * Query OSV API for all vulnerabilities affecting a package (any version)
 */
export async function fetchAllPackageVulnerabilities(packageName: string): Promise<OsvVulnerability[]> {
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
      }),
    });

    if (!response.ok) {
      console.error(`[${new Date().toISOString()}] ❌ OSV API error for ${packageName}:`, response.status);
      return [];
    }

    const data = (await response.json()) as { vulns?: OsvVulnerability[] };
    return data.vulns || [];
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Failed to fetch OSV vulnerabilities for ${packageName}:`, error.message);
    return [];
  }
}

/**
 * Query OSV API for vulnerabilities affecting a specific version
 */
export async function fetchVersionVulnerabilities(
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
      console.error(`[${new Date().toISOString()}] ❌ OSV API error for ${packageName}@${version}:`, response.status);
      return [];
    }

    const data = (await response.json()) as { vulns?: OsvVulnerability[] };
    return data.vulns || [];
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Failed to fetch OSV vulnerabilities for ${packageName}@${version}:`, error.message);
    return [];
  }
}

/**
 * Classify vulnerability severity from CVSS score
 * Reuses pattern from workers.ts
 */
export function classifyVulnerabilitySeverity(vuln: OsvVulnerability): string {
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

/**
 * Check if a vulnerability affects a given version (using OSV affected ranges).
 * Uses semver for comparison; returns false for unparseable versions.
 */
export function vulnAffectsVersion(vuln: OsvVulnerability, version: string): boolean {
  const v = semver.valid(semver.coerce(version));
  if (!v) return false;

  const affected = vuln.affected;
  if (!affected?.length) return true; // no range = assume affected

  for (const a of affected) {
    const ranges = a.ranges;
    if (!ranges?.length) return true;

    for (const range of ranges) {
      const events = range.events || [];
      let introduced: string | null = null;
      for (const e of events) {
        if (e.introduced !== undefined) {
          introduced = e.introduced === '0' ? '0.0.0' : e.introduced;
        }
        if (e.fixed !== undefined) {
          const fixedVer = semver.valid(semver.coerce(e.fixed));
          if (introduced !== null && fixedVer) {
            try {
              const intro = semver.valid(semver.coerce(introduced)) ?? '0.0.0';
              if (intro && semver.gte(v, intro) && semver.lt(v, fixedVer)) return true;
            } catch {
              // ignore
            }
            introduced = null;
          }
        }
      }
      if (introduced !== null) {
        try {
          const intro = semver.valid(semver.coerce(introduced)) ?? '0.0.0';
          if (intro && semver.gte(v, intro)) return true;
        } catch {
          // ignore
        }
      }
    }
  }
  return false;
}

/**
 * Process raw OSV vulnerability into our storage format
 */
export function processVulnerability(vuln: OsvVulnerability): ProcessedVulnerability {
  const severity = classifyVulnerabilitySeverity(vuln);
  
  // Extract fixed versions from affected ranges
  const fixedVersions: string[] = vuln.affected?.flatMap(a => 
    a.ranges?.flatMap(r => 
      r.events?.filter(e => e.fixed).map(e => e.fixed!) || []
    ) || []
  ) || [];

  return {
    osvId: vuln.id,
    severity,
    summary: vuln.summary || null,
    details: vuln.details || null,
    aliases: vuln.aliases || [],
    affectedVersions: vuln.affected || null,
    fixedVersions,
    publishedAt: vuln.published || null,
    modifiedAt: vuln.modified || null,
  };
}

/**
 * Main function to check for OSV vulnerabilities
 * 
 * @param packageName - The npm package name
 * @param lastKnownVersion - The last npm version we knew about (to detect new releases)
 * @param knownOsvIds - Set of OSV IDs we already know about (to detect new disclosures)
 * @returns Results including new vulnerabilities and version info
 */
export async function checkOsvVulnerabilities(
  packageName: string,
  lastKnownVersion: string | null,
  knownOsvIds: Set<string>
): Promise<OsvCheckResult> {
  console.log(`[${new Date().toISOString()}] 🔍 Checking OSV vulnerabilities for ${packageName}...`);

  try {
    // Step 1: Check npm for latest version
    console.log(`[${new Date().toISOString()}] 📦 Checking npm registry for latest version...`);
    const npmInfo = await fetchLatestNpmVersion(packageName);
    const isNewVersion = npmInfo.latestVersion !== null && 
                         lastKnownVersion !== null && 
                         npmInfo.latestVersion !== lastKnownVersion;

    if (isNewVersion) {
      console.log(`[${new Date().toISOString()}] 🆕 New npm version detected: ${lastKnownVersion} -> ${npmInfo.latestVersion}`);
    } else if (npmInfo.latestVersion) {
      console.log(`[${new Date().toISOString()}] 📦 Current npm version: ${npmInfo.latestVersion}`);
    }

    // Step 2: Fetch all vulnerabilities for the package
    console.log(`[${new Date().toISOString()}] 🔐 Fetching all OSV vulnerabilities...`);
    const rawVulns = await fetchAllPackageVulnerabilities(packageName);
    console.log(`[${new Date().toISOString()}] 📊 Found ${rawVulns.length} total vulnerabilities in OSV`);

    // Step 3: Process vulnerabilities
    const allVulnerabilities = rawVulns.map(processVulnerability);

    // Step 4: Find new vulnerabilities (not in our known set)
    const newVulnerabilities = allVulnerabilities.filter(v => !knownOsvIds.has(v.osvId));

    if (newVulnerabilities.length > 0) {
      console.log(`[${new Date().toISOString()}] ⚠️ Found ${newVulnerabilities.length} NEW vulnerabilities!`);
      for (const v of newVulnerabilities) {
        console.log(`[${new Date().toISOString()}]    - ${v.osvId} (${v.severity}): ${v.summary?.substring(0, 80) || 'No summary'}`);
      }
    } else {
      console.log(`[${new Date().toISOString()}] ✅ No new vulnerabilities found`);
    }

    // Step 5: If there's a new version, also check version-specific vulnerabilities
    if (isNewVersion && npmInfo.latestVersion) {
      console.log(`[${new Date().toISOString()}] 🔍 Checking vulnerabilities for new version ${npmInfo.latestVersion}...`);
      const versionVulns = await fetchVersionVulnerabilities(packageName, npmInfo.latestVersion);
      
      if (versionVulns.length > 0) {
        console.log(`[${new Date().toISOString()}] ⚠️ New version ${npmInfo.latestVersion} has ${versionVulns.length} known vulnerabilities`);
      } else {
        console.log(`[${new Date().toISOString()}] ✅ New version ${npmInfo.latestVersion} has no known vulnerabilities`);
      }
    }

    return {
      newVulnerabilities,
      allVulnerabilities,
      latestNpmVersion: npmInfo.latestVersion,
      isNewVersion,
    };
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ OSV check failed for ${packageName}:`, error.message);
    return {
      newVulnerabilities: [],
      allVulnerabilities: [],
      latestNpmVersion: null,
      isNewVersion: false,
      error: error.message,
    };
  }
}
