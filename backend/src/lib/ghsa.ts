import semver from 'semver';

// ============================================================================
// GHSA (GitHub Security Advisories) – shared module
// Extracted from workers.ts so both workers and projects routes can use these.
// ============================================================================

/** GitHub token for GraphQL (optional). Unauthenticated = 60 req/h; with token = 5000 points/h. */
export function getGitHubToken(): string {
  const t = (process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_PAT || '').trim();
  return t;
}

/** One vulnerability from GitHub Advisory GraphQL (securityVulnerabilities.nodes). */
export interface GhsaVuln {
  ghsaId: string;
  summary: string | null;
  description: string | null;
  severity: string | null; // CRITICAL, HIGH, MODERATE, LOW
  vulnerableVersionRange: string;
  firstPatchedVersion: string | null;
  publishedAt: string | null;
  updatedAt: string | null;
  identifiers: Array<{ type: string; value: string }>;
}

/** Map our ecosystem ids to GHSA GraphQL SecurityAdvisoryEcosystem enum values. */
const ECOSYSTEM_TO_GHSA: Record<string, string> = {
  npm: 'NPM',
  pypi: 'PIP',
  maven: 'MAVEN',
  nuget: 'NUGET',
  golang: 'GO',
  cargo: 'RUST',
  gem: 'RUBYGEMS',
  composer: 'COMPOSER',
  pub: 'PUB',
  hex: 'ERLANG',
  swift: 'SWIFT',
};

/**
 * Fetch vulnerabilities for multiple packages in one GraphQL request (up to 100).
 * Uses GitHub Advisory Database (GHSA).
 * Rate limits: unauthenticated 60/h; with GITHUB_TOKEN 5000 points/h.
 */
export async function fetchGhsaVulnerabilitiesBatch(packageNames: string[], ecosystem?: string): Promise<Map<string, GhsaVuln[]>> {
  const result = new Map<string, GhsaVuln[]>();
  if (packageNames.length === 0) return result;
  const maxPerQuery = 100;
  const firstPerPackage = 30;
  const names = packageNames.slice(0, maxPerQuery);
  const ghsaEcosystem = ECOSYSTEM_TO_GHSA[ecosystem ?? 'npm'] ?? 'NPM';

  const buildQuery = (): string => {
    const parts = names.map((name, i) => {
      const escaped = JSON.stringify(name);
      return `p${i}: securityVulnerabilities(package: ${escaped}, ecosystem: ${ghsaEcosystem}, first: ${firstPerPackage}) { nodes { advisory { ghsaId summary description severity publishedAt updatedAt identifiers { type value } } vulnerableVersionRange firstPatchedVersion { identifier } } }`;
    });
    return `query { ${parts.join(' ')} }`;
  };

  try {
    const token = getGitHubToken();
    if (!token) {
      console.warn('[GHSA] No GitHub token (GITHUB_TOKEN, GH_TOKEN, or GITHUB_PAT). Set one in .env and restart to avoid rate limits.');
    }
    const res = await fetch('https://api.github.com/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Deptex-App',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ query: buildQuery() }),
    });
    if (!res.ok) {
      console.warn('[GHSA] GraphQL request failed:', res.status, await res.text());
      return result;
    }
    const json = (await res.json()) as { errors?: unknown; data?: Record<string, { nodes: Array<{
      advisory: { ghsaId: string; summary: string | null; description: string | null; severity: string | null; publishedAt: string | null; updatedAt: string | null; identifiers: Array<{ type: string; value: string }> };
      vulnerableVersionRange: string;
      firstPatchedVersion: { identifier: string } | null;
    }> }> };
    if (json.errors) {
      console.warn('[GHSA] GraphQL errors:', JSON.stringify(json.errors));
      return result;
    }
    const data = json.data as Record<string, { nodes: Array<{
      advisory: {
        ghsaId: string;
        summary: string | null;
        description: string | null;
        severity: string | null;
        publishedAt: string | null;
        updatedAt: string | null;
        identifiers: Array<{ type: string; value: string }>;
      };
      vulnerableVersionRange: string;
      firstPatchedVersion: { identifier: string } | null;
    }> }>;
    for (let i = 0; i < names.length; i++) {
      const nodes = data[`p${i}`]?.nodes ?? [];
      const vulns: GhsaVuln[] = nodes.map((n) => ({
        ghsaId: n.advisory.ghsaId,
        summary: n.advisory.summary ?? null,
        description: n.advisory.description ?? null,
        severity: n.advisory.severity ?? null,
        vulnerableVersionRange: n.vulnerableVersionRange || '',
        firstPatchedVersion: n.firstPatchedVersion?.identifier ?? null,
        publishedAt: n.advisory.publishedAt ?? null,
        updatedAt: n.advisory.updatedAt ?? null,
        identifiers: n.advisory.identifiers ?? [],
      }));
      result.set(names[i], vulns);
    }
  } catch (e) {
    console.warn('[GHSA] fetch failed:', (e as Error).message);
  }
  return result;
}

/** Filter GHSA vulns to those affecting the given version; normalize severity to critical|high|medium|low. */
export function filterGhsaVulnsByVersion(vulns: GhsaVuln[], version: string): GhsaVuln[] {
  const v = semver.valid(semver.coerce(version));
  if (!v) return [];
  return vulns.filter((u) => {
    const range = (u.vulnerableVersionRange || '').replace(/\s+/g, ' ').trim();
    if (!range) return false;
    try {
      return semver.satisfies(v, range);
    } catch {
      return false;
    }
  });
}

/** Map GHSA severity to our critical|high|medium|low. */
export function ghsaSeverityToLevel(severity: string | null): string {
  if (!severity) return 'medium';
  const s = severity.toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'high';
  if (s === 'MODERATE' || s === 'MEDIUM') return 'medium';
  if (s === 'LOW') return 'low';
  return 'medium';
}

/** Convert GHSA vuln to dependency_vulnerabilities row shape (osv_id stores GHSA id). */
export function ghsaVulnToRow(dependencyId: string, v: GhsaVuln): Record<string, unknown> {
  const fixedVersions = v.firstPatchedVersion ? [v.firstPatchedVersion] : [];
  const affectedVersions = v.firstPatchedVersion
    ? [{ ranges: [{ events: [{ introduced: '0.0.0', fixed: v.firstPatchedVersion }] }] }]
    : null;
  const aliases = (v.identifiers || []).filter((i) => i.type === 'CVE').map((i) => i.value);
  return {
    dependency_id: dependencyId,
    osv_id: v.ghsaId,
    severity: ghsaSeverityToLevel(v.severity),
    summary: v.summary || null,
    details: v.description || null,
    aliases,
    affected_versions: affectedVersions,
    fixed_versions: fixedVersions,
    published_at: v.publishedAt || null,
    modified_at: v.updatedAt || null,
  };
}
