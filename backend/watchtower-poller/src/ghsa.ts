/**
 * GHSA (GitHub Security Advisories) for Watchtower Poller.
 * Single source for vulnerability data (no OSV). Same data as npm audit.
 */

const token = (process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_PAT || '').trim();

export interface GhsaVuln {
  ghsaId: string;
  summary: string | null;
  description: string | null;
  severity: string | null;
  vulnerableVersionRange: string;
  firstPatchedVersion: string | null;
  publishedAt: string | null;
  updatedAt: string | null;
  identifiers: Array<{ type: string; value: string }>;
}

const MAX_PER_QUERY = 100;
const FIRST_PER_PACKAGE = 30;

/**
 * Fetch vulnerabilities for up to 100 npm package names in one GraphQL request.
 */
export async function fetchGhsaVulnerabilitiesBatch(packageNames: string[]): Promise<Map<string, GhsaVuln[]>> {
  const result = new Map<string, GhsaVuln[]>();
  if (packageNames.length === 0) return result;
  const names = packageNames.slice(0, MAX_PER_QUERY);

  const query = `query { ${names
    .map(
      (name, i) =>
        `p${i}: securityVulnerabilities(package: ${JSON.stringify(name)}, ecosystem: NPM, first: ${FIRST_PER_PACKAGE}) { nodes { advisory { ghsaId summary description severity publishedAt updatedAt identifiers { type value } } vulnerableVersionRange firstPatchedVersion { identifier } } }`
    )
    .join(' ')} }`;

  try {
    if (!token) {
      console.warn('[GHSA] No GitHub token. Set GITHUB_TOKEN, GH_TOKEN, or GITHUB_PAT for vulnerability sync.');
    }
    const res = await fetch('https://api.github.com/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Deptex-Watchtower-Poller',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ query }),
    });
    if (!res.ok) {
      console.warn('[GHSA] GraphQL request failed:', res.status, await res.text());
      return result;
    }
    const json = await res.json();
    if (json.errors) {
      console.warn('[GHSA] GraphQL errors:', JSON.stringify(json.errors));
      return result;
    }
    const data = json.data as Record<
      string,
      {
        nodes: Array<{
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
        }>;
      }
    >;
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

function ghsaSeverityToLevel(severity: string | null): string {
  if (!severity) return 'medium';
  const s = severity.toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'high';
  if (s === 'MODERATE' || s === 'MEDIUM') return 'medium';
  if (s === 'LOW') return 'low';
  return 'medium';
}

/** Row shape for dependency_vulnerabilities upsert (osv_id stores GHSA id). */
export interface GhsaVulnInsert {
  dependency_id: string;
  osv_id: string;
  severity: string;
  summary: string | null;
  details: string | null;
  aliases: string[];
  affected_versions: unknown;
  fixed_versions: string[];
  published_at: string | null;
  modified_at: string | null;
}

export function ghsaVulnToInsert(dependencyId: string, v: GhsaVuln): GhsaVulnInsert {
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
    details: v.description?.substring(0, 10000) ?? null,
    aliases,
    affected_versions: affectedVersions,
    fixed_versions: fixedVersions,
    published_at: v.publishedAt ?? null,
    modified_at: v.updatedAt ?? null,
  };
}
