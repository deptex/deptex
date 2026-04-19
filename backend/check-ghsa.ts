/**
 * One-off: simulate the exact GHSA GraphQL call used by populate-dependencies
 * to see what GitHub returns for "react" vs "lodash".
 * Run from backend: npx tsx check-ghsa.ts
 */
import 'dotenv/config';

const firstPerPackage = 30;

function buildQuery(packageNames: string[]): string {
  const parts = packageNames.map((name, i) => {
    const escaped = JSON.stringify(name);
    return `p${i}: securityVulnerabilities(package: ${escaped}, ecosystem: NPM, first: ${firstPerPackage}) { nodes { advisory { ghsaId summary severity publishedAt identifiers { type value } } vulnerableVersionRange firstPatchedVersion { identifier } } }`;
  });
  return `query { ${parts.join(' ')} }`;
}

async function main() {
  const token =
    (process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_PAT || '').trim();
  if (!token) {
    console.error('No GITHUB_TOKEN / GH_TOKEN / GITHUB_PAT in env. Add to .env and re-run.');
    process.exit(1);
  }

  const packageNames = ['react', 'lodash'];
  const query = buildQuery(packageNames);

  console.log('Query (same as ghsa.ts fetchGhsaVulnerabilitiesBatch):');
  console.log(query);
  console.log('\n--- Calling https://api.github.com/graphql ---\n');

  const res = await fetch('https://api.github.com/graphql', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'Deptex-App',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ query }),
  });

  const text = await res.text();
  if (!res.ok) {
    console.error('HTTP', res.status, text);
    process.exit(1);
  }

  const json = JSON.parse(text);
  if (json.errors) {
    console.error('GraphQL errors:', JSON.stringify(json.errors, null, 2));
    process.exit(1);
  }

  const data = json.data as Record<
    string,
    { nodes: Array<{
      advisory: { ghsaId: string; summary: string | null; severity: string | null; publishedAt: string | null; identifiers: Array<{ type: string; value: string }> };
      vulnerableVersionRange: string;
      firstPatchedVersion: { identifier: string } | null;
    }> }
  >;

  for (let i = 0; i < packageNames.length; i++) {
    const name = packageNames[i];
    const nodes = data[`p${i}`]?.nodes ?? [];
    console.log(`${name}: ${nodes.length} vulnerability/ies from GHSA`);
    nodes.slice(0, 5).forEach((n, j) => {
      console.log(`  ${j + 1}. ${n.advisory.ghsaId} [${n.advisory.severity ?? '?'}] ${n.vulnerableVersionRange} -> ${n.firstPatchedVersion?.identifier ?? 'none'}`);
      console.log(`     ${(n.advisory.summary || '').slice(0, 80)}...`);
    });
    if (nodes.length > 5) console.log(`  ... and ${nodes.length - 5} more`);
    console.log('');
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
