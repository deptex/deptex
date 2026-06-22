/**
 * Read-only probe for the finding -> tracker integration against REAL infra.
 *
 * Proves the part the unit/PGLite suite can't: that an org's stored Jira/Linear
 * credentials actually authenticate against the live Atlassian / Linear APIs and
 * that destination listing works. It NEVER creates a ticket — it only reads
 * connected providers + lists Jira projects / Linear teams, so it's safe to run
 * against production with zero side effects.
 *
 *   npm run tracker:probe -- <organizationId> [projectId]
 *
 * Requires the org to have Jira and/or Linear connected via Organization
 * Settings > Integrations (organization_integrations rows). GitHub availability
 * additionally needs a project with a connected repo, hence the optional
 * projectId.
 */
import 'dotenv/config';
import { getConnectedProviders, listJiraProjects, listLinearTeams } from '../src/lib/trackers';

async function main() {
  const orgId = process.argv[2];
  const projectId = process.argv[3] ?? '00000000-0000-0000-0000-000000000000';
  if (!orgId) {
    console.error('Usage: npm run tracker:probe -- <organizationId> [projectId]');
    process.exit(1);
  }

  console.log(`Probing tracker integrations for org ${orgId} (project ${projectId})…\n`);

  const providers = await getConnectedProviders(orgId, projectId);
  console.log('Connected providers:', providers.length ? providers.join(', ') : '(none)');

  if (providers.includes('jira')) {
    try {
      const projects = await listJiraProjects(orgId);
      console.log(`\nJira projects (${projects.length}):`);
      for (const p of projects.slice(0, 25)) console.log(`  ${p.key}  ${p.name}`);
      if (projects.length > 25) console.log(`  …and ${projects.length - 25} more`);
    } catch (e: any) {
      console.error('Jira project list FAILED:', e.message);
    }
  }

  if (providers.includes('linear')) {
    try {
      const teams = await listLinearTeams(orgId);
      console.log(`\nLinear teams (${teams.length}):`);
      for (const t of teams.slice(0, 25)) console.log(`  ${t.id}  ${t.name}`);
      if (teams.length > 25) console.log(`  …and ${teams.length - 25} more`);
    } catch (e: any) {
      console.error('Linear team list FAILED:', e.message);
    }
  }

  if (providers.includes('github')) {
    console.log('\nGitHub: org App installed + project repo connected (issues will file to the project repo).');
  }

  console.log('\nProbe complete (read-only — no tickets created).');
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});
