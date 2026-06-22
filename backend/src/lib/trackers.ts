/**
 * External issue-tracker helpers for the finding -> ticket flow.
 *
 * Credentials are ORG-SCOPED: Jira and Linear are read from
 * `organization_integrations` (the same rows the org-settings Integrations tab
 * connects via /jira/install + /linear/install), and GitHub uses the org's App
 * installation + the project's connected repo. Destination selection
 * (Jira project / issue type, Linear team) happens at ticket-creation time
 * because the connect flow doesn't capture it — these helpers expose the
 * list endpoints the picker needs.
 *
 * The REST bodies mirror the Aegis tool closures in lib/aegis/tools/external.ts;
 * those tools now delegate here so there is one implementation.
 */

import { supabase } from './supabase';
import { createInstallationToken, createIssue as createGithubIssueApi, getIssue as getGithubIssueApi } from './github';

export type TrackerProvider = 'jira' | 'linear' | 'github';

export interface TrackerResult {
  provider: TrackerProvider;
  externalId: string;
  externalKey: string | null;
  externalUrl: string | null;
}

export class TrackerError extends Error {
  constructor(message: string, readonly connected: boolean = true) {
    super(message);
    this.name = 'TrackerError';
  }
}

// ---------------------------------------------------------------------------
// Connection lookups
// ---------------------------------------------------------------------------

async function getOrgIntegration(
  organizationId: string,
  provider: 'jira' | 'linear',
): Promise<{ access_token: string; metadata: Record<string, any> }> {
  const { data, error } = await supabase
    .from('organization_integrations')
    .select('access_token, metadata, status')
    .eq('organization_id', organizationId)
    .eq('provider', provider)
    .maybeSingle();
  if (error) throw new TrackerError(error.message);
  if (!data?.access_token) {
    throw new TrackerError(
      `${provider} is not connected. Connect it under Organization Settings > Integrations.`,
      false,
    );
  }
  return { access_token: data.access_token, metadata: (data.metadata ?? {}) as Record<string, any> };
}

/** Resolve the project's connected GitHub repo + the org App installation. */
async function getGithubTarget(
  projectId: string,
): Promise<{ installationId: string; repoFullName: string }> {
  const { data: repo } = await supabase
    .from('project_repositories')
    .select('repo_full_name, provider')
    .eq('project_id', projectId)
    .eq('provider', 'github')
    .maybeSingle();
  if (!repo?.repo_full_name) {
    throw new TrackerError('This project has no connected GitHub repository.', false);
  }
  const { data: project } = await supabase
    .from('projects')
    .select('organization_id')
    .eq('id', projectId)
    .maybeSingle();
  if (!project) throw new TrackerError('Project not found.', false);
  const { data: org } = await supabase
    .from('organizations')
    .select('github_installation_id')
    .eq('id', project.organization_id)
    .maybeSingle();
  if (!org?.github_installation_id) {
    throw new TrackerError('GitHub App is not installed for this organization.', false);
  }
  return { installationId: String(org.github_installation_id), repoFullName: repo.repo_full_name };
}

/** Which tracker providers can this org/project file to right now. */
export async function getConnectedProviders(
  organizationId: string,
  projectId: string,
): Promise<TrackerProvider[]> {
  const out: TrackerProvider[] = [];

  const { data: orgInts } = await supabase
    .from('organization_integrations')
    .select('provider')
    .eq('organization_id', organizationId)
    .in('provider', ['jira', 'linear']);
  const connected = new Set((orgInts ?? []).map((r: any) => r.provider));
  if (connected.has('jira')) out.push('jira');
  if (connected.has('linear')) out.push('linear');

  const { data: repo } = await supabase
    .from('project_repositories')
    .select('repo_full_name')
    .eq('project_id', projectId)
    .eq('provider', 'github')
    .maybeSingle();
  if (repo?.repo_full_name) {
    const { data: project } = await supabase
      .from('projects')
      .select('organization_id')
      .eq('id', projectId)
      .maybeSingle();
    if (project) {
      const { data: org } = await supabase
        .from('organizations')
        .select('github_installation_id')
        .eq('id', project.organization_id)
        .maybeSingle();
      if (org?.github_installation_id) out.push('github');
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Jira
// ---------------------------------------------------------------------------

function jiraBaseUrl(meta: Record<string, any>): { base: string; cloud: boolean } {
  const cloudId = meta.cloud_id;
  if (cloudId) return { base: `https://api.atlassian.com/ex/jira/${cloudId}`, cloud: true };
  if (meta.base_url) return { base: String(meta.base_url).replace(/\/+$/, ''), cloud: false };
  throw new TrackerError('Jira integration is missing cloud_id / base_url. Reconnect Jira.', true);
}

export async function listJiraProjects(
  organizationId: string,
): Promise<Array<{ key: string; name: string }>> {
  const conn = await getOrgIntegration(organizationId, 'jira');
  const { base, cloud } = jiraBaseUrl(conn.metadata);
  const url = cloud
    ? `${base}/rest/api/3/project/search?maxResults=100`
    : `${base}/rest/api/2/project`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${conn.access_token}`, Accept: 'application/json' },
  });
  if (!res.ok) throw new TrackerError(`Jira project list failed (${res.status}).`);
  const data = (await res.json()) as any;
  const values = Array.isArray(data) ? data : data.values ?? [];
  return values.map((p: any) => ({ key: p.key, name: p.name })).filter((p: any) => p.key);
}

export async function createJiraIssue(
  organizationId: string,
  params: { projectKey?: string; summary: string; description: string; issueType?: string },
): Promise<TrackerResult> {
  const conn = await getOrgIntegration(organizationId, 'jira');
  const { base, cloud } = jiraBaseUrl(conn.metadata);
  const projectKey = params.projectKey || conn.metadata.project_key;
  if (!projectKey) {
    throw new TrackerError('No Jira project selected. Pick a Jira project to file into.', true);
  }
  const issueType = params.issueType ?? conn.metadata.issue_type ?? 'Task';

  const body = cloud
    ? {
        fields: {
          project: { key: projectKey },
          summary: params.summary,
          description: {
            type: 'doc',
            version: 1,
            content: [{ type: 'paragraph', content: [{ type: 'text', text: params.description }] }],
          },
          issuetype: { name: issueType },
        },
      }
    : {
        fields: {
          project: { key: projectKey },
          summary: params.summary,
          description: params.description,
          issuetype: { name: issueType },
        },
      };
  const apiPath = cloud ? '/rest/api/3/issue' : '/rest/api/2/issue';
  const res = await fetch(`${base}${apiPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${conn.access_token}`,
    },
    body: JSON.stringify(body),
  });
  const data = (await res.json().catch(() => ({}))) as any;
  if (!res.ok || !data.key) {
    const msg = data.errors
      ? JSON.stringify(data.errors)
      : data.errorMessages?.join(', ') ?? `Jira API error (${res.status})`;
    throw new TrackerError(msg);
  }
  const siteUrl: string | undefined = conn.metadata.site_url || conn.metadata.url;
  const browseUrl = siteUrl ? `${String(siteUrl).replace(/\/+$/, '')}/browse/${data.key}` : null;
  return { provider: 'jira', externalId: String(data.id ?? data.key), externalKey: data.key, externalUrl: browseUrl };
}

// ---------------------------------------------------------------------------
// Linear
// ---------------------------------------------------------------------------

function linearAuthHeader(token: string): string {
  // Personal API keys are sent raw; OAuth access tokens need the Bearer prefix.
  return token.startsWith('lin_api_') ? token : `Bearer ${token}`;
}

async function linearGraphQL(token: string, query: string, variables: Record<string, any>): Promise<any> {
  const res = await fetch('https://api.linear.app/graphql', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: linearAuthHeader(token) },
    body: JSON.stringify({ query, variables }),
  });
  const data = (await res.json().catch(() => ({}))) as any;
  if (data.errors?.length) throw new TrackerError(data.errors[0].message ?? 'Linear API error');
  return data.data;
}

export async function listLinearTeams(
  organizationId: string,
): Promise<Array<{ id: string; name: string }>> {
  const conn = await getOrgIntegration(organizationId, 'linear');
  const data = await linearGraphQL(conn.access_token, `{ teams { nodes { id name key } } }`, {});
  return (data?.teams?.nodes ?? []).map((t: any) => ({ id: t.id, name: t.key ? `${t.name} (${t.key})` : t.name }));
}

export async function createLinearIssue(
  organizationId: string,
  params: { teamId?: string; title: string; description: string },
): Promise<TrackerResult> {
  const conn = await getOrgIntegration(organizationId, 'linear');
  const teamId = params.teamId || conn.metadata.team_id;
  if (!teamId) {
    throw new TrackerError('No Linear team selected. Pick a Linear team to file into.', true);
  }
  const mutation = `
    mutation CreateIssue($input: IssueCreateInput!) {
      issueCreate(input: $input) { success issue { id identifier url } }
    }
  `;
  const data = await linearGraphQL(conn.access_token, mutation, {
    input: { teamId, title: params.title, description: params.description },
  });
  const created = data?.issueCreate;
  if (!created?.success || !created.issue) {
    throw new TrackerError('Linear issueCreate returned success=false');
  }
  return {
    provider: 'linear',
    externalId: created.issue.id,
    externalKey: created.issue.identifier ?? null,
    externalUrl: created.issue.url ?? null,
  };
}

// ---------------------------------------------------------------------------
// GitHub
// ---------------------------------------------------------------------------

export async function createGithubIssue(
  projectId: string,
  params: { title: string; body: string; labels?: string[] },
): Promise<TrackerResult> {
  const { installationId, repoFullName } = await getGithubTarget(projectId);
  const token = await createInstallationToken(installationId);
  const issue = await createGithubIssueApi(token, repoFullName, params);
  return {
    provider: 'github',
    externalId: String(issue.number),
    externalKey: `#${issue.number}`,
    externalUrl: issue.html_url,
  };
}

// ---------------------------------------------------------------------------
// State sync (poll)
// ---------------------------------------------------------------------------

/**
 * Refresh the open/done state of an org's GitHub tracker links by polling the
 * GitHub API. This is the universal path that works without webhooks (local dev,
 * pre-deploy); the issues webhook is the prod real-time optimization on top.
 * Linear/Jira polling is a follow-on. Returns the number of links whose state
 * changed.
 */
export async function syncOrgGithubLinkStates(organizationId: string): Promise<number> {
  const { data: links } = await supabase
    .from('finding_tracker_links')
    .select('id, project_id, external_id, external_state')
    .eq('organization_id', organizationId)
    .eq('provider', 'github');
  if (!links?.length) return 0;

  // Resolve the repo + installation token once per project.
  const byProject = new Map<string, Array<{ id: string; external_id: string; external_state: string | null }>>();
  for (const l of links as any[]) {
    const arr = byProject.get(l.project_id) ?? [];
    arr.push({ id: l.id, external_id: l.external_id, external_state: l.external_state });
    byProject.set(l.project_id, arr);
  }

  let changed = 0;
  for (const [projectId, projLinks] of byProject) {
    let target: { installationId: string; repoFullName: string };
    try {
      target = await getGithubTarget(projectId);
    } catch {
      continue; // repo disconnected — leave the links as-is
    }
    let token: string;
    try {
      token = await createInstallationToken(target.installationId);
    } catch {
      continue;
    }
    for (const l of projLinks) {
      try {
        const issue = await getGithubIssueApi(token, target.repoFullName, Number(l.external_id));
        const newState = issue.state === 'closed' ? 'done' : 'open';
        if (newState !== l.external_state) {
          await supabase
            .from('finding_tracker_links')
            .update({ external_state: newState, external_state_synced_at: new Date().toISOString() })
            .eq('id', l.id);
          changed++;
        }
      } catch {
        // A single issue fetch failing shouldn't abort the rest.
      }
    }
  }
  return changed;
}
