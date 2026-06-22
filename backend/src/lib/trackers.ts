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
import { createInstallationToken, createIssue as createGithubIssueApi } from './github';

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

interface JiraToken {
  accessToken: string;
  base: string;
  cloud: boolean;
  cloudId?: string;
  metadata: Record<string, any>;
}

/**
 * Get a usable Jira access token for an org. Atlassian 3LO access tokens expire
 * after ~1 hour, so every Jira call must mint a fresh one from the stored
 * refresh token (and persist the rotated refresh token, or we lock ourselves
 * out). NOTE: concurrent callers can race on the rotated refresh token; the
 * picker -> create flow is sequential, so this is acceptable for now.
 */
async function getValidJiraToken(organizationId: string): Promise<JiraToken> {
  const { data: conn } = await supabase
    .from('organization_integrations')
    .select('refresh_token, metadata')
    .eq('organization_id', organizationId)
    .eq('provider', 'jira')
    .maybeSingle();
  if (!conn?.refresh_token) {
    throw new TrackerError('Jira is not connected. Connect it under Organization Settings > Integrations.', false);
  }
  const res = await fetch('https://auth.atlassian.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'refresh_token',
      client_id: process.env.JIRA_CLIENT_ID,
      client_secret: process.env.JIRA_CLIENT_SECRET,
      refresh_token: conn.refresh_token,
    }),
  });
  const data = (await res.json().catch(() => ({}))) as any;
  if (!data.access_token) {
    throw new TrackerError('Could not refresh the Jira token — reconnect Jira.', true);
  }
  await supabase
    .from('organization_integrations')
    .update({
      access_token: data.access_token,
      refresh_token: data.refresh_token ?? conn.refresh_token,
      updated_at: new Date().toISOString(),
    })
    .eq('organization_id', organizationId)
    .eq('provider', 'jira');
  const metadata = (conn.metadata ?? {}) as Record<string, any>;
  const { base, cloud } = jiraBaseUrl(metadata);
  return { accessToken: data.access_token, base, cloud, cloudId: metadata.cloud_id, metadata };
}

export async function listJiraProjects(
  organizationId: string,
): Promise<Array<{ key: string; name: string }>> {
  const { accessToken, base, cloud } = await getValidJiraToken(organizationId);
  const url = cloud
    ? `${base}/rest/api/3/project/search?maxResults=100`
    : `${base}/rest/api/2/project`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
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
  const { accessToken, base, cloud, metadata } = await getValidJiraToken(organizationId);
  const projectKey = params.projectKey || metadata.project_key;
  if (!projectKey) {
    throw new TrackerError('No Jira project selected. Pick a Jira project to file into.', true);
  }
  const issueType = params.issueType ?? metadata.issue_type ?? 'Task';

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
      Authorization: `Bearer ${accessToken}`,
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
  const siteUrl: string | undefined = metadata.site_url || metadata.url;
  const browseUrl = siteUrl ? `${String(siteUrl).replace(/\/+$/, '')}/browse/${data.key}` : null;
  return { provider: 'jira', externalId: String(data.id ?? data.key), externalKey: data.key, externalUrl: browseUrl };
}

/**
 * Register a dynamic Jira webhook for an org (jira:issue_updated) so issue status
 * changes update the chip in real time. Atlassian doesn't HMAC-sign these, so the
 * callback URL carries a shared secret we verify. The webhook expires after 30
 * days — refreshAllJiraWebhooks (daily cron) keeps it alive. Best-effort: a
 * failure here must not break the Jira connect.
 */
export async function registerJiraWebhook(organizationId: string): Promise<void> {
  const secret = process.env.JIRA_WEBHOOK_SECRET;
  if (!secret) return; // not configured — webhooks off, nothing to do
  let tok: JiraToken;
  try {
    tok = await getValidJiraToken(organizationId);
  } catch {
    return;
  }
  if (!tok.cloudId) return;
  const backendUrl = (process.env.BACKEND_URL || process.env.API_BASE_URL || 'http://localhost:3001').replace(/\/$/, '');
  const callbackUrl = `${backendUrl}/api/integrations/webhooks/jira/${organizationId}?token=${encodeURIComponent(secret)}`;
  const res = await fetch(`https://api.atlassian.com/ex/jira/${tok.cloudId}/rest/api/3/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tok.accessToken}`, Accept: 'application/json' },
    body: JSON.stringify({ url: callbackUrl, webhooks: [{ events: ['jira:issue_updated'], jqlFilter: 'project IS NOT EMPTY' }] }),
  });
  const data = (await res.json().catch(() => ({}))) as any;
  const webhookId = data?.webhookRegistrationResult?.[0]?.createdWebhookId;
  if (webhookId != null) {
    await supabase
      .from('organization_integrations')
      .update({ metadata: { ...tok.metadata, webhook_id: webhookId }, updated_at: new Date().toISOString() })
      .eq('organization_id', organizationId)
      .eq('provider', 'jira');
  }
}

/**
 * Refresh every org's Jira dynamic webhook (they expire after 30 days). Run from
 * the daily cron — daily re-up is well within the window. Returns how many were
 * refreshed.
 */
export async function refreshAllJiraWebhooks(): Promise<{ refreshed: number; total: number }> {
  const { data: rows } = await supabase
    .from('organization_integrations')
    .select('organization_id, metadata')
    .eq('provider', 'jira');
  let refreshed = 0;
  let total = 0;
  for (const row of rows ?? []) {
    const meta = (row.metadata ?? {}) as Record<string, any>;
    const webhookId = meta.webhook_id;
    if (webhookId == null) continue;
    total++;
    try {
      const tok = await getValidJiraToken(row.organization_id);
      if (!tok.cloudId) continue;
      const res = await fetch(`https://api.atlassian.com/ex/jira/${tok.cloudId}/rest/api/3/webhook/refresh`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tok.accessToken}`, Accept: 'application/json' },
        body: JSON.stringify({ webhookIds: [webhookId] }),
      });
      if (res.ok) refreshed++;
    } catch {
      // skip — next daily run retries
    }
  }
  return { refreshed, total };
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

// Tracker-link state is kept fresh by provider webhooks (see the handlers in
// routes/integrations.ts). The on-load poll was removed in favor of webhooks.
