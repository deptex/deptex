import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../../../backend/src/lib/supabase';
import { sendEmail } from '../../email';
import { createInstallationToken } from '../../github';
import { createIssueComment } from '../../github';

registerAegisTool(
  'sendSlackMessage',
  { category: 'external', permissionLevel: 'moderate', requiredRbacPermissions: ['manage_integrations'] },
  tool({
    description: 'Send a message to a Slack channel. Requires Slack integration to be connected.',
    inputSchema: z.object({
      organizationId: z.string().uuid(),
      channel: z.string(),
      message: z.string(),
    }),
    execute: async ({ organizationId, channel, message }) => {
      const { data: conn, error } = await supabase
        .from('organization_integrations')
        .select('access_token')
        .eq('organization_id', organizationId)
        .eq('provider', 'slack')
        .single();
      if (error || !conn?.access_token) {
        return JSON.stringify({
          error: 'Slack is not connected. Go to Organization Settings > Integrations to connect Slack.',
          connected: false,
        });
      }
      try {
        const res = await fetch('https://slack.com/api/chat.postMessage', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${conn.access_token}` },
          body: JSON.stringify({ channel, text: message }),
        });
        const data = (await res.json()) as { ok?: boolean; error?: string };
        if (!data.ok) {
          return JSON.stringify({ error: data.error ?? 'Slack API error', success: false });
        }
        return JSON.stringify({ success: true, channel });
      } catch (err: any) {
        return JSON.stringify({ error: err.message, success: false });
      }
    },
  })
);

registerAegisTool(
  'sendEmail',
  { category: 'external', permissionLevel: 'moderate', requiredRbacPermissions: ['manage_integrations'] },
  tool({
    description: 'Send an email via the configured nodemailer/SMTP.',
    inputSchema: z.object({
      to: z.string().email(),
      subject: z.string(),
      body: z.string(),
    }),
    execute: async ({ to, subject, body }) => {
      const result = await sendEmail({ to, subject, text: body });
      if (!result.sent) {
        return JSON.stringify({ error: result.error ?? 'Email send failed', success: false });
      }
      return JSON.stringify({ success: true, messageId: result.messageId });
    },
  })
);

registerAegisTool(
  'createJiraTicket',
  { category: 'external', permissionLevel: 'moderate', requiredRbacPermissions: ['manage_integrations'] },
  tool({
    description: 'Create a Jira ticket. Requires Jira integration to be connected.',
    inputSchema: z.object({
      organizationId: z.string().uuid(),
      summary: z.string(),
      description: z.string(),
      issueType: z.string().optional(),
    }),
    execute: async ({ organizationId, summary, description, issueType }) => {
      const { data: conn, error } = await supabase
        .from('organization_integrations')
        .select('access_token, metadata')
        .eq('organization_id', organizationId)
        .eq('provider', 'jira')
        .single();
      if (error || !conn?.access_token) {
        return JSON.stringify({
          error: 'Jira is not connected. Go to Organization Settings > Integrations to connect Jira.',
          connected: false,
        });
      }
      const meta = (conn.metadata ?? {}) as Record<string, any>;
      const projectKey = meta.project_key;
      const cloudId = meta.cloud_id;
      const baseUrl = cloudId ? `https://api.atlassian.com/ex/jira/${cloudId}` : meta.base_url;
      if (!baseUrl || !projectKey) {
        return JSON.stringify({
          error: 'Jira integration is missing project_key or cloud_id. Configure in Integration settings.',
          connected: true,
        });
      }
      try {
        const body = {
          fields: {
            project: { key: projectKey },
            summary,
            description: { type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text: description }] }] },
            issuetype: { name: issueType ?? meta.issue_type ?? 'Task' },
          },
        };
        const res = await fetch(`${baseUrl}/rest/api/3/issue`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${conn.access_token}` },
          body: JSON.stringify(body),
        });
        const data = (await res.json()) as { key?: string; errors?: Record<string, string> };
        if (!res.ok) {
          const errMsg = data.errors ? JSON.stringify(data.errors) : (data as any).errorMessages?.join(', ') ?? 'Jira API error';
          return JSON.stringify({ error: errMsg, success: false });
        }
        return JSON.stringify({ success: true, issueKey: data.key });
      } catch (err: any) {
        return JSON.stringify({ error: err.message, success: false });
      }
    },
  })
);

registerAegisTool(
  'createLinearTicket',
  { category: 'external', permissionLevel: 'moderate', requiredRbacPermissions: ['manage_integrations'] },
  tool({
    description: 'Create a Linear issue. Requires Linear integration to be connected.',
    inputSchema: z.object({
      organizationId: z.string().uuid(),
      title: z.string(),
      description: z.string(),
    }),
    execute: async ({ organizationId, title, description }) => {
      const { data: conn, error } = await supabase
        .from('organization_integrations')
        .select('access_token, metadata')
        .eq('organization_id', organizationId)
        .eq('provider', 'linear')
        .single();
      if (error || !conn?.access_token) {
        return JSON.stringify({
          error: 'Linear is not connected. Go to Organization Settings > Integrations to connect Linear (API key).',
          connected: false,
        });
      }
      const meta = (conn.metadata ?? {}) as Record<string, any>;
      const teamId = meta.team_id;
      if (!teamId) {
        return JSON.stringify({
          error: 'Linear integration is missing team_id. Configure in Integration settings.',
          connected: true,
        });
      }
      try {
        const mutation = `
          mutation CreateIssue($input: IssueCreateInput!) {
            issueCreate(input: $input) {
              success
              issue { id identifier url }
            }
          }
        `;
        const res = await fetch('https://api.linear.app/graphql', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: conn.access_token },
          body: JSON.stringify({
            query: mutation,
            variables: { input: { teamId, title, description } },
          }),
        });
        const data = (await res.json()) as { data?: { issueCreate?: { success?: boolean; issue?: { identifier: string } }; errors?: Array<{ message: string }> }; errors?: Array<{ message: string }> };
        const errs = data.errors ?? data.data?.issueCreate === undefined ? [] : [];
        if (errs.length) {
          return JSON.stringify({ error: errs[0].message ?? 'Linear API error', success: false });
        }
        const created = data.data?.issueCreate;
        if (!created?.success) {
          return JSON.stringify({ error: 'Linear issueCreate returned success=false', success: false });
        }
        return JSON.stringify({ success: true, identifier: created.issue?.identifier });
      } catch (err: any) {
        return JSON.stringify({ error: err.message, success: false });
      }
    },
  })
);

registerAegisTool(
  'postPRComment',
  { category: 'external', permissionLevel: 'moderate', requiredRbacPermissions: ['manage_integrations'] },
  tool({
    description: 'Post a comment on a GitHub pull request. Requires GitHub App integration and project with connected repo.',
    inputSchema: z.object({
      projectId: z.string().uuid(),
      prNumber: z.number(),
      body: z.string(),
    }),
    execute: async ({ projectId, prNumber, body }) => {
      const { data: repo } = await supabase
        .from('project_repositories')
        .select('repo_full_name, provider')
        .eq('project_id', projectId)
        .single();
      if (!repo || repo.provider !== 'github') {
        return JSON.stringify({
          error: 'Project repo not found or not a GitHub repo. Only GitHub is supported for PR comments.',
          success: false,
        });
      }
      const { data: project } = await supabase.from('projects').select('organization_id').eq('id', projectId).single();
      if (!project) return JSON.stringify({ error: 'Project not found', success: false });
      const { data: org } = await supabase.from('organizations').select('github_installation_id').eq('id', project.organization_id).single();
      const installationId = org?.github_installation_id;
      if (!installationId) {
        return JSON.stringify({
          error: 'GitHub App is not connected for this organization. Connect GitHub in Organization Settings.',
          success: false,
        });
      }
      try {
        const token = await createInstallationToken(installationId);
        await createIssueComment(token, repo.repo_full_name, prNumber, body);
        return JSON.stringify({ success: true, repo: repo.repo_full_name, prNumber });
      } catch (err: any) {
        return JSON.stringify({ error: err.message, success: false });
      }
    },
  })
);

registerAegisTool(
  'sendWebhook',
  { category: 'external', permissionLevel: 'moderate', requiredRbacPermissions: ['manage_integrations'] },
  tool({
    description: 'Send a webhook payload to a custom URL.',
    inputSchema: z.object({
      url: z.string().url(),
      payload: z.string(),
    }),
    execute: async ({ url, payload }) => {
      try {
        let parsed: any;
        try {
          parsed = JSON.parse(payload);
        } catch {
          return JSON.stringify({ error: 'payload must be valid JSON', success: false });
        }
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(parsed),
        });
        const text = await res.text();
        if (!res.ok) {
          return JSON.stringify({ error: `HTTP ${res.status}: ${text.slice(0, 500)}`, success: false });
        }
        return JSON.stringify({ success: true, statusCode: res.status });
      } catch (err: any) {
        return JSON.stringify({ error: err.message, success: false });
      }
    },
  })
);
