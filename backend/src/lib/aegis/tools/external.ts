// @ts-nocheck
import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../lib/supabase';
import { sendEmail } from '../../email';
import { createInstallationToken } from '../../github';
import { createIssueComment } from '../../github';
import { createJiraIssue, createLinearIssue, TrackerError } from '../../trackers';

registerAegisTool(
  'sendSlackMessage',
  { category: 'external', permissionLevel: 'moderate', requiredRbacPermissions: ['manage_integrations'] },
  tool({
    description: 'Send a message to a Slack channel. Requires Slack integration to be connected.',
    parameters: z.object({
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
    parameters: z.object({
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
    parameters: z.object({
      organizationId: z.string().uuid(),
      summary: z.string(),
      description: z.string(),
      issueType: z.string().optional(),
      projectKey: z.string().optional().describe('Jira project key (e.g. SEC). Falls back to the stored default.'),
    }),
    execute: async ({ organizationId, summary, description, issueType, projectKey }) => {
      try {
        const result = await createJiraIssue(organizationId, { projectKey, summary, description, issueType });
        return JSON.stringify({ success: true, issueKey: result.externalKey, url: result.externalUrl });
      } catch (err: any) {
        if (err instanceof TrackerError) {
          return JSON.stringify({ error: err.message, connected: err.connected, success: false });
        }
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
    parameters: z.object({
      organizationId: z.string().uuid(),
      title: z.string(),
      description: z.string(),
      teamId: z.string().optional().describe('Linear team id. Falls back to the stored default.'),
    }),
    execute: async ({ organizationId, title, description, teamId }) => {
      try {
        const result = await createLinearIssue(organizationId, { teamId, title, description });
        return JSON.stringify({ success: true, identifier: result.externalKey, url: result.externalUrl });
      } catch (err: any) {
        if (err instanceof TrackerError) {
          return JSON.stringify({ error: err.message, connected: err.connected, success: false });
        }
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
    parameters: z.object({
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
    parameters: z.object({
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
