import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { sendEmail } from './email';

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface DispatchResult {
  success: boolean;
  statusCode?: number;
  externalId?: string;
  error?: string;
  retryable: boolean;
}

export interface NotificationMessage {
  title: string;
  body: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  eventType: string;
  projectName: string;
  organizationId: string;
  deptexUrl: string;
  metadata: Record<string, any>;
}

export interface IntegrationConnection {
  id: string;
  organization_id: string;
  provider: string;
  access_token: string;
  refresh_token?: string;
  token_expires_at?: string;
  display_name?: string;
  metadata?: Record<string, any>;
}

export interface NotificationEvent {
  id: string;
  event_type: string;
  organization_id: string;
  project_id?: string;
  payload: Record<string, any>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const APP_URL = process.env.FRONTEND_URL || 'https://app.deptex.io';

const SEVERITY_COLORS: Record<string, number> = {
  critical: 0xff0000,
  high: 0xff6600,
  medium: 0xffaa00,
  low: 0x0099ff,
  info: 0x888888,
};

const SEVERITY_HEX: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

const MESSAGE_LIMITS: Record<string, { title?: number; body?: number; totalBytes?: number }> = {
  slack: { title: 150, body: 3000 },
  discord: { title: 256, body: 4096 },
  jira: { title: 255, body: 32767 },
  linear: { title: 255, body: 10000 },
  asana: { title: 255, body: 65535 },
  email: { title: 978 },
  pagerduty: { title: 1024 },
  custom_webhook: { totalBytes: 100_000 },
};

const TICKETING_PROVIDERS = new Set(['jira', 'linear', 'asana']);

// ---------------------------------------------------------------------------
// Message templates
// ---------------------------------------------------------------------------

export function buildDefaultMessage(
  event: NotificationEvent,
  context: any
): NotificationMessage {
  const orgId = event.organization_id;
  const projectId = event.project_id || event.payload?.project_id;
  const projectName: string =
    event.payload?.project_name || context?.project_name || 'Unknown project';

  const baseUrl = `${APP_URL}/organizations/${orgId}`;
  const projectUrl = projectId ? `${baseUrl}/projects/${projectId}` : baseUrl;

  const templates: Record<string, () => Pick<NotificationMessage, 'title' | 'body' | 'severity' | 'deptexUrl'>> = {
    vulnerability_discovered: () => {
      const { osv_id, severity, dependency_name, version } = event.payload;
      return {
        title: `New ${severity || 'unknown'}-severity vulnerability in ${dependency_name || 'a dependency'}`,
        body: `${osv_id || 'A vulnerability'} was discovered in ${dependency_name}@${version || 'unknown'} used by ${projectName}. Review and remediate the issue to maintain your security posture.`,
        severity: severity || 'high',
        deptexUrl: `${projectUrl}/security`,
      };
    },
    malicious_package_detected: () => {
      const { dependency_name, version } = event.payload;
      return {
        title: `Malicious package detected: ${dependency_name || 'unknown'}`,
        body: `${dependency_name}@${version || 'unknown'} has been flagged as malicious in ${projectName}. Immediate removal is recommended.`,
        severity: 'critical',
        deptexUrl: `${projectUrl}/security`,
      };
    },
    status_changed: () => {
      const { previous_status, new_status } = event.payload;
      return {
        title: `${projectName} status changed to ${new_status || 'unknown'}`,
        body: `Project status changed from "${previous_status || 'none'}" to "${new_status || 'unknown'}".`,
        severity: 'info',
        deptexUrl: `${projectUrl}/overview`,
      };
    },
    pr_check_completed: () => {
      const { pr_number, result, summary } = event.payload;
      const passed = result === 'success' || result === 'passed';
      return {
        title: `PR #${pr_number || '?'} check ${passed ? 'passed' : 'failed'} for ${projectName}`,
        body: summary || `Pull request check completed with result: ${result || 'unknown'}.`,
        severity: passed ? 'info' : 'high',
        deptexUrl: `${projectUrl}/compliance/updates`,
      };
    },
    ai_fix_completed: () => {
      const { dependency_name, fix_type, pr_url } = event.payload;
      return {
        title: `AI fix completed for ${dependency_name || 'a dependency'} in ${projectName}`,
        body: `An AI-generated ${fix_type || 'fix'} has been created${pr_url ? ` — PR: ${pr_url}` : ''}. Review the changes before merging.`,
        severity: 'info',
        deptexUrl: pr_url || `${projectUrl}/dependencies`,
      };
    },
    extraction_completed: () => ({
      title: `Extraction completed for ${projectName}`,
      body: `Dependency extraction finished successfully. ${event.payload.dependency_count ?? 'All'} dependencies processed.`,
      severity: 'info',
      deptexUrl: `${projectUrl}/dependencies`,
    }),
    extraction_failed: () => ({
      title: `Extraction failed for ${projectName}`,
      body: `Dependency extraction failed: ${event.payload.error || 'Unknown error'}. Check project settings and retry.`,
      severity: 'high',
      deptexUrl: `${projectUrl}/settings`,
    }),
    dependency_added: () => {
      const { dependency_name, version } = event.payload;
      return {
        title: `New dependency added to ${projectName}`,
        body: `${dependency_name}@${version || 'latest'} was added to the project.`,
        severity: 'info',
        deptexUrl: `${projectUrl}/dependencies`,
      };
    },
    dependency_updated: () => {
      const { dependency_name, previous_version, new_version } = event.payload;
      return {
        title: `Dependency updated in ${projectName}`,
        body: `${dependency_name} was updated from ${previous_version || '?'} to ${new_version || '?'}.`,
        severity: 'info',
        deptexUrl: `${projectUrl}/dependencies`,
      };
    },
    dependency_removed: () => {
      const { dependency_name } = event.payload;
      return {
        title: `Dependency removed from ${projectName}`,
        body: `${dependency_name || 'A dependency'} was removed from the project.`,
        severity: 'info',
        deptexUrl: `${projectUrl}/dependencies`,
      };
    },
    policy_violation: () => {
      const { rule, dependency_name } = event.payload;
      return {
        title: `Policy violation in ${projectName}`,
        body: `${dependency_name || 'A dependency'} violates policy rule: ${rule || 'unknown rule'}.`,
        severity: 'medium',
        deptexUrl: `${projectUrl}/compliance/policy-results`,
      };
    },
    license_violation: () => {
      const { license, dependency_name } = event.payload;
      return {
        title: `License violation in ${projectName}`,
        body: `${dependency_name || 'A dependency'} uses license "${license || 'unknown'}" which is not allowed by your organization policy.`,
        severity: 'medium',
        deptexUrl: `${projectUrl}/compliance/policy-results`,
      };
    },
  };

  const builder = templates[event.event_type];
  const parts = builder
    ? builder()
    : {
        title: `[${event.event_type}] ${projectName}`,
        body: `An event of type "${event.event_type}" occurred in ${projectName}.`,
        severity: 'info' as const,
        deptexUrl: projectUrl,
      };

  return {
    ...parts,
    eventType: event.event_type,
    projectName,
    organizationId: orgId,
    metadata: event.payload,
  };
}

// ---------------------------------------------------------------------------
// Message length enforcement
// ---------------------------------------------------------------------------

function truncateWithSuffix(text: string, max: number, deptexUrl: string): string {
  if (text.length <= max) return text;
  const suffix = `... [View in Deptex](${deptexUrl})`;
  const available = max - suffix.length;
  if (available <= 0) return text.slice(0, max);
  return text.slice(0, available) + suffix;
}

export function enforceMessageLimits(
  message: NotificationMessage,
  destinationType: string
): NotificationMessage {
  const limits = MESSAGE_LIMITS[destinationType];
  if (!limits) return message;

  const out = { ...message };

  if (limits.title && out.title.length > limits.title) {
    out.title = truncateWithSuffix(out.title, limits.title, message.deptexUrl);
  }
  if (limits.body && out.body.length > limits.body) {
    out.body = truncateWithSuffix(out.body, limits.body, message.deptexUrl);
  }
  if (limits.totalBytes) {
    const payload = JSON.stringify(out);
    if (Buffer.byteLength(payload, 'utf8') > limits.totalBytes) {
      const overhead = Buffer.byteLength(payload, 'utf8') - Buffer.byteLength(out.body, 'utf8');
      const maxBody = limits.totalBytes - overhead - 200;
      out.body = truncateWithSuffix(out.body, Math.max(maxBody, 100), message.deptexUrl);
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// PII redacted mode helper
// ---------------------------------------------------------------------------

function applyRedactedMode(
  connection: IntegrationConnection,
  message: NotificationMessage
): NotificationMessage {
  if (!connection.metadata?.redacted_mode) return message;
  if (!TICKETING_PROVIDERS.has(connection.provider)) return message;
  return {
    ...message,
    body: `${message.title}\n\nView details in Deptex: ${message.deptexUrl}`,
  };
}

// ---------------------------------------------------------------------------
// Dispatchers
// ---------------------------------------------------------------------------

async function dispatchSlack(
  connection: IntegrationConnection,
  message: NotificationMessage,
  _event: NotificationEvent
): Promise<DispatchResult> {
  const channelId = connection.metadata?.channel_id;
  if (!channelId) {
    return { success: false, error: 'No Slack channel_id configured', retryable: false };
  }

  const msg = enforceMessageLimits(message, 'slack');

  const blocks = [
    {
      type: 'section',
      text: { type: 'mrkdwn', text: `*${msg.title}*\n${msg.body}` },
    },
    {
      type: 'context',
      elements: [
        { type: 'mrkdwn', text: `Severity: *${msg.severity}* | Event: \`${msg.eventType}\` | Project: *${msg.projectName}*` },
      ],
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: 'View in Deptex' },
          url: msg.deptexUrl,
        },
      ],
    },
  ];

  try {
    const res = await fetch('https://slack.com/api/chat.postMessage', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        Authorization: `Bearer ${connection.access_token}`,
      },
      body: JSON.stringify({ channel: channelId, blocks, text: msg.title }),
    });

    const data = await res.json() as any;

    if (!data.ok) {
      const retryable = data.error === 'rate_limited' || data.error === 'service_unavailable';
      return { success: false, statusCode: res.status, error: data.error, retryable };
    }

    return { success: true, statusCode: res.status, externalId: data.ts, retryable: false };
  } catch (err: any) {
    return { success: false, error: err.message, retryable: true };
  }
}

async function dispatchDiscord(
  connection: IntegrationConnection,
  message: NotificationMessage,
  _event: NotificationEvent
): Promise<DispatchResult> {
  const channelId = connection.metadata?.channel_id;
  if (!channelId) {
    return { success: false, error: 'No Discord channel_id configured', retryable: false };
  }

  const msg = enforceMessageLimits(message, 'discord');
  const color = SEVERITY_COLORS[msg.severity] ?? 0x888888;

  const embed = {
    title: msg.title,
    description: msg.body,
    color,
    url: msg.deptexUrl,
    fields: [
      { name: 'Severity', value: msg.severity, inline: true },
      { name: 'Project', value: msg.projectName, inline: true },
      { name: 'Event', value: msg.eventType, inline: true },
    ],
    footer: { text: 'Deptex' },
    timestamp: new Date().toISOString(),
  };

  try {
    const res = await fetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bot ${connection.access_token}`,
      },
      body: JSON.stringify({ embeds: [embed] }),
    });

    if (!res.ok) {
      const body = await res.text();
      const retryable = res.status === 429 || res.status >= 500;
      return { success: false, statusCode: res.status, error: body, retryable };
    }

    const data = await res.json() as any;
    return { success: true, statusCode: res.status, externalId: data.id, retryable: false };
  } catch (err: any) {
    return { success: false, error: err.message, retryable: true };
  }
}

async function dispatchJira(
  connection: IntegrationConnection,
  message: NotificationMessage,
  _event: NotificationEvent
): Promise<DispatchResult> {
  const projectKey = connection.metadata?.project_key;
  if (!projectKey) {
    return { success: false, error: 'No Jira project_key configured', retryable: false };
  }

  const msg = enforceMessageLimits(
    applyRedactedMode(connection, message),
    'jira'
  );

  const priorityMap: Record<string, string> = {
    critical: 'Highest',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Lowest',
  };

  const cloudId = connection.metadata?.cloud_id;
  const baseUrl = cloudId
    ? `https://api.atlassian.com/ex/jira/${cloudId}`
    : connection.metadata?.base_url;

  if (!baseUrl) {
    return { success: false, error: 'No Jira cloud_id or base_url configured', retryable: false };
  }

  const body = {
    fields: {
      project: { key: projectKey },
      summary: msg.title,
      description: {
        type: 'doc',
        version: 1,
        content: [
          {
            type: 'paragraph',
            content: [{ type: 'text', text: msg.body }],
          },
          {
            type: 'paragraph',
            content: [
              { type: 'text', text: 'View in Deptex: ' },
              {
                type: 'text',
                text: msg.deptexUrl,
                marks: [{ type: 'link', attrs: { href: msg.deptexUrl } }],
              },
            ],
          },
        ],
      },
      issuetype: { name: connection.metadata?.issue_type || 'Task' },
      priority: { name: priorityMap[msg.severity] || 'Medium' },
      labels: ['deptex', msg.severity],
    },
  };

  try {
    const res = await fetch(`${baseUrl}/rest/api/3/issue`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${connection.access_token}`,
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const errBody = await res.text();
      const retryable = res.status === 429 || res.status >= 500;
      return { success: false, statusCode: res.status, error: errBody, retryable };
    }

    const data = await res.json() as any;
    return { success: true, statusCode: res.status, externalId: data.key, retryable: false };
  } catch (err: any) {
    return { success: false, error: err.message, retryable: true };
  }
}

async function dispatchLinear(
  connection: IntegrationConnection,
  message: NotificationMessage,
  _event: NotificationEvent
): Promise<DispatchResult> {
  const teamId = connection.metadata?.team_id;
  if (!teamId) {
    return { success: false, error: 'No Linear team_id configured', retryable: false };
  }

  const msg = enforceMessageLimits(
    applyRedactedMode(connection, message),
    'linear'
  );

  const priorityMap: Record<string, number> = {
    critical: 1,
    high: 2,
    medium: 3,
    low: 4,
    info: 0,
  };

  const mutation = `
    mutation CreateIssue($input: IssueCreateInput!) {
      issueCreate(input: $input) {
        success
        issue { id identifier url }
      }
    }
  `;

  const variables = {
    input: {
      teamId,
      title: msg.title,
      description: `${msg.body}\n\n[View in Deptex](${msg.deptexUrl})`,
      priority: priorityMap[msg.severity] ?? 0,
      labelIds: connection.metadata?.label_ids || [],
    },
  };

  try {
    const res = await fetch('https://api.linear.app/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: connection.access_token,
      },
      body: JSON.stringify({ query: mutation, variables }),
    });

    const data = await res.json() as any;

    if (data.errors?.length) {
      return { success: false, statusCode: res.status, error: data.errors[0].message, retryable: res.status >= 500 };
    }

    const created = data.data?.issueCreate;
    if (!created?.success) {
      return { success: false, error: 'Linear issueCreate returned success=false', retryable: false };
    }

    return {
      success: true,
      statusCode: res.status,
      externalId: created.issue?.identifier,
      retryable: false,
    };
  } catch (err: any) {
    return { success: false, error: err.message, retryable: true };
  }
}

async function dispatchAsana(
  connection: IntegrationConnection,
  message: NotificationMessage,
  _event: NotificationEvent
): Promise<DispatchResult> {
  const projectGid = connection.metadata?.project_gid;
  const workspaceGid = connection.metadata?.workspace_gid;
  if (!workspaceGid) {
    return { success: false, error: 'No Asana workspace_gid configured', retryable: false };
  }

  const msg = enforceMessageLimits(
    applyRedactedMode(connection, message),
    'asana'
  );

  const taskData: Record<string, any> = {
    data: {
      name: msg.title,
      notes: `${msg.body}\n\nView in Deptex: ${msg.deptexUrl}`,
      workspace: workspaceGid,
      ...(projectGid && { projects: [projectGid] }),
    },
  };

  try {
    const res = await fetch('https://app.asana.com/api/1.0/tasks', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${connection.access_token}`,
      },
      body: JSON.stringify(taskData),
    });

    if (!res.ok) {
      const errBody = await res.text();
      const retryable = res.status === 429 || res.status >= 500;
      return { success: false, statusCode: res.status, error: errBody, retryable };
    }

    const data = await res.json() as any;
    return { success: true, statusCode: res.status, externalId: data.data?.gid, retryable: false };
  } catch (err: any) {
    return { success: false, error: err.message, retryable: true };
  }
}

async function dispatchEmail(
  connection: IntegrationConnection,
  message: NotificationMessage,
  event: NotificationEvent
): Promise<DispatchResult> {
  const recipients = connection.metadata?.recipients as string[] | undefined;
  if (!recipients?.length) {
    return { success: false, error: 'No email recipients configured', retryable: false };
  }

  const msg = enforceMessageLimits(message, 'email');
  const subject = msg.title.replace(/[\r\n]/g, ' ').slice(0, 978);
  const severityColor = SEVERITY_HEX[msg.severity] || '#6b7280';

  const apiKey = process.env.INTERNAL_API_KEY;
  const unsubscribeTokens = recipients.map((email) => {
    if (!apiKey) return '';
    return jwt.sign(
      { email, orgId: event.organization_id, type: 'unsubscribe' },
      apiKey,
      { expiresIn: '90d' }
    );
  });

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#09090b;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#09090b;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#09090b;border:1px solid #27272a;border-radius:8px;overflow:hidden;">
        <tr><td style="padding:24px 32px;border-bottom:1px solid #27272a;">
          <span style="color:#fafafa;font-size:16px;font-weight:600;">Deptex</span>
        </td></tr>
        <tr><td style="padding:32px;">
          <span style="display:inline-block;padding:2px 10px;border-radius:9999px;font-size:12px;font-weight:500;color:#fff;background:${severityColor};margin-bottom:16px;">${msg.severity.toUpperCase()}</span>
          <h1 style="color:#fafafa;font-size:20px;font-weight:600;margin:16px 0 8px;">${msg.title}</h1>
          <p style="color:#a1a1aa;font-size:14px;line-height:1.6;margin:0 0 24px;">${msg.body}</p>
          <table cellpadding="0" cellspacing="0"><tr><td style="background:#fafafa;border-radius:6px;">
            <a href="${msg.deptexUrl}" style="display:inline-block;padding:10px 24px;color:#09090b;text-decoration:none;font-size:14px;font-weight:500;">View in Deptex</a>
          </td></tr></table>
        </td></tr>
        <tr><td style="padding:16px 32px;border-top:1px solid #27272a;color:#52525b;font-size:12px;">
          Event: ${msg.eventType} &middot; Project: ${msg.projectName}
        </td></tr>
      </table>
      <p style="color:#52525b;font-size:11px;margin-top:16px;">
        <a href="${APP_URL}/api/notifications/unsubscribe?token=${unsubscribeTokens[0] || ''}" style="color:#52525b;text-decoration:underline;">Unsubscribe</a>
      </p>
    </td></tr>
  </table>
</body>
</html>`;

  const text = `[${msg.severity.toUpperCase()}] ${msg.title}\n\n${msg.body}\n\nView in Deptex: ${msg.deptexUrl}`;

  const unsubscribeUrl = `${APP_URL}/api/notifications/unsubscribe?token=${unsubscribeTokens[0] || ''}`;
  const headers: Record<string, string> = {};
  if (unsubscribeTokens[0]) {
    headers['List-Unsubscribe'] = `<${unsubscribeUrl}>`;
    headers['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
  }

  try {
    const result = await sendEmail({
      to: recipients,
      subject,
      html,
      text,
      ...headers,
    });

    if (!result.sent) {
      return { success: false, error: result.error || 'Email send failed', retryable: true };
    }
    return { success: true, externalId: result.messageId, retryable: false };
  } catch (err: any) {
    return { success: false, error: err.message, retryable: true };
  }
}

async function dispatchCustomWebhook(
  connection: IntegrationConnection,
  message: NotificationMessage,
  event: NotificationEvent
): Promise<DispatchResult> {
  const webhookUrl = connection.metadata?.webhook_url;
  if (!webhookUrl) {
    return { success: false, error: 'No webhook_url configured', retryable: false };
  }

  const msg = enforceMessageLimits(message, 'custom_webhook');
  const deliveryId = crypto.randomUUID();

  const payload = JSON.stringify({
    event: event.event_type,
    delivery_id: deliveryId,
    timestamp: new Date().toISOString(),
    organization_id: event.organization_id,
    project_id: event.project_id,
    notification: {
      title: msg.title,
      body: msg.body,
      severity: msg.severity,
      url: msg.deptexUrl,
    },
    data: event.payload,
  });

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Deptex-Event': event.event_type,
    'X-Deptex-Delivery': deliveryId,
    'User-Agent': 'Deptex-Webhook/1.0',
  };

  const secret = connection.metadata?.webhook_secret || connection.access_token;
  if (secret) {
    const signature = crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex');
    headers['X-Deptex-Signature'] = `sha256=${signature}`;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers,
      body: payload,
      signal: controller.signal,
      redirect: 'error',
    });

    clearTimeout(timeout);

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      const retryable = res.status === 429 || res.status >= 500;
      return { success: false, statusCode: res.status, error: body.slice(0, 500), retryable };
    }

    return { success: true, statusCode: res.status, externalId: deliveryId, retryable: false };
  } catch (err: any) {
    const retryable = err.name === 'AbortError' || err.code === 'ECONNREFUSED';
    return { success: false, error: err.message, retryable };
  }
}

async function dispatchPagerDuty(
  connection: IntegrationConnection,
  message: NotificationMessage,
  event: NotificationEvent
): Promise<DispatchResult> {
  const routingKey = connection.access_token;
  if (!routingKey) {
    return { success: false, error: 'No PagerDuty routing key configured', retryable: false };
  }

  const msg = enforceMessageLimits(message, 'pagerduty');

  const pdSeverity: Record<string, string> = {
    critical: 'critical',
    high: 'error',
    medium: 'warning',
    low: 'info',
    info: 'info',
  };

  const payload = {
    routing_key: routingKey,
    event_action: 'trigger',
    dedup_key: `deptex-${event.id}`,
    payload: {
      summary: msg.title,
      source: 'Deptex',
      severity: pdSeverity[msg.severity] || 'info',
      component: msg.projectName,
      group: event.organization_id,
      class: msg.eventType,
      custom_details: {
        body: msg.body,
        deptex_url: msg.deptexUrl,
        ...event.payload,
      },
    },
    links: [{ href: msg.deptexUrl, text: 'View in Deptex' }],
  };

  try {
    const res = await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const body = await res.text();
      const retryable = res.status === 429 || res.status >= 500;
      return { success: false, statusCode: res.status, error: body, retryable };
    }

    const data = await res.json() as any;
    return { success: true, statusCode: res.status, externalId: data.dedup_key, retryable: false };
  } catch (err: any) {
    return { success: false, error: err.message, retryable: true };
  }
}

// ---------------------------------------------------------------------------
// Dispatcher router
// ---------------------------------------------------------------------------

const dispatchers: Record<string, (c: IntegrationConnection, m: NotificationMessage, e: NotificationEvent) => Promise<DispatchResult>> = {
  slack: dispatchSlack,
  discord: dispatchDiscord,
  jira: dispatchJira,
  linear: dispatchLinear,
  asana: dispatchAsana,
  email: dispatchEmail,
  custom_webhook: dispatchCustomWebhook,
  pagerduty: dispatchPagerDuty,
};

export async function dispatchToDestination(
  connection: IntegrationConnection,
  message: NotificationMessage,
  event: NotificationEvent
): Promise<DispatchResult> {
  const handler = dispatchers[connection.provider];
  if (!handler) {
    return { success: false, error: `Unsupported provider: ${connection.provider}`, retryable: false };
  }
  return handler(connection, message, event);
}
