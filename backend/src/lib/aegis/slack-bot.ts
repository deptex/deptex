/**
 * Phase 7B: Aegis Slack bot handler.
 * Handles:
 * - app_mention events from Slack Events API
 * - Slash commands: /aegis status, /aegis fix CVE-..., /aegis report
 * - Interactive actions (approval buttons)
 * - Rate limiting (1 msg/sec per channel)
 *
 * Slack Events API requires 3-second ack — we ack immediately and process via QStash.
 */
// @ts-nocheck
import crypto from 'crypto';
import { supabase } from '../../lib/supabase';
import { decryptApiKey } from '../ai/encryption';
import { executeMessage, ExecutionContext } from './executor';

// ─── QStash helpers ───

function getQStashToken(): string | undefined {
  return process.env.QSTASH_TOKEN;
}

function getQStashBaseUrl(): string {
  return process.env.QSTASH_REGION
    ? process.env[`${process.env.QSTASH_REGION}_QSTASH_URL`]?.replace(/\/$/, '') || 'https://qstash.upstash.io'
    : 'https://qstash.upstash.io';
}

function getApiBaseUrl(): string {
  return process.env.API_BASE_URL || process.env.BACKEND_URL || 'http://localhost:3001';
}

// ─── Rate limiting: 1 msg/sec per channel ───

const channelLastSend = new Map<string, number>();
const RATE_LIMIT_MS = 1000;

async function rateLimitChannel(channelId: string): Promise<void> {
  const last = channelLastSend.get(channelId) ?? 0;
  const now = Date.now();
  const elapsed = now - last;
  if (elapsed < RATE_LIMIT_MS) {
    await new Promise(r => setTimeout(r, RATE_LIMIT_MS - elapsed));
  }
  channelLastSend.set(channelId, Date.now());
}

// ─── Slack signature verification ───

/**
 * Verify Slack request signature using HMAC-SHA256.
 * Slack sends: X-Slack-Signature: v0=<hex>, X-Slack-Request-Timestamp: <unix_ts>
 * Base string: v0:timestamp:body
 */
export function verifySlackSignatureWithTimestamp(
  body: string,
  signature: string,
  signingSecret: string,
  timestamp: string
): boolean {
  if (!signature.startsWith('v0=')) return false;
  // Reject if request is older than 5 minutes (replay attack)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestamp, 10)) > 60 * 5) return false;
  const baseString = `v0:${timestamp}:${body}`;
  const hmac = crypto.createHmac('sha256', signingSecret);
  hmac.update(baseString);
  return hmac.digest('hex') === signature.slice(3);
}

// ─── Lookup org config ───

interface SlackConfig {
  id: string;
  organization_id: string;
  slack_bot_token: string;
  slack_signing_secret: string;
  encryption_key_version?: number;
  default_channel_id?: string;
  enabled: boolean;
  slack_team_id?: string;
}

async function getSlackConfigByTeamId(teamId: string): Promise<SlackConfig | null> {
  const { data, error } = await supabase
    .from('aegis_slack_config')
    .select('*')
    .eq('enabled', true);

  if (error) {
    console.error('[Slack] Failed to fetch slack config:', error);
    return null;
  }

  const configs = (data ?? []) as (SlackConfig & { slack_team_id?: string })[];
  const match = configs.find(c => c.slack_team_id === teamId);
  return match ?? configs[0] ?? null;
}

function getBotToken(config: SlackConfig): string {
  if (config.encryption_key_version != null && config.encryption_key_version > 0) {
    return decryptApiKey(config.slack_bot_token, config.encryption_key_version);
  }
  return config.slack_bot_token;
}

function getSigningSecret(config: SlackConfig): string {
  if (config.encryption_key_version != null && config.encryption_key_version > 0) {
    return decryptApiKey(config.slack_signing_secret, config.encryption_key_version);
  }
  return config.slack_signing_secret;
}

// ─── Slack Web API (chat.postMessage) ───

/**
 * Send a message to a Slack channel. Respects rate limit (1 msg/sec per channel).
 */
export async function sendSlackResponse(
  botToken: string,
  channelId: string,
  text: string,
  threadTs?: string
): Promise<boolean> {
  await rateLimitChannel(channelId);

  const res = await fetch('https://slack.com/api/chat.postMessage', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${botToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      channel: channelId,
      text,
      ...(threadTs && { thread_ts: threadTs }),
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    console.error('[Slack] chat.postMessage failed:', res.status, err);
    return false;
  }

  const data = await res.json();
  if (!data.ok) {
    console.error('[Slack] chat.postMessage API error:', data);
    return false;
  }

  return true;
}

// ─── Event handlers ───

/**
 * Handle Slack Events API payload.
 * Verifies signature (needs X-Slack-Signature and X-Slack-Request-Timestamp from headers),
 * processes app_mention, url_verification.
 * Returns { challenge } for url_verification; otherwise processes async via QStash.
 */
export async function handleSlackEvent(
  body: string,
  signingSecret: string,
  headers?: { signature?: string; timestamp?: string }
): Promise<{ challenge?: string }> {
  const parsed = JSON.parse(body);

  // url_verification challenge (Slack app config)
  if (parsed.type === 'url_verification') {
    return { challenge: parsed.challenge };
  }

  const sig = headers?.signature ?? '';
  const ts = headers?.timestamp ?? String(Math.floor(Date.now() / 1000));
  const isValid = verifySlackSignatureWithTimestamp(body, sig, signingSecret, ts);
  if (!isValid) {
    throw new Error('Invalid Slack signature');
  }

  const event = parsed.event;
  const teamId = parsed.team_id;

  if (parsed.type === 'event_callback') {
    if (event?.type === 'app_mention') {
      const config = await getSlackConfigByTeamId(teamId);
      if (!config) {
        console.warn('[Slack] No slack config for team:', teamId);
        return {};
      }

      const userId = event.user;
      const channelId = event.channel;
      const threadTs = event.thread_ts ?? event.ts;
      let text = (event.text || '').replace(/<@[A-Z0-9]+>/g, '').trim();

      // Queue via QStash for async processing (Slack requires 3s ack)
      const token = getQStashToken();
      if (token) {
        const url = `${getApiBaseUrl()}/api/internal/aegis/process-slack-message`;
        await fetch(`${getQStashBaseUrl()}/v2/publish/${encodeURIComponent(url)}`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'Upstash-Method': 'POST',
            'Upstash-Delay': '0s',
            'Upstash-Retries': '3',
            'Upstash-Forward-Content-Type': 'application/json',
          },
          body: JSON.stringify({
            organizationId: config.organization_id,
            userId,
            channelId,
            text,
            threadTs,
          }),
        });
      } else {
        // No QStash: process inline (may exceed 3s - not recommended for production)
        const botToken = getBotToken(config);
        await processSlackMessage(config.organization_id, userId, channelId, text, threadTs, botToken);
      }
    }
  }

  return {};
}

/**
 * Handle Slack Interactive Components (button clicks).
 * Parses callback_id for aegis_approval_approve / aegis_approval_reject.
 * Pass headers.signature and headers.timestamp from X-Slack-Signature and X-Slack-Request-Timestamp.
 */
export async function handleSlackInteraction(
  body: string,
  signingSecret: string,
  headers?: { signature?: string; timestamp?: string }
): Promise<void> {
  // Slack sends form-urlencoded
  const payloadStr = typeof body === 'string' && body.startsWith('payload=')
    ? decodeURIComponent(body.replace(/^payload=/, ''))
    : body;
  const payload = JSON.parse(payloadStr);

  const sig = headers?.signature ?? '';
  const ts = headers?.timestamp ?? String(Math.floor(Date.now() / 1000));
  const isValid = verifySlackSignatureWithTimestamp(body, sig, signingSecret, ts);
  if (!isValid) {
    throw new Error('Invalid Slack signature');
  }

  const action = payload.actions?.[0];
  const callbackId = action?.action_id ?? payload.callback_id ?? '';

  if (callbackId === 'aegis_approval_approve' || callbackId === 'aegis_approval_reject') {
    const requestId = action?.value ?? payload.callback_id?.split('|')?.[1];
    if (!requestId) {
      console.warn('[Slack] Approval action missing requestId');
      return;
    }

    const status = callbackId === 'aegis_approval_approve' ? 'approved' : 'rejected';
    const userId = payload.user?.id;

    await supabase
      .from('aegis_approval_requests')
      .update({
        status,
        reviewed_at: new Date().toISOString(),
        // reviewed_by: we don't have auth.users id from Slack user_id - could map via user_profiles
      })
      .eq('id', requestId)
      .eq('status', 'pending');

    // Optionally respond in thread
    const channelId = payload.channel?.id;
    const threadTs = payload.message?.thread_ts ?? payload.message?.ts;
    const responseUrl = payload.response_url;
    if (responseUrl && channelId) {
      const config = await getSlackConfigByTeamId(payload.team?.id ?? '');
      if (config) {
        const text = status === 'approved'
          ? '✅ Approval request approved. Aegis will continue.'
          : '❌ Approval request rejected.';
        if (threadTs) {
          await sendSlackResponse(getBotToken(config), channelId, text, threadTs);
        } else {
          await fetch(responseUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, replace_original: false }),
          });
        }
      }
    }
  }
}

/**
 * Process a Slack message asynchronously (called via QStash or inline).
 * Runs Aegis and sends the response back to Slack.
 * If botToken is not provided, looks up aegis_slack_config for the organization.
 */
export async function processSlackMessage(
  organizationId: string,
  userId: string,
  channelId: string,
  text: string,
  threadTs: string | undefined,
  botToken?: string
): Promise<void> {
  let token = botToken;
  if (!token) {
    const { data: config } = await supabase
      .from('aegis_slack_config')
      .select('*')
      .eq('organization_id', organizationId)
      .eq('enabled', true)
      .single();
    if (!config) {
      console.error('[Slack] No slack config for org:', organizationId);
      return;
    }
    token = getBotToken(config as SlackConfig);
  }
  if (!text.trim()) {
    await sendSlackResponse(token!, channelId, 'What would you like me to help with?', threadTs);
    return;
  }

  const { data: org } = await supabase
    .from('organizations')
    .select('name')
    .eq('id', organizationId)
    .single();

  const context: ExecutionContext = {
    organizationId,
    userId,
    organizationName: org?.name ?? 'Organization',
  };

  try {
    const result = await executeMessage(text, context);
    const reply = typeof result.message === 'string' ? result.message : JSON.stringify(result.message);
    await sendSlackResponse(token!, channelId, reply, threadTs);
  } catch (err: any) {
    console.error('[Slack] Aegis execution failed:', err);
    await sendSlackResponse(
      token!,
      channelId,
      `Sorry, I encountered an error: ${err.message || 'Unknown error'}`,
      threadTs
    );
  }
}

// ─── Slash command handling (called from route, uses same verify + process) ───

export function parseSlashCommand(text: string): { command: string; args: string[] } {
  const parts = text.trim().split(/\s+/);
  const cmd = parts[0]?.toLowerCase() ?? '';
  const args = parts.slice(1);
  return { command: cmd, args };
}

export function handleSlashCommandResponse(
  command: string,
  args: string[]
): string {
  switch (command) {
    case 'status':
      return 'Fetching security status… (Implementation: call Aegis tools and format output)';
    case 'fix':
      const cve = args[0];
      return cve ? `Queuing fix for ${cve}… (Implementation: trigger AI fix)` : 'Usage: /aegis fix CVE-XXXX-XXXXX';
    case 'report':
      return 'Generating report… (Implementation: run Aegis report automation)';
    default:
      return `Unknown command: ${command}. Available: status, fix, report`;
  }
}
