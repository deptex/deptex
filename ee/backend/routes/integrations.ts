import express from 'express';
import { supabase } from '../../../backend/src/lib/supabase';
import { authenticateUser, AuthRequest } from '../../../backend/src/middleware/auth';
import {
  createInstallationToken,
  getInstallationAccount,
  getCompareChangedFiles,
  getRepositoryFileContent,
  listCheckRunsForRef,
  createCheckRun,
  updateCheckRun,
  createIssueComment,
  listIssueComments,
  updateIssueComment,
  type CheckRunOutput,
} from '../lib/github';
import { queueExtractionJob, queueASTParsingJob } from '../lib/redis';
import { invalidateProjectCaches } from '../lib/cache';
import { getEffectivePolicies, isLicenseAllowed } from '../lib/project-policies';
import { getVulnCountsForPackageVersion, exceedsThreshold, type VulnCounts } from '../../../backend/src/lib/vuln-counts';
import { detectAffectedWorkspaces, isFileInWorkspace, type EcosystemId } from '../lib/manifest-registry';
import { checkRateLimit } from '../lib/rate-limit';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { emitEvent } from '../lib/event-bus';

const DEPTEX_COMMENT_MARKER = '<!-- deptex-pr-check -->';
const MAX_COMMENT_LENGTH = 60000;
const MAX_CHECK_RUN_TEXT = 65000;
const MAX_EXTRACTION_PER_PUSH = 10;

/** Base URL of this backend (no trailing slash). Used for OAuth redirect/callback URLs. */
function getBackendUrl(): string {
  const url = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
  return url.replace(/\/$/, '');
}

/** Base URL of the frontend app (no trailing slash). Used to redirect users after OAuth. */
function getFrontendUrl(): string {
  const url = process.env.FRONTEND_URL || 'http://localhost:3000';
  return url.replace(/\/$/, '');
}

const router = express.Router();

// Initiate Slack OAuth
router.get('/slack/connect', authenticateUser, async (req: AuthRequest, res) => {
  const clientId = process.env.SLACK_CLIENT_ID;
  // Use BACKEND_URL if set, otherwise default to localhost
  // Make sure this matches EXACTLY what you configured in Slack app settings
  const backendUrl = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
  const redirectUri = `${backendUrl}/api/integrations/slack/callback`;
  const scopes = 'chat:write channels:read channels:history files:write';
  
  console.log('Slack OAuth redirect URI:', redirectUri); // Debug log
  
  if (!clientId) {
    return res.status(500).json({ error: 'Slack client ID not configured' });
  }
  
  // Store user ID in state for security
  const state = Buffer.from(JSON.stringify({ userId: req.user!.id })).toString('base64');
  
  const authUrl = `https://slack.com/oauth/v2/authorize?client_id=${clientId}&scope=${scopes}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
  
  // Return the redirect URL as JSON so frontend can handle it
  res.json({ redirectUrl: authUrl });
});

// Handle Slack OAuth callback
router.get('/slack/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  if (error) {
    return res.redirect(`${process.env.FRONTEND_URL}/settings?error=slack&message=${encodeURIComponent(error as string)}`);
  }
  
  if (!code) {
    return res.redirect(`${process.env.FRONTEND_URL}/settings?error=slack&message=No authorization code`);
  }
  
  try {
    // Decode state to get user ID
    let userId: string;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
    } catch {
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=slack&message=Invalid state`);
    }
    
    // Reconstruct redirect URI (must match exactly what was used in the initial request)
    const backendUrl = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
    const redirectUri = `${backendUrl}/api/integrations/slack/callback`;
    
    console.log('Slack callback redirect URI:', redirectUri); // Debug log
    
    // Exchange code for token
    const response = await fetch('https://slack.com/api/oauth.v2.access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.SLACK_CLIENT_ID!,
        client_secret: process.env.SLACK_CLIENT_SECRET!,
        code: code as string,
        redirect_uri: redirectUri,
      }),
    });
    
    const data = await response.json() as any;
    
    if (!data.ok) {
      console.error('Slack OAuth error:', data.error);
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=slack&message=${encodeURIComponent(data.error || 'Unknown error')}`);
    }
    
    // Store tokens in database
    const { error: dbError } = await (supabase
      .from('user_integrations')
      .upsert({
        user_id: userId,
        provider: 'slack',
        access_token: data.access_token, // Bot token (xoxb-...)
        refresh_token: data.authed_user?.access_token || null, // User token (xoxp-...) - store in refresh_token field
        team_id: data.team.id,
        team_name: data.team.name,
        provider_user_id: data.authed_user?.id,
        provider_username: data.authed_user?.id, // Slack doesn't provide username in OAuth response
        metadata: {
          bot_user_id: data.bot_user_id,
          authed_user_id: data.authed_user?.id,
          scope: data.scope,
        },
        updated_at: new Date().toISOString(),
      } as any, {
        onConflict: 'user_id,provider'
      }));
    
    if (dbError) {
      console.error('Database error:', dbError);
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=slack&message=Failed to save integration`);
    }
    
    res.redirect(`${process.env.FRONTEND_URL}/settings?connected=slack`);
  } catch (error: any) {
    console.error('Slack OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/settings?error=slack&message=${encodeURIComponent(error.message || 'Unknown error')}`);
  }
});

// Get user's integrations
router.get('/', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { data, error } = await supabase
      .from('user_integrations')
      .select('provider, team_name, provider_username, created_at, updated_at')
      .eq('user_id', req.user!.id);
    
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    
    res.json(data || []);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Disconnect an integration
router.delete('/:provider', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { provider } = req.params;
    
    const { error } = await supabase
      .from('user_integrations')
      .delete()
      .eq('user_id', req.user!.id)
      .eq('provider', provider);
    
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Initiate Discord OAuth
router.get('/discord/connect', authenticateUser, async (req: AuthRequest, res) => {
  const clientId = process.env.DISCORD_CLIENT_ID;
  const backendUrl = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
  const redirectUri = `${backendUrl}/api/integrations/discord/callback`;
  const scopes = 'bot webhook.incoming guilds guilds.members.read';
  
  if (!clientId) {
    return res.status(500).json({ error: 'Discord client ID not configured' });
  }
  
  // Store user ID in state for security
  const state = Buffer.from(JSON.stringify({ userId: req.user!.id })).toString('base64');
  
  // Discord bot permissions (permission integer)
  // 2048 = SEND_MESSAGES
  // 8192 = MANAGE_MESSAGES
  // 16384 = EMBED_LINKS
  // 32768 = ATTACH_FILES
  // 536870912 = USE_EXTERNAL_EMOJIS
  // Combined: 2048 + 8192 + 16384 + 32768 + 536870912 = 536889104
  // Or use a permission calculator: https://discordapi.com/permissions.html
  const permissions = '536889104'; // Send messages, manage messages, embed links, attach files, use external emojis
  
  const authUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&permissions=${permissions}&scope=${encodeURIComponent(scopes)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&response_type=code`;
  
  // Return the redirect URL as JSON so frontend can handle it
  res.json({ redirectUrl: authUrl });
});

// Handle Discord OAuth callback
router.get('/discord/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  if (error) {
    return res.redirect(`${process.env.FRONTEND_URL}/settings?error=discord&message=${encodeURIComponent(error as string)}`);
  }
  
  if (!code) {
    return res.redirect(`${process.env.FRONTEND_URL}/settings?error=discord&message=No authorization code`);
  }
  
  try {
    // Decode state to get user ID
    let userId: string;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
    } catch {
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=discord&message=Invalid state`);
    }
    
    // Reconstruct redirect URI (must match exactly what was used in the initial request)
    const backendUrl = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
    const redirectUri = `${backendUrl}/api/integrations/discord/callback`;
    
    // Exchange code for token
    const response = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID!,
        client_secret: process.env.DISCORD_CLIENT_SECRET!,
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: redirectUri,
      }),
    });
    
    const data = await response.json() as any;
    
    if (data.error) {
      console.error('Discord OAuth error:', data.error);
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=discord&message=${encodeURIComponent(data.error_description || data.error || 'Unknown error')}`);
    }
    
    // Get user info
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: {
        'Authorization': `Bearer ${data.access_token}`,
      },
    });
    const userData = await userResponse.json() as any;
    
    // Store tokens in database
    const { error: dbError } = await (supabase
      .from('user_integrations')
      .upsert({
        user_id: userId,
        provider: 'discord',
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        provider_user_id: userData.id,
        provider_username: userData.username,
        metadata: {
          discriminator: userData.discriminator,
          avatar: userData.avatar,
          scope: data.scope,
        },
        updated_at: new Date().toISOString(),
      } as any, {
        onConflict: 'user_id,provider'
      }));
    
    if (dbError) {
      console.error('Database error:', dbError);
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=discord&message=Failed to save integration`);
    }
    
    res.redirect(`${process.env.FRONTEND_URL}/settings?connected=discord`);
  } catch (error: any) {
    console.error('Discord OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/settings?error=discord&message=${encodeURIComponent(error.message || 'Unknown error')}`);
  }
});

// ============================================================
// ORG-LEVEL Discord connect (OAuth -> organization_integrations)
// ============================================================
router.get('/discord/install', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { org_id, project_id, team_id } = req.query;
    if (!org_id || typeof org_id !== 'string') {
      return res.status(400).json({ error: 'Organization ID is required' });
    }
    const clientId = process.env.DISCORD_CLIENT_ID;
    if (!clientId) {
      return res.status(500).json({ error: 'Discord client ID not configured' });
    }
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', org_id)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    if (project_id && typeof project_id === 'string') {
      const { data: proj } = await supabase.from('projects').select('id').eq('id', project_id).eq('organization_id', org_id).single();
      if (!proj) return res.status(400).json({ error: 'Project not found' });
    }
    if (team_id && typeof team_id === 'string') {
      const { data: team } = await supabase.from('teams').select('id').eq('id', team_id).eq('organization_id', org_id).single();
      if (!team) return res.status(400).json({ error: 'Team not found' });
    }
    const backendUrl = (process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`).replace(/\/$/, '');
    const frontendUrl = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
    const redirectUri = `${backendUrl}/api/integrations/discord/org-callback`;
    const scopes = 'bot guilds';
    const permissions = '536889104';
    const statePayload: { userId: string; orgId: string; projectId?: string; teamId?: string; successRedirect?: string } = { userId: req.user!.id, orgId: org_id };
    if (project_id && typeof project_id === 'string') {
      statePayload.projectId = project_id;
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/projects/${project_id}/settings?connected=discord`;
    } else if (team_id && typeof team_id === 'string') {
      statePayload.teamId = team_id;
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/teams/${team_id}/settings/notifications?connected=discord`;
    } else {
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/settings/integrations?connected=discord`;
    }
    const state = Buffer.from(JSON.stringify(statePayload)).toString('base64');
    const authUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&permissions=${permissions}&scope=${encodeURIComponent(scopes)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&response_type=code`;
    res.json({ redirectUrl: authUrl });
  } catch (error: any) {
    console.error('Discord org install error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/discord/org-callback', async (req, res) => {
  const { code, state, error } = req.query;
  const frontendUrl = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');

  if (error) {
    return res.redirect(`${frontendUrl}?error=discord&message=${encodeURIComponent(error as string)}`);
  }
  if (!code) {
    return res.redirect(`${frontendUrl}?error=discord&message=No authorization code`);
  }

  try {
    let userId: string;
    let orgId: string;
    let projectId: string | undefined;
    let teamId: string | undefined;
    let successRedirect: string | undefined;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
      orgId = stateData.orgId;
      projectId = stateData.projectId;
      teamId = stateData.teamId;
      successRedirect = stateData.successRedirect;
      if (!projectId && !teamId && successRedirect) {
        const teamMatch = successRedirect.match(/\/organizations\/[^/]+\/teams\/([^/]+)\/settings\/notifications/);
        const projectMatch = successRedirect.match(/\/organizations\/[^/]+\/projects\/([^/]+)\/settings/);
        if (teamMatch) teamId = teamMatch[1];
        else if (projectMatch) projectId = projectMatch[1];
      }
    } catch {
      return res.redirect(`${frontendUrl}?error=discord&message=Invalid state`);
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();
    if (!membership) {
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=discord&message=Not authorized`);
    }

    const backendUrl = (process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`).replace(/\/$/, '');
    const redirectUri = `${backendUrl}/api/integrations/discord/org-callback`;

    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID!,
        client_secret: process.env.DISCORD_CLIENT_SECRET!,
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: redirectUri,
      }),
    });
    const tokenData = await tokenRes.json() as any;

    if (tokenData.error) {
      console.error('Discord OAuth error:', tokenData.error);
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=discord&message=${encodeURIComponent(tokenData.error_description || tokenData.error || 'Unknown error')}`);
    }

    const guildId = (req.query.guild_id as string) || null;
    let displayName = 'Discord Server';
    if (guildId) {
      const botToken = process.env.DISCORD_BOT_TOKEN || tokenData.access_token;
      try {
        const guildRes = await fetch(`https://discord.com/api/v10/guilds/${guildId}`, {
          headers: { Authorization: `Bot ${botToken}` },
        });
        if (guildRes.ok) {
          const guild = await guildRes.json() as { name?: string };
          if (guild.name) displayName = guild.name;
        }
      } catch (_) {
        // ignore - falls back to "Discord Server"
      }
    }

    const discordInsert = {
      provider: 'discord',
      installation_id: guildId,
      display_name: displayName,
      access_token: tokenData.access_token,
      status: 'connected',
      metadata: {
        guild_id: guildId,
        guild_name: displayName,
        scope: tokenData.scope,
      },
      connected_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    } as any;

    const redirectOnSuccess = successRedirect || `${frontendUrl}/organizations/${orgId}/settings/integrations?connected=discord`;

    if (projectId) {
      const { data: proj } = await supabase.from('projects').select('id').eq('id', projectId).eq('organization_id', orgId).single();
      if (!proj) {
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=discord&message=Project not found`);
      }
      const { error: dbError } = await supabase.from('project_integrations').insert({ project_id: projectId, ...discordInsert });
      if (dbError) {
        console.error('Discord project integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/projects/${projectId}/settings?error=discord&message=Failed to save integration`);
      }
      res.redirect(redirectOnSuccess);
    } else if (teamId) {
      const { data: team } = await supabase.from('teams').select('id').eq('id', teamId).eq('organization_id', orgId).single();
      if (!team) {
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=discord&message=Team not found`);
      }
      const { error: dbError } = await supabase.from('team_integrations').insert({ team_id: teamId, ...discordInsert });
      if (dbError) {
        console.error('Discord team integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/teams/${teamId}/settings/notifications?error=discord&message=Failed to save integration`);
      }
      res.redirect(redirectOnSuccess);
    } else {
      const { error: dbError } = await supabase.from('organization_integrations').insert({ organization_id: orgId, ...discordInsert });
      if (dbError) {
        console.error('Discord org integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=discord&message=Failed to save integration`);
      }
      try { await emitEvent({ type: 'integration_connected', organizationId: orgId, payload: { provider: 'discord', displayName }, source: 'system', priority: 'normal' }); } catch (e) {}
      res.redirect(redirectOnSuccess);
    }
  } catch (err: any) {
    console.error('Discord org callback error:', err);
    const f = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(`${f.replace(/\/$/, '')}/organizations?error=discord&message=${encodeURIComponent(err.message || 'Unknown error')}`);
  }
});

// Initiate Jira OAuth
router.get('/jira/connect', authenticateUser, async (req: AuthRequest, res) => {
  const clientId = process.env.JIRA_CLIENT_ID;
  const backendUrl = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
  const redirectUri = `${backendUrl}/api/integrations/jira/callback`;
  const scopes = 'read:jira-work write:jira-work read:jira-user manage:jira-project';
  
  if (!clientId) {
    return res.status(500).json({ error: 'Jira client ID not configured' });
  }
  
  // Store user ID in state for security
  const state = Buffer.from(JSON.stringify({ userId: req.user!.id })).toString('base64');
  
  // Jira uses Atlassian OAuth endpoint
  // Users will authorize access to their Jira site during the flow
  const authUrl = `https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=${clientId}&scope=${encodeURIComponent(scopes)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&response_type=code&prompt=consent`;
  
  // Return the redirect URL as JSON so frontend can handle it
  res.json({ redirectUrl: authUrl });
});

// Handle Jira OAuth callback
router.get('/jira/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  if (error) {
    return res.redirect(`${process.env.FRONTEND_URL}/settings?error=jira&message=${encodeURIComponent(error as string)}`);
  }
  
  if (!code) {
    return res.redirect(`${process.env.FRONTEND_URL}/settings?error=jira&message=No authorization code`);
  }
  
  try {
    // Decode state to get user ID
    let userId: string;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
    } catch {
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=jira&message=Invalid state`);
    }
    
    // Reconstruct redirect URI (must match exactly what was used in the initial request)
    const backendUrl = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
    const redirectUri = `${backendUrl}/api/integrations/jira/callback`;
    
    // Exchange code for token
    const response = await fetch('https://auth.atlassian.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: process.env.JIRA_CLIENT_ID!,
        client_secret: process.env.JIRA_CLIENT_SECRET!,
        code: code as string,
        redirect_uri: redirectUri,
      }),
    });
    
    const data = await response.json() as any;
    
    if (data.error) {
      console.error('Jira OAuth error:', data.error);
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=jira&message=${encodeURIComponent(data.error_description || data.error || 'Unknown error')}`);
    }
    
    // Get user info and accessible sites from Jira
    // First, get accessible sites (cloud IDs)
    const sitesResponse = await fetch('https://api.atlassian.com/oauth/token/accessible-resources', {
      headers: {
        'Authorization': `Bearer ${data.access_token}`,
        'Accept': 'application/json',
      },
    });
    
    const sites = await sitesResponse.json() as Array<{ id: string; name: string; url: string }>;
    
    if (!sites || sites.length === 0) {
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=jira&message=No accessible Jira sites found`);
    }
    
    // Use the first accessible site (user can have multiple)
    const primarySite = sites[0];
    
    // Get user info
    const userResponse = await fetch(`https://api.atlassian.com/ex/jira/${primarySite.id}/rest/api/3/myself`, {
      headers: {
        'Authorization': `Bearer ${data.access_token}`,
        'Accept': 'application/json',
      },
    });
    
    const userData = await userResponse.json() as { accountId: string; displayName?: string; emailAddress?: string };
    
    // Store tokens in database
    const { error: dbError } = await (supabase
      .from('user_integrations')
      .upsert({
        user_id: userId,
        provider: 'jira',
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        team_id: primarySite.id, // Jira cloud ID
        team_name: primarySite.name, // Jira site name
        provider_user_id: userData.accountId,
        provider_username: userData.displayName || userData.emailAddress,
        metadata: {
          cloud_id: primarySite.id,
          site_name: primarySite.name,
          url: primarySite.url,
          scopes: data.scope,
          all_sites: sites, // Store all accessible sites
        },
        updated_at: new Date().toISOString(),
      } as any, {
        onConflict: 'user_id,provider'
      }));
    
    if (dbError) {
      console.error('Database error:', dbError);
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=jira&message=Failed to save integration`);
    }
    
    res.redirect(`${process.env.FRONTEND_URL}/settings?connected=jira`);
  } catch (error: any) {
    console.error('Jira OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/settings?error=jira&message=${encodeURIComponent(error.message || 'Unknown error')}`);
  }
});

// Initiate GitLab OAuth
router.get('/gitlab/connect', authenticateUser, async (req: AuthRequest, res) => {
  const clientId = process.env.GITLAB_CLIENT_ID;
  const backendUrl = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
  const redirectUri = `${backendUrl}/api/integrations/gitlab/callback`;
  const scopes = 'api read_user read_repository write_repository';
  const gitlabUrl = process.env.GITLAB_URL || 'https://gitlab.com';
  
  if (!clientId) {
    return res.status(500).json({ error: 'GitLab client ID not configured' });
  }
  
  // Store user ID in state for security
  const state = Buffer.from(JSON.stringify({ userId: req.user!.id })).toString('base64');
  
  const authUrl = `${gitlabUrl}/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent(scopes)}&state=${encodeURIComponent(state)}`;
  
  // Return the redirect URL as JSON so frontend can handle it
  res.json({ redirectUrl: authUrl });
});

// Handle GitLab OAuth callback
router.get('/gitlab/callback', async (req, res) => {
  const { code, state, error } = req.query;
  const gitlabUrl = process.env.GITLAB_URL || 'https://gitlab.com';
  
  if (error) {
    return res.redirect(`${process.env.FRONTEND_URL}/settings?error=gitlab&message=${encodeURIComponent(error as string)}`);
  }
  
  if (!code) {
    return res.redirect(`${process.env.FRONTEND_URL}/settings?error=gitlab&message=No authorization code`);
  }
  
  try {
    // Decode state to get user ID
    let userId: string;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
    } catch {
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=gitlab&message=Invalid state`);
    }
    
    // Reconstruct redirect URI (must match exactly what was used in the initial request)
    const backendUrl = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
    const redirectUri = `${backendUrl}/api/integrations/gitlab/callback`;
    
    // Exchange code for token
    const response = await fetch(`${gitlabUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.GITLAB_CLIENT_ID!,
        client_secret: process.env.GITLAB_CLIENT_SECRET!,
        code: code as string,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri,
      }),
    });
    
    const data = await response.json() as any;
    
    if (data.error) {
      console.error('GitLab OAuth error:', data.error);
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=gitlab&message=${encodeURIComponent(data.error_description || data.error || 'Unknown error')}`);
    }
    
    // Get user info
    const userResponse = await fetch(`${gitlabUrl}/api/v4/user`, {
      headers: {
        'Authorization': `Bearer ${data.access_token}`,
      },
    });
    const userData = await userResponse.json() as any;
    
    // Store tokens in database
    const { error: dbError } = await (supabase
      .from('user_integrations')
      .upsert({
        user_id: userId,
        provider: 'gitlab',
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        provider_user_id: userData.id.toString(),
        provider_username: userData.username,
        metadata: {
          name: userData.name,
          email: userData.email,
          avatar_url: userData.avatar_url,
          scope: data.scope,
        },
        updated_at: new Date().toISOString(),
      } as any, {
        onConflict: 'user_id,provider'
      }));
    
    if (dbError) {
      console.error('Database error:', dbError);
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=gitlab&message=Failed to save integration`);
    }
    
    res.redirect(`${process.env.FRONTEND_URL}/settings?connected=gitlab`);
  } catch (error: any) {
    console.error('GitLab OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/settings?error=gitlab&message=${encodeURIComponent(error.message || 'Unknown error')}`);
  }
});

// Connect Linear with API key (Linear uses API keys, not OAuth)
router.post('/linear/connect', authenticateUser, async (req: AuthRequest, res) => {
  const { apiKey } = req.body;
  
  if (!apiKey || typeof apiKey !== 'string') {
    return res.status(400).json({ error: 'API key is required' });
  }
  
  try {
    // Verify API key by making a test request to Linear's GraphQL API
    const response = await fetch('https://api.linear.app/graphql', {
      method: 'POST',
      headers: {
        'Authorization': apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query: '{ viewer { id name email } }',
      }),
    });
    
    const data = await response.json() as any;
    
    if (data.errors || !data.data?.viewer) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    const viewer = data.data.viewer;
    
    // Store API key in database (stored as access_token)
    const { error: dbError } = await (supabase
      .from('user_integrations')
      .upsert({
        user_id: req.user!.id,
        provider: 'linear',
        access_token: apiKey, // Store API key as access_token
        provider_user_id: viewer.id,
        provider_username: viewer.name || viewer.email,
        metadata: {
          name: viewer.name,
          email: viewer.email,
        },
        updated_at: new Date().toISOString(),
      } as any, {
        onConflict: 'user_id,provider'
      }));
    
    if (dbError) {
      console.error('Database error:', dbError);
      return res.status(500).json({ error: 'Failed to save integration' });
    }
    
    res.json({ success: true });
  } catch (error: any) {
    console.error('Linear API key verification error:', error);
    res.status(500).json({ error: error.message || 'Failed to verify API key' });
  }
});

// Initiate Stripe OAuth Connect
router.get('/stripe/connect', authenticateUser, async (req: AuthRequest, res) => {
  const clientId = process.env.STRIPE_CLIENT_ID;
  const backendUrl = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
  const redirectUri = `${backendUrl}/api/integrations/stripe/callback`;
  
  if (!clientId) {
    return res.status(500).json({ error: 'Stripe client ID not configured' });
  }
  
  // Store user ID in state for security
  const state = Buffer.from(JSON.stringify({ userId: req.user!.id })).toString('base64');
  
  // Stripe OAuth Connect URL
  // Use 'read_write' scope to allow full access to the connected account
  const authUrl = `https://connect.stripe.com/oauth/authorize?response_type=code&client_id=${clientId}&scope=read_write&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
  
  // Return the redirect URL as JSON so frontend can handle it
  res.json({ redirectUrl: authUrl });
});

// Handle Stripe OAuth callback
router.get('/stripe/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  if (error) {
    return res.redirect(`${process.env.FRONTEND_URL}/settings?error=stripe&message=${encodeURIComponent(error as string)}`);
  }
  
  if (!code) {
    return res.redirect(`${process.env.FRONTEND_URL}/settings?error=stripe&message=No authorization code`);
  }
  
  try {
    // Decode state to get user ID
    let userId: string;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
    } catch {
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=stripe&message=Invalid state`);
    }
    
    // Exchange code for access token
    const response = await fetch('https://connect.stripe.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: process.env.STRIPE_CLIENT_ID!,
        client_secret: process.env.STRIPE_SECRET_KEY!,
        code: code as string,
      }),
    });
    
    const data = await response.json() as any;
    
    if (data.error) {
      console.error('Stripe OAuth error:', data.error);
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=stripe&message=${encodeURIComponent(data.error_description || data.error || 'Unknown error')}`);
    }
    
    // Get account info from Stripe
    const accountResponse = await fetch(`https://api.stripe.com/v1/accounts/${data.stripe_user_id}`, {
      headers: {
        'Authorization': `Bearer ${process.env.STRIPE_SECRET_KEY}`,
      },
    });
    const accountData = await accountResponse.json() as any;
    
    // Store tokens in database
    const { error: dbError } = await (supabase
      .from('user_integrations')
      .upsert({
        user_id: userId,
        provider: 'stripe',
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        provider_user_id: data.stripe_user_id, // Stripe account ID
        provider_username: accountData.business_profile?.name || accountData.email || 'Stripe Account',
        team_id: data.stripe_user_id,
        team_name: accountData.business_profile?.name || accountData.email || 'Stripe Account',
        metadata: {
          stripe_user_id: data.stripe_user_id,
          stripe_publishable_key: data.stripe_publishable_key,
          scope: data.scope,
          livemode: data.livemode,
        },
        updated_at: new Date().toISOString(),
      } as any, {
        onConflict: 'user_id,provider'
      }));
    
    if (dbError) {
      console.error('Database error:', dbError);
      return res.redirect(`${process.env.FRONTEND_URL}/settings?error=stripe&message=Failed to save integration`);
    }
    
    res.redirect(`${process.env.FRONTEND_URL}/settings?connected=stripe`);
  } catch (error: any) {
    console.error('Stripe OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/settings?error=stripe&message=${encodeURIComponent(error.message || 'Unknown error')}`);
  }
});

// ============================================
// ORGANIZATION-LEVEL INTEGRATIONS (GitHub App, etc.)
// ============================================

// Get organization integrations
router.get('/organizations/:orgId/integrations', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { orgId } = req.params;
    
    // Verify user is a member of the organization
    const { data: membership, error: memberError } = await supabase
      .from('organization_members')
      .select('*')
      .eq('organization_id', orgId)
      .eq('user_id', req.user!.id)
      .single();
    
    if (memberError || !membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    
    // Get organization integrations
    const { data, error } = await supabase
      .from('organization_integrations')
      .select('*')
      .eq('organization_id', orgId);
    
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    
    res.json(data || []);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// PRO DISCOVERY: List available GitHub App installations
// ============================================================
interface GitHubInstallation {
  id: number;
  account: {
    login: string;
    type: string;
    avatar_url: string;
  };
  app_id: number;
  target_type: string;
}

interface AvailableInstallation {
  id: number;
  account_login: string;
  account_type: string;
  account_avatar: string;
  is_connected_to_this_org: boolean;
  is_connected_elsewhere: boolean;
  connected_org_name?: string;
}

// GET /github/available-installations
// Lists GitHub App installations the user has access to
router.get('/github/available-installations', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { org_id, github_token } = req.query;
    
    if (!org_id || typeof org_id !== 'string') {
      return res.status(400).json({ error: 'Organization ID is required' });
    }
    
    if (!github_token || typeof github_token !== 'string') {
      return res.status(400).json({ 
        error: 'GitHub token required',
        code: 'GITHUB_TOKEN_REQUIRED',
        message: 'Please ensure you are logged in with GitHub to discover existing installations.'
      });
    }
    
    // Verify user is a member of the organization
    const { data: membership, error: memberError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', org_id)
      .eq('user_id', req.user!.id)
      .single();
    
    if (memberError || !membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    
    // Get our GitHub App ID
    const ourAppId = process.env.GITHUB_APP_ID;
    if (!ourAppId) {
      return res.status(500).json({ error: 'GitHub App not configured' });
    }
    
    // Call GitHub API to list user's installations
    const githubResponse = await fetch('https://api.github.com/user/installations', {
      headers: {
        'Authorization': `Bearer ${github_token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'Deptex-App',
      },
    });
    
    if (!githubResponse.ok) {
      const errorText = await githubResponse.text();
      console.error('GitHub API error:', githubResponse.status, errorText);
      
      if (githubResponse.status === 401) {
        return res.status(401).json({ 
          error: 'GitHub token expired or invalid',
          code: 'GITHUB_TOKEN_INVALID',
          message: 'Your GitHub session has expired. Please re-authenticate with GitHub.'
        });
      }
      
      return res.status(githubResponse.status).json({ 
        error: 'Failed to fetch GitHub installations',
        details: errorText
      });
    }
    
    const data = await githubResponse.json() as { installations: GitHubInstallation[] };
    const allInstallations = data.installations || [];
    
    // Filter to only our app's installations
    const ourInstallations = allInstallations.filter(
      inst => inst.app_id.toString() === ourAppId
    );
    
    if (ourInstallations.length === 0) {
      return res.json({ 
        installations: [],
        message: 'No existing installations found for this GitHub App.'
      });
    }
    
    // Cross-reference with our database to check connections
    const installationIds = ourInstallations.map(i => i.id.toString());
    
    const { data: connectedOrgs, error: dbError } = await supabase
      .from('organizations')
      .select('id, name, github_installation_id')
      .in('github_installation_id', installationIds);
    
    if (dbError) {
      console.error('Database error:', dbError);
    }
    
    // Build connection map
    const connectionMap = new Map<string, { orgId: string; orgName: string }>();
    (connectedOrgs || []).forEach(org => {
      if (org.github_installation_id) {
        connectionMap.set(org.github_installation_id, {
          orgId: org.id,
          orgName: org.name,
        });
      }
    });
    
    // Build response
    const availableInstallations: AvailableInstallation[] = ourInstallations.map(inst => {
      const instIdStr = inst.id.toString();
      const connection = connectionMap.get(instIdStr);
      
      return {
        id: inst.id,
        account_login: inst.account.login,
        account_type: inst.account.type,
        account_avatar: inst.account.avatar_url,
        is_connected_to_this_org: connection?.orgId === org_id,
        is_connected_elsewhere: connection ? connection.orgId !== org_id : false,
        connected_org_name: connection?.orgId !== org_id ? connection?.orgName : undefined,
      };
    });
    
    res.json({ installations: availableInstallations });
  } catch (error: any) {
    console.error('Error fetching available installations:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /github/connect-installation
// Connect an existing GitHub App installation to an organization
router.post('/github/connect-installation', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { org_id, installation_id, account_login, account_type } = req.body;
    
    if (!org_id || !installation_id) {
      return res.status(400).json({ error: 'Organization ID and installation ID are required' });
    }
    
    // Verify user is a member of the organization
    const { data: membership, error: memberError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', org_id)
      .eq('user_id', req.user!.id)
      .single();
    
    if (memberError || !membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    
    // TODO: Check manage_integrations permission
    
    // Check if this installation is already connected elsewhere (double-install prevention)
    const { data: existingOrg, error: existingError } = await supabase
      .from('organizations')
      .select('id, name')
      .eq('github_installation_id', installation_id.toString())
      .single();
    
    if (existingOrg && existingOrg.id !== org_id) {
      return res.status(409).json({
        error: 'Installation already connected',
        code: 'ALREADY_CONNECTED',
        message: `This GitHub account is already connected to "${existingOrg.name}". Please disconnect it there first.`,
        connected_org_name: existingOrg.name,
      });
    }
    
    // Update organization with installation_id
    const { error: updateError } = await supabase
      .from('organizations')
      .update({
        github_installation_id: installation_id.toString(),
        updated_at: new Date().toISOString(),
      })
      .eq('id', org_id);
    
    if (updateError) {
      console.error('Failed to update organization:', updateError);
      
      // Check if it's a unique constraint violation
      if (updateError.code === '23505') {
        return res.status(409).json({
          error: 'Installation already connected to another organization',
          code: 'ALREADY_CONNECTED',
        });
      }
      
      return res.status(500).json({ error: 'Failed to connect installation' });
    }
    
    // Store in organization_integrations table
    const { error: integrationError } = await supabase
      .from('organization_integrations')
      .upsert({
        organization_id: org_id,
        provider: 'github',
        installation_id: installation_id.toString(),
        status: 'connected',
        metadata: {
          account_login: account_login,
          account_type: account_type,
          connected_via: 'pro_discovery',
        },
        connected_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      } as any, {
        onConflict: 'organization_id,provider'
      });
    
    if (integrationError) {
      console.error('Failed to store integration:', integrationError);
    }
    
    console.log('GitHub installation connected via Pro Discovery:', {
      org_id,
      installation_id,
      account_login,
    });
    
    res.json({ 
      success: true,
      message: 'GitHub App connected successfully',
    });
  } catch (error: any) {
    console.error('Error connecting installation:', error);
    res.status(500).json({ error: error.message });
  }
});

// Initiate GitHub App installation
// Returns the GitHub App installation URL as JSON (frontend will redirect)
router.get('/github/install', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { org_id } = req.query;
    
    if (!org_id || typeof org_id !== 'string') {
      return res.status(400).json({ error: 'Organization ID is required' });
    }
    
    // Verify user is a member of the organization
    const { data: membership, error: memberError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', org_id)
      .eq('user_id', req.user!.id)
      .single();
    
    if (memberError || !membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    
    // TODO: Check permissions via organization_roles table
    // For now, we'll let the frontend handle the permission check
    
    // Get GitHub App name from environment
    const githubAppName = process.env.GITHUB_APP_NAME || 'deptex';
    
    if (!githubAppName || githubAppName === 'deptex') {
      console.warn('GITHUB_APP_NAME not set in environment variables. Using default "deptex".');
    }
    
    // Store org_id in state for callback
    const state = Buffer.from(JSON.stringify({ 
      userId: req.user!.id, 
      orgId: org_id 
    })).toString('base64');
    
    // GitHub App installation URL
    // The user will select repositories and complete the installation
    const installUrl = `https://github.com/apps/${githubAppName}/installations/new?state=${encodeURIComponent(state)}`;
    
    // Return URL as JSON so frontend can redirect with proper auth
    res.json({ redirectUrl: installUrl });
  } catch (error: any) {
    console.error('GitHub App install error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GitHub App installation callback (Setup URL)
// This is called by GitHub after the user completes the installation
router.get('/github/callback', async (req, res) => {
  const frontendUrl = getFrontendUrl();
  try {
    const { installation_id, setup_action, state } = req.query;

    console.log('GitHub App callback received:', { installation_id, setup_action, state, query: req.query });

    if (!installation_id) {
      console.error('GitHub callback missing installation_id');
      return res.redirect(`${frontendUrl}?error=github&message=No installation ID received`);
    }
    
    // Decode state to get user ID and org ID
    let userId: string;
    let orgId: string;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
      orgId = stateData.orgId;
    } catch {
      return res.redirect(`${frontendUrl}?error=github&message=Invalid state parameter`);
    }
    
    // Verify user is still a member of the organization
    const { data: membership, error: memberError } = await supabase
      .from('organization_members')
      .select('*')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();
    
    if (memberError || !membership) {
      return res.redirect(`${frontendUrl}?error=github&message=Not authorized to add integration`);
    }
    
    // Same GitHub installation can be connected to multiple orgs; no double-install block.
    // Fetch GitHub account login and avatar for display (e.g. "deptex" + avatar instead of "GitHub #112215649")
    let githubAccountLogin: string | null = null;
    let githubAccountType: string | null = null;
    let githubAccountAvatarUrl: string | null = null;
    try {
      const installationAccount = await getInstallationAccount(installation_id as string);
      if (installationAccount?.login) {
        githubAccountLogin = installationAccount.login;
        githubAccountType = installationAccount.account_type ?? null;
        githubAccountAvatarUrl = installationAccount.avatar_url ?? null;
      }
    } catch (fetchError) {
      console.warn('Could not fetch GitHub account info:', fetchError);
    }
    
    // ============================================================
    // Update organization with installation_id
    // ============================================================
    const { error: orgUpdateError } = await supabase
      .from('organizations')
      .update({ 
        github_installation_id: installation_id as string,
        updated_at: new Date().toISOString()
      })
      .eq('id', orgId);
    
    if (orgUpdateError) {
      console.error('Failed to update organization:', orgUpdateError);
      
      // Check if it's a unique constraint violation
      if (orgUpdateError.code === '23505') {
        const errorMessage = encodeURIComponent(
          'This GitHub account is already connected to another Deptex Organization.'
        );
        return res.redirect(
          `${frontendUrl}/organizations/${orgId}/settings/integrations?error=github&message=${errorMessage}`
        );
      }
      
      return res.redirect(
        `${frontendUrl}/organizations/${orgId}/settings/integrations?error=github&message=Failed to save installation`
      );
    }
    
    // Store in organization_integrations table. Multiple GitHub apps per org = always INSERT a new row.
    const payload = {
      organization_id: orgId,
      provider: 'github',
      installation_id: installation_id as string,
      display_name: githubAccountLogin || `GitHub #${installation_id}`,
      status: 'connected',
      metadata: {
        setup_action: setup_action,
        account_login: githubAccountLogin,
        account_type: githubAccountType,
        account_avatar_url: githubAccountAvatarUrl,
      },
      connected_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    } as any;

    const { error: integrationError } = await supabase
      .from('organization_integrations')
      .insert(payload);
    if (integrationError) {
      console.error('Failed to store integration:', integrationError);
      const errMsg = encodeURIComponent(integrationError.message || 'Failed to save connection');
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=github&message=${errMsg}`);
    }

    console.log('GitHub App installation successful:', { orgId, installation_id });

    try {
      await emitEvent({ type: 'integration_connected', organizationId: orgId, payload: { provider: 'github', displayName: githubAccountLogin || `GitHub #${installation_id}` }, source: 'system', priority: 'normal' });
    } catch (e) {}

    const redirectUrl = `${frontendUrl}/organizations/${orgId}/settings/integrations?connected=github`;
    res.redirect(redirectUrl);
  } catch (error: any) {
    console.error('GitHub App callback error:', error);
    res.redirect(`${getFrontendUrl()}?error=github&message=${encodeURIComponent(error.message || 'Unknown error')}`);
  }
});

// Disconnect GitHub App from organization
// Note: This only removes it from our database. User must uninstall from GitHub manually.
router.delete('/organizations/:orgId/integrations/github', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { orgId } = req.params;
    
    // Verify user has manage_integrations permission
    const { data: membership, error: memberError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', req.user!.id)
      .single();
    
    if (memberError || !membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    
    // TODO: Check permissions via organization_roles table
    
    // Get the installation_id before removing it (to return in response)
    const { data: orgData } = await supabase
      .from('organizations')
      .select('github_installation_id')
      .eq('id', orgId)
      .single();
    
    const installationId = orgData?.github_installation_id;
    
    // Remove installation_id from organization
    const { error: orgUpdateError } = await supabase
      .from('organizations')
      .update({ 
        github_installation_id: null,
        updated_at: new Date().toISOString()
      })
      .eq('id', orgId);
    
    if (orgUpdateError) {
      return res.status(500).json({ error: orgUpdateError.message });
    }
    
    // Update organization_integrations table
    const { error: integrationError } = await supabase
      .from('organization_integrations')
      .update({
        status: 'disconnected',
        updated_at: new Date().toISOString(),
      })
      .eq('organization_id', orgId)
      .eq('provider', 'github');
    
    if (integrationError) {
      console.error('Failed to update integration status:', integrationError);
    }
    
    try { await emitEvent({ type: 'integration_disconnected', organizationId: orgId, payload: { provider: 'github' }, source: 'system', priority: 'normal' }); } catch (e) {}

    // Return installation_id so frontend can open GitHub's uninstall page
    res.json({ success: true, installationId });
  } catch (error: any) {
    console.error('GitHub App disconnect error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// Push event: intelligent extraction based on manifest changes + sync_frequency
// Phase 8B: Complete rewrite with change detection, commit tracking, concurrency caps
// ============================================================
type PushProjectRow = {
  project_id: string;
  default_branch: string;
  package_json_path: string | null;
  installation_id: string;
  sync_frequency: string;
  status: string;
  projects: { organization_id: string }[] | { organization_id: string } | null;
};

async function handlePushEvent(payload: any): Promise<void> {
  const repoFullName = payload.repository?.full_name;
  const ref = payload.ref;
  const installationId = payload.installation?.id;
  const before = payload.before;
  const after = payload.after;

  if (!repoFullName || !ref || !installationId) {
    console.log('[webhook push] Missing repository.full_name, ref, or installation.id; skipping.');
    return;
  }
  if (!after || /^0+$/.test(String(after))) return;

  const { data: rows, error: fetchError } = await supabase
    .from('project_repositories')
    .select('project_id, default_branch, package_json_path, installation_id, sync_frequency, status, projects(organization_id)')
    .eq('repo_full_name', repoFullName)
    .eq('installation_id', String(installationId));

  if (fetchError) {
    console.error('[webhook push] Failed to fetch project_repositories:', fetchError);
    return;
  }

  const expectedRef = (branch: string) => `refs/heads/${branch}`;
  const rowList = (rows ?? []) as PushProjectRow[];

  // 8B.6: Stale default_branch guard
  const payloadDefaultBranch = payload.repository?.default_branch;
  if (payloadDefaultBranch) {
    for (const r of rowList) {
      if (r.default_branch && r.default_branch !== payloadDefaultBranch) {
        await supabase.from('project_repositories')
          .update({ default_branch: payloadDefaultBranch, updated_at: new Date().toISOString() })
          .eq('project_id', r.project_id);
        r.default_branch = payloadDefaultBranch;
      }
    }
  }

  const activeStatuses = ['pending', 'initializing', 'ready', 'error', 'cancelled'];
  const projects = rowList.filter(
    (r) => r.default_branch && ref === expectedRef(r.default_branch) && activeStatuses.includes(r.status)
  );
  if (projects.length === 0) return;

  let changedFiles: string[] = [];
  let forceFullExtraction = false;
  try {
    const token = await createInstallationToken(String(installationId));
    changedFiles = await getCompareChangedFiles(token, repoFullName, before, after);
  } catch (err: any) {
    if (err?.message?.includes('422') || err?.message?.includes('404')) {
      console.warn('[webhook push] Force push detected, falling back to full extraction');
      forceFullExtraction = true;
    } else {
      console.error('[webhook push] Compare API failed:', err?.message);
    }
  }

  const affectedWorkspaces = detectAffectedWorkspaces(changedFiles);
  const rootManifestChanged = affectedWorkspaces.has('');

  let extractionCount = 0;

  for (const row of projects) {
    const proj = row.projects;
    const organizationId = Array.isArray(proj) ? proj[0]?.organization_id : proj?.organization_id;
    if (!organizationId) continue;

    const workspace = (row.package_json_path ?? '').trim();
    const workspaceChanged = affectedWorkspaces.has(workspace);
    const isAffected = forceFullExtraction || workspaceChanged || (rootManifestChanged && workspace !== '');

    let extractionTriggered = false;

    if (isAffected && row.sync_frequency === 'on_commit') {
      if (extractionCount < MAX_EXTRACTION_PER_PUSH) {
        try {
          const result = await queueExtractionJob(row.project_id, organizationId, row as any);
          if (result.success) {
            extractionCount++;
            extractionTriggered = true;
            console.log('[webhook push] Queued extraction for project', row.project_id);
          }
        } catch (err: any) {
          console.error('[webhook push] Extraction queue failed for project', row.project_id, err?.message);
        }
      } else {
        console.warn(`[webhook push] Per-org cap reached (${MAX_EXTRACTION_PER_PUSH}), skipping extraction for project`, row.project_id);
      }
    }

    if (!extractionTriggered) {
      const anyFileInWorkspace = changedFiles.some((f) => isFileInWorkspace(f, workspace));
      if (anyFileInWorkspace) {
        await queueASTParsingJob(row.project_id, {
          repo_full_name: repoFullName,
          installation_id: String(installationId),
          default_branch: row.default_branch,
          package_json_path: workspace,
        }).catch((err: any) => {
          console.warn('[webhook push] AST job not queued for project', row.project_id, err?.message);
        });
      }
    }

    // 8C: Record commits
    const commits = payload.commits ?? [];
    for (const c of commits) {
      const commitSha = c.id || c.sha;
      if (!commitSha) continue;
      const manifestChanged = (c.added ?? []).concat(c.modified ?? [], c.removed ?? []).some(
        (f: string) => {
          const match = detectAffectedWorkspaces([f]);
          return match.size > 0;
        }
      );
      await supabase.from('project_commits').upsert({
        project_id: row.project_id,
        sha: commitSha,
        message: (c.message || '').slice(0, 10000),
        author_name: c.author?.name,
        author_email: c.author?.email,
        author_avatar_url: c.author?.avatar_url,
        committed_at: c.timestamp,
        manifest_changed: manifestChanged,
        extraction_triggered: extractionTriggered,
        extraction_status: extractionTriggered ? 'queued' : 'skipped',
        files_changed: (c.added?.length ?? 0) + (c.modified?.length ?? 0) + (c.removed?.length ?? 0),
        provider: 'github',
        provider_url: c.url,
      }, { onConflict: 'project_id,sha' }).catch((err: any) => {
        console.warn('[webhook push] Commit record failed:', err?.message);
      });
    }

    // Update webhook health
    await supabase.from('project_repositories').update({
      last_webhook_at: new Date().toISOString(),
      last_webhook_event: 'push',
      webhook_status: 'active',
    }).eq('project_id', row.project_id);

    await invalidateProjectCaches(organizationId, row.project_id).catch(() => {});
  }
}

function verifyGitHubWebhookSignature(req: express.Request): boolean {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === 'production') {
      console.error('CRITICAL: GITHUB_WEBHOOK_SECRET not set in production. Rejecting webhook.');
      return false;
    }
    console.warn('GITHUB_WEBHOOK_SECRET not set; skipping verification (dev mode only).');
    return true;
  }
  const signature = req.headers['x-hub-signature-256'] as string | undefined;
  if (!signature || !signature.startsWith('sha256=')) return false;
  const rawBody = (req as any).rawBody;
  if (typeof rawBody !== 'string') return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(signature, 'utf8'), Buffer.from(expected, 'utf8'));
  } catch {
    return false;
  }
}

async function deduplicateWebhookDelivery(deliveryId: string | undefined): Promise<boolean> {
  if (!deliveryId) return false;
  try {
    const { Redis } = await import('@upstash/redis');
    const redis = new Redis({
      url: process.env.UPSTASH_REDIS_URL!,
      token: process.env.UPSTASH_REDIS_TOKEN!,
    });
    const key = `webhook-delivery:${deliveryId}`;
    const existing = await redis.get(key);
    if (existing) return true;
    await redis.set(key, '1', { ex: 3600 });
    return false;
  } catch {
    return false;
  }
}

async function recordWebhookDelivery(
  deliveryId: string | undefined,
  eventType: string,
  action: string | undefined,
  repoFullName: string | null,
  installationId: string | undefined,
  payloadSize: number,
  status: string = 'received'
) {
  try {
    await supabase.from('webhook_deliveries').insert({
      delivery_id: deliveryId || 'unknown',
      provider: 'github',
      event_type: eventType,
      action,
      repo_full_name: repoFullName,
      installation_id: installationId,
      processing_status: status,
      payload_size_bytes: payloadSize,
    });
  } catch {}
}

async function updateWebhookDeliveryStatus(
  deliveryId: string | undefined,
  status: string,
  durationMs?: number,
  errorMessage?: string
) {
  if (!deliveryId) return;
  try {
    const update: Record<string, unknown> = { processing_status: status };
    if (durationMs !== undefined) update.processing_duration_ms = durationMs;
    if (errorMessage) update.error_message = errorMessage.slice(0, 500);
    await supabase.from('webhook_deliveries')
      .update(update)
      .eq('delivery_id', deliveryId)
      .eq('provider', 'github');
  } catch {}
}

export async function githubWebhookHandler(req: express.Request, res: express.Response) {
  try {
    // 8Q.2: Rate limiting
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const rl = await checkRateLimit(`webhook:github:${ip}`, 100, 60);
    if (!rl.allowed) {
      return res.status(429).json({ error: 'Rate limit exceeded' });
    }

    if (!verifyGitHubWebhookSignature(req)) {
      res.status(401).json({ error: 'Invalid webhook signature' });
      return;
    }

    const event = req.headers['x-github-event'] as string;
    const deliveryId = req.headers['x-github-delivery'] as string | undefined;
    const payload = req.body;
    const payloadSize = Buffer.byteLength(JSON.stringify(payload));

    console.log('GitHub webhook received:', event, payload?.action || '');

    const startMs = Date.now();
    await recordWebhookDelivery(
      deliveryId, event, payload?.action,
      payload?.repository?.full_name,
      payload?.installation?.id?.toString(),
      payloadSize
    );

    // 8F.7: Deduplication
    if (await deduplicateWebhookDelivery(deliveryId)) {
      await updateWebhookDeliveryStatus(deliveryId, 'skipped');
      return res.json({ received: true, skipped: 'duplicate' });
    }

    res.json({ received: true });

    try {
      switch (event) {
        case 'installation':
          await handleInstallationEvent(payload);
          break;

        case 'installation_repositories':
          if (payload?.action === 'removed') {
            await handleInstallationReposRemovedEvent(payload);
          }
          break;

        case 'push':
          await handlePushEvent(payload);
          break;

        case 'pull_request':
          if (['opened', 'synchronize', 'reopened'].includes(payload?.action)) {
            await handlePullRequestEvent(payload);
          }
          if (payload?.action === 'closed') {
            await handlePullRequestClosedEvent(payload);
          }
          break;

        case 'repository':
          switch (payload?.action) {
            case 'deleted':
              await handleRepositoryDeletedEvent(payload);
              break;
            case 'renamed':
              await handleRepositoryRenamedEvent(payload);
              break;
            case 'transferred':
              await handleRepositoryTransferredEvent(payload);
              break;
            case 'edited':
              await handleRepositoryEditedEvent(payload);
              break;
            default:
              console.log('Repository event:', payload?.action, payload?.repository?.full_name);
          }
          break;

        default:
          console.log('Unhandled GitHub event:', event);
      }

      await updateWebhookDeliveryStatus(deliveryId, 'processed', Date.now() - startMs);
    } catch (err: any) {
      console.error('GitHub webhook processing error:', err?.message);
      await updateWebhookDeliveryStatus(deliveryId, 'error', Date.now() - startMs, err?.message);
    }
  } catch (error: any) {
    console.error('GitHub webhook error:', error);
    res.status(200).json({ received: true, error: error.message });
  }
}

// 8P: Repository Lifecycle Event Handlers
async function handleRepositoryDeletedEvent(payload: any) {
  const repoFullName = payload.repository?.full_name;
  if (!repoFullName) return;

  await supabase
    .from('project_repositories')
    .update({ status: 'repo_deleted', updated_at: new Date().toISOString() })
    .eq('repo_full_name', repoFullName);

  const { data: repos } = await supabase
    .from('project_repositories')
    .select('project_id')
    .eq('repo_full_name', repoFullName);

  for (const repo of repos || []) {
    await supabase
      .from('extraction_jobs')
      .update({ status: 'cancelled' })
      .eq('project_id', repo.project_id)
      .in('status', ['queued', 'processing']);
  }

  console.log(`[webhook] Repository deleted: ${repoFullName}. Marked ${repos?.length || 0} repos as repo_deleted.`);
}

async function handleRepositoryRenamedEvent(payload: any) {
  const oldName = payload.changes?.repository?.name?.from;
  const newFullName = payload.repository?.full_name;
  const owner = payload.repository?.owner?.login;
  if (!oldName || !newFullName || !owner) return;

  const oldFullName = `${owner}/${oldName}`;
  const { data } = await supabase
    .from('project_repositories')
    .update({ repo_full_name: newFullName, updated_at: new Date().toISOString() })
    .eq('repo_full_name', oldFullName)
    .select('id');

  console.log(`[webhook] Repository renamed: ${oldFullName} -> ${newFullName}. Updated ${data?.length || 0} repos.`);
}

async function handleRepositoryTransferredEvent(payload: any) {
  const newFullName = payload.repository?.full_name;
  const changes = payload.changes;
  if (!newFullName || !changes) return;

  const oldOwner = changes.owner?.from?.user?.login || changes.owner?.from?.organization?.login;
  const oldName = payload.repository?.name;
  if (oldOwner && oldName) {
    const oldFullName = `${oldOwner}/${oldName}`;
    await supabase
      .from('project_repositories')
      .update({ repo_full_name: newFullName, updated_at: new Date().toISOString() })
      .eq('repo_full_name', oldFullName);
    console.log(`[webhook] Repository transferred: ${oldFullName} -> ${newFullName}`);
  }
}

async function handleRepositoryEditedEvent(payload: any) {
  const repoFullName = payload.repository?.full_name;
  const defaultBranchChange = payload.changes?.default_branch;
  if (!repoFullName || !defaultBranchChange) return;

  const newDefaultBranch = payload.repository?.default_branch;
  const { data } = await supabase
    .from('project_repositories')
    .update({ default_branch: newDefaultBranch, updated_at: new Date().toISOString() })
    .eq('repo_full_name', repoFullName)
    .select('id');

  console.log(`[webhook] Default branch changed for ${repoFullName}: ${defaultBranchChange.from} -> ${newDefaultBranch}. Updated ${data?.length || 0} repos.`);
}

async function handleInstallationReposRemovedEvent(payload: any) {
  const removedRepos = payload.repositories_removed || [];
  for (const repo of removedRepos) {
    await supabase
      .from('project_repositories')
      .update({ status: 'access_revoked', updated_at: new Date().toISOString() })
      .eq('repo_full_name', repo.full_name);
  }
  if (removedRepos.length > 0) {
    console.log(`[webhook] Installation repos removed: ${removedRepos.map((r: any) => r.full_name).join(', ')}`);
  }
}

// 8G.3: Handle PR closed/merged event
async function handlePullRequestClosedEvent(payload: any) {
  const repoFullName = payload?.repository?.full_name;
  const pr = payload?.pull_request;
  if (!repoFullName || !pr) return;

  const prNumber = pr.number;
  const isMerged = pr.merged === true;

  const { data: projectRows } = await supabase
    .from('project_repositories')
    .select('project_id')
    .eq('repo_full_name', repoFullName);

  for (const row of projectRows ?? []) {
    await supabase
      .from('project_pull_requests')
      .update({
        status: isMerged ? 'merged' : 'closed',
        ...(isMerged ? { merged_at: pr.merged_at || new Date().toISOString() } : { closed_at: pr.closed_at || new Date().toISOString() }),
        updated_at: new Date().toISOString(),
      })
      .eq('project_id', (row as any).project_id)
      .eq('pr_number', prNumber)
      .eq('provider', 'github');

    // Phase 7: Update AI fix job status when fix PR is merged/closed
    const fixStatus = isMerged ? 'merged' : 'pr_closed';
    await supabase
      .from('project_security_fixes')
      .update({ status: fixStatus, completed_at: new Date().toISOString() })
      .eq('project_id', (row as any).project_id)
      .eq('pr_number', prNumber)
      .eq('pr_provider', 'github')
      .in('status', ['completed']);

    // Phase 16: Update fix outcome on merge/close
    try {
      const { updateOutcomeOnMerge } = await import('../lib/learning/outcome-recorder');
      await updateOutcomeOnMerge(
        (row as any).project_id, prNumber, 'github',
        isMerged, isMerged ? (pr.merged_at || new Date().toISOString()) : undefined,
      );
    } catch { /* non-fatal */ }
  }

  console.log(`[webhook] PR #${prNumber} ${isMerged ? 'merged' : 'closed'} on ${repoFullName}`);
}

// Also mount on router for backwards compatibility
router.post('/webhooks/github', githubWebhookHandler);

// ============================================================
// PR Guardrails: helpers and handlePullRequestEvent
// ============================================================

/** Get direct dependency names and their resolved versions from package.json + lockfile. */
function getDirectDepsFromPackageJson(pkg: {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, spec] of Object.entries(pkg.dependencies || {})) {
    out[name] = spec;
  }
  for (const [name, spec] of Object.entries(pkg.devDependencies || {})) {
    if (!(name in out)) out[name] = spec;
  }
  return out;
}

/** Get resolved version for a direct dep from lockfile (v2/v3 packages or legacy dependencies). */
function getResolvedVersion(lockJson: any, name: string): string | null {
  const packages = lockJson?.packages || {};
  const root = packages[''] || {};
  const direct = { ...(root.dependencies || {}), ...(root.devDependencies || {}) };
  const spec = direct[name];
  if (!spec) return null;
  const nodePath = `node_modules/${name}`;
  const entry = packages[nodePath];
  if (entry?.version) return entry.version;
  const legacy = lockJson?.dependencies?.[name];
  return legacy?.version ?? null;
}

/** Build set of "name@version" from lockfile packages (for transitive diff). */
function getLockfilePackagesSet(lockJson: any): Set<string> {
  const set = new Set<string>();
  const packages = lockJson?.packages || {};
  for (const [pathKey, entry] of Object.entries(packages)) {
    if (pathKey === '' || !(pathKey as string).includes('node_modules/')) continue;
    const e = entry as { name?: string; version?: string };
    const name = e?.name || (pathKey as string).split('/node_modules/').pop() || '';
    const version = e?.version;
    if (name && version) set.add(`${name}@${version}`);
  }
  return set;
}

/** Get license for a package: from DB first, else npm registry. */
async function getLicenseForPackage(name: string, _version?: string | null): Promise<string | null> {
  const { data } = await supabase.from('dependencies').select('license').eq('name', name).single() as { data: { license: string | null } | null };
  if (data?.license) return data.license;
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
      headers: { Accept: 'application/json', 'User-Agent': 'Deptex-App' },
    });
    if (!res.ok) return null;
    const data2 = (await res.json()) as { license?: string | { type?: string }; [key: string]: unknown };
    const lic = data2?.license;
    if (typeof lic === 'string') return lic;
    if (lic?.type) return lic.type;
    return null;
  } catch {
    return null;
  }
}

async function handlePullRequestEvent(payload: any): Promise<void> {
  const repoFullName = payload?.repository?.full_name;
  const pr = payload?.pull_request;
  const baseSha = pr?.base?.sha;
  const headSha = pr?.head?.sha;
  const prNumber = pr?.number;
  const installationId = payload?.installation?.id?.toString();
  const isFork = pr?.head?.repo?.fork === true || (pr?.head?.repo?.full_name !== pr?.base?.repo?.full_name);

  if (!repoFullName || !baseSha || !headSha || !prNumber || !installationId) {
    console.log('[PR check] Missing repo, refs, pr number, or installation; skipping.');
    return;
  }

  // 8E.5: Only PRs targeting default branch
  const targetBranch = pr?.base?.ref;

  let token: string;
  try {
    token = await createInstallationToken(installationId);
  } catch (err: any) {
    console.error('[PR check] Failed to get installation token:', err?.message);
    return;
  }

  let changedFiles: string[] = [];
  try {
    changedFiles = await getCompareChangedFiles(token, repoFullName, baseSha, headSha);
  } catch (err: any) {
    if (err?.message?.includes('422')) {
      console.warn('[PR check] Force push on PR, using base-branch-only analysis');
    } else {
      console.error('[PR check] getCompareChangedFiles failed:', err?.message);
      return;
    }
  }

  // 8D.1: Multi-ecosystem workspace detection
  const affectedWorkspaceMap = detectAffectedWorkspaces(changedFiles);

  const { data: projectRows, error: fetchError } = await supabase
    .from('project_repositories')
    .select('project_id, package_json_path, installation_id, default_branch, pull_request_comments_enabled, projects(name, organization_id)')
    .eq('repo_full_name', repoFullName);

  if (fetchError || !projectRows?.length) {
    console.log('[PR check] No linked projects for this repo.');
    return;
  }

  // 8E.5: Filter to projects where PR targets their default branch
  const matchedRows = (projectRows as any[]).filter(r => r.default_branch === targetBranch);
  if (matchedRows.length === 0) return;

  type ProjectResult = {
    projectId: string;
    projectName: string;
    workspace: string;
    section: string;
    blocked: boolean;
    depsAdded: number;
    depsUpdated: number;
    depsRemoved: number;
    transitiveChanges: number;
    blockedBy: Record<string, number>;
    commentsEnabled: boolean;
  };

  const results: ProjectResult[] = [];

  for (const row of matchedRows) {
    const projectId = row.project_id;
    const workspace = (row.package_json_path ?? '').trim();
    const organizationId = Array.isArray(row.projects) ? row.projects[0]?.organization_id : row.projects?.organization_id;
    const projectName = (Array.isArray(row.projects) ? row.projects[0]?.name : row.projects?.name) || 'Project';
    const commentsEnabled = row.pull_request_comments_enabled !== false;

    if (!organizationId) continue;

    const workspaceAffected = affectedWorkspaceMap.has(workspace) || affectedWorkspaceMap.has('');
    const checkName = `Deptex - ${projectName}`;

    // 8E.2: Create check run as in_progress immediately
    let checkRunId: number | undefined;
    try {
      const cr = await createCheckRun(token, repoFullName, headSha, checkName, {
        status: 'in_progress',
      });
      checkRunId = cr.id;
    } catch (err: any) {
      console.error(`[PR check] Failed to create check run for ${projectName}:`, err?.message);
    }

    try {
      if (!workspaceAffected) {
        // No dependency changes for this project
        if (checkRunId) {
          await updateCheckRun(token, repoFullName, checkRunId, {
            status: 'completed',
            conclusion: 'success',
            output: { title: 'Passed — no dependency changes', summary: 'No manifest or lockfile changes detected for this project.' },
          });
        }
        results.push({
          projectId, projectName, workspace, section: `### ${projectName}\n\nNo dependency changes detected.\n`,
          blocked: false, depsAdded: 0, depsUpdated: 0, depsRemoved: 0, transitiveChanges: 0,
          blockedBy: {}, commentsEnabled,
        });

        await supabase.from('project_pull_requests').upsert({
          project_id: projectId, pr_number: prNumber, title: pr?.title, author_login: pr?.user?.login,
          author_avatar_url: pr?.user?.avatar_url, status: 'open', check_result: 'passed',
          check_summary: 'No dependency changes', provider: 'github', provider_url: pr?.html_url,
          base_branch: targetBranch, head_branch: pr?.head?.ref, head_sha: headSha,
          opened_at: pr?.created_at, last_checked_at: new Date().toISOString(), updated_at: new Date().toISOString(),
        }, { onConflict: 'project_id,pr_number,provider' }).catch(() => {});
        continue;
      }

      // 8D.2: Check which ecosystems are affected
      const ecosystems = affectedWorkspaceMap.get(workspace) ?? affectedWorkspaceMap.get('') ?? new Set<EcosystemId>();
      const hasNpm = ecosystems.has('npm');

      const lines: string[] = [];
      lines.push(`### ${projectName}`);
      lines.push('');

      let blocked = false;
      let depsAdded = 0;
      let depsUpdated = 0;
      let depsRemoved = 0;
      let transitiveChanges = 0;
      const blockedBy: Record<string, number> = {};

      if (hasNpm) {
        // Deep npm analysis
        const pkgPath = workspace ? `${workspace}/package.json` : 'package.json';
        const lockPath = workspace ? `${workspace}/package-lock.json` : 'package-lock.json';

        let basePkg: Record<string, string> = {};
        let headPkg: Record<string, string> = {};
        let baseLock: any = null;
        let headLock: any = null;

        try {
          if (isFork) {
            try {
              const content = await getRepositoryFileContent(token, repoFullName, pkgPath, headSha);
              headPkg = getDirectDepsFromPackageJson(JSON.parse(content));
            } catch {
              lines.push('*Fork repository — head branch analysis unavailable.*');
            }
          } else {
            const content = await getRepositoryFileContent(token, repoFullName, pkgPath, headSha);
            headPkg = getDirectDepsFromPackageJson(JSON.parse(content));
          }
          try {
            const content = await getRepositoryFileContent(token, repoFullName, pkgPath, baseSha);
            basePkg = getDirectDepsFromPackageJson(JSON.parse(content));
          } catch {}
          try { baseLock = JSON.parse(await getRepositoryFileContent(token, repoFullName, lockPath, baseSha)); } catch {}
          try { headLock = JSON.parse(await getRepositoryFileContent(token, repoFullName, lockPath, headSha)); } catch {}
        } catch {}

        const directAddedPkgs: Array<{ name: string; version: string }> = [];
        const directBumpedPkgs: Array<{ name: string; oldVersion: string; newVersion: string }> = [];

        for (const [name] of Object.entries(headPkg)) {
          const newVersion = headLock ? getResolvedVersion(headLock, name) : null;
          if (!newVersion) continue;
          if (!(name in basePkg)) {
            directAddedPkgs.push({ name, version: newVersion });
          } else {
            const oldVersion = baseLock ? getResolvedVersion(baseLock, name) : null;
            if (oldVersion && oldVersion !== newVersion) {
              directBumpedPkgs.push({ name, oldVersion, newVersion });
            }
          }
        }

        // Removed packages
        for (const name of Object.keys(basePkg)) {
          if (!(name in headPkg)) depsRemoved++;
        }

        const { acceptedLicenses } = await getEffectivePolicies(organizationId, projectId);

        // Load guardrails config (Phase 8H: policy engine or legacy)
        let prCheckCode: string | null = null;
        try {
          const { data: proj } = await supabase.from('projects').select('effective_pr_check_code').eq('id', projectId).single();
          prCheckCode = proj?.effective_pr_check_code;
        } catch {}
        if (!prCheckCode) {
          try {
            const { data: orgPrCheck } = await supabase.from('organization_pr_checks').select('pr_check_code').eq('organization_id', organizationId).single();
            prCheckCode = orgPrCheck?.pr_check_code;
          } catch {}
        }

        const { data: guardrailsRow } = await supabase.from('project_pr_guardrails').select('*').eq('project_id', projectId).single();
        const guardrails = guardrailsRow as any;
        const hasVulnBlocking = guardrails?.block_critical_vulns || guardrails?.block_high_vulns || guardrails?.block_medium_vulns || guardrails?.block_low_vulns;

        const checkPackage = async (name: string, version: string) => {
          const vulnCounts = await getVulnCountsForPackageVersion(supabase, name, version);
          const license = await getLicenseForPackage(name, version);
          const policyViolation = Boolean(guardrails?.block_policy_violations && acceptedLicenses.length > 0 && isLicenseAllowed(license, acceptedLicenses) === false);

          if (policyViolation) { blocked = true; blockedBy.policy_violations = (blockedBy.policy_violations ?? 0) + 1; }
          if (hasVulnBlocking) {
            if (guardrails?.block_critical_vulns && exceedsThreshold(vulnCounts, 'critical')) { blocked = true; blockedBy.critical_vulns = (blockedBy.critical_vulns ?? 0) + vulnCounts.critical_vulns; }
            if (guardrails?.block_high_vulns && exceedsThreshold(vulnCounts, 'high')) { blocked = true; blockedBy.high_vulns = (blockedBy.high_vulns ?? 0) + vulnCounts.high_vulns; }
            if (guardrails?.block_medium_vulns && exceedsThreshold(vulnCounts, 'medium')) { blocked = true; blockedBy.medium_vulns = (blockedBy.medium_vulns ?? 0) + vulnCounts.medium_vulns; }
            if (guardrails?.block_low_vulns && exceedsThreshold(vulnCounts, 'low')) { blocked = true; blockedBy.low_vulns = (blockedBy.low_vulns ?? 0) + vulnCounts.low_vulns; }
          }
          return { vulnCounts, license, policyViolation };
        };

        const fmtVuln = (v: VulnCounts) =>
          [v.critical_vulns, v.high_vulns, v.medium_vulns, v.low_vulns].some(n => n > 0)
            ? `${v.critical_vulns} critical, ${v.high_vulns} high, ${v.medium_vulns} medium, ${v.low_vulns} low vulnerabilities`
            : '0 vulnerabilities';

        // Phase 10B: Watchtower check for upgraded packages
        const { data: wtProject } = await supabase.from('projects').select('watchtower_enabled').eq('id', projectId).single();
        if (wtProject?.watchtower_enabled && directBumpedPkgs.length > 0) {
          for (const { name: pkgName, newVersion } of directBumpedPkgs) {
            const { data: dep } = await supabase.from('dependencies').select('id').eq('name', pkgName).single();
            if (!dep) continue;

            const { data: wlEntry } = await supabase
              .from('organization_watchlist')
              .select('id, quarantine_until, is_current_version_quarantined')
              .eq('organization_id', organizationId)
              .eq('dependency_id', dep.id)
              .single();

            if (!wlEntry) continue;

            const isQuarantined = wlEntry.quarantine_until && new Date(wlEntry.quarantine_until) > new Date();
            if (isQuarantined) {
              const daysLeft = Math.ceil((new Date(wlEntry.quarantine_until).getTime() - Date.now()) / 86400000);
              blocked = true;
              blockedBy.watchtower_quarantine = (blockedBy.watchtower_quarantine ?? 0) + 1;
              lines.push(`- **${pkgName}@${newVersion}** — blocked by Watchtower: quarantined (${daysLeft} day${daysLeft !== 1 ? 's' : ''} remaining)`);
            }

            const { data: wp } = await supabase.from('watched_packages').select('analysis_data').eq('name', pkgName).single();
            if (wp) {
              const ad = wp.analysis_data as any;
              if (ad?.registryIntegrityStatus === 'fail' || ad?.installScriptsStatus === 'fail' || ad?.entropyAnalysisStatus === 'fail') {
                blocked = true;
                blockedBy.watchtower_check_failed = (blockedBy.watchtower_check_failed ?? 0) + 1;
                const failedChecks = [
                  ad?.registryIntegrityStatus === 'fail' ? 'registry integrity' : null,
                  ad?.installScriptsStatus === 'fail' ? 'install scripts' : null,
                  ad?.entropyAnalysisStatus === 'fail' ? 'entropy analysis' : null,
                ].filter(Boolean).join(', ');
                lines.push(`- **${pkgName}@${newVersion}** — blocked by Watchtower: ${failedChecks} check(s) failed`);
              }
            }
          }
        }

        if (directBumpedPkgs.length > 0) {
          depsUpdated = directBumpedPkgs.length;
          lines.push('**Packages updated:**');
          for (const { name, oldVersion, newVersion } of directBumpedPkgs.slice(0, 30)) {
            const { vulnCounts } = await checkPackage(name, newVersion);
            lines.push(`- **${name}** \`${oldVersion}\` -> \`${newVersion}\` — ${fmtVuln(vulnCounts)}`);
          }
          if (directBumpedPkgs.length > 30) lines.push(`- ...and ${directBumpedPkgs.length - 30} more`);
          lines.push('');
        }

        if (directAddedPkgs.length > 0) {
          depsAdded = directAddedPkgs.length;
          lines.push('**Packages added:**');
          for (const { name, version } of directAddedPkgs.slice(0, 30)) {
            const { vulnCounts, license, policyViolation } = await checkPackage(name, version);
            const licStr = license ?? 'Unknown';
            const policyStr = policyViolation ? ' **(does not comply with project policy)**' : '';
            lines.push(`- **${name}** \`${version}\` — license: ${licStr}; ${fmtVuln(vulnCounts)}${policyStr}`);
          }
          if (directAddedPkgs.length > 30) lines.push(`- ...and ${directAddedPkgs.length - 30} more`);
          lines.push('');
        }

        // Transitive deps
        if (headLock && baseLock) {
          const baseSet = getLockfilePackagesSet(baseLock);
          const headSet = getLockfilePackagesSet(headLock);
          const directNames = new Set([...Object.keys(basePkg), ...Object.keys(headPkg)]);
          const transitive: Array<{ name: string; version: string }> = [];
          for (const key of headSet) {
            if (baseSet.has(key)) continue;
            const idx = key.lastIndexOf('@');
            const name = idx >= 0 ? key.slice(0, idx) : key;
            const version = idx >= 0 ? key.slice(idx + 1) : '';
            if (directNames.has(name) || !version) continue;
            transitive.push({ name, version });
          }
          if (transitive.length > 0) {
            transitiveChanges = transitive.length;
            lines.push('**Transitive dependencies (new/updated):**');
            for (const { name, version } of transitive.slice(0, 20)) {
              const { vulnCounts, license, policyViolation } = await checkPackage(name, version);
              const licStr = license ?? 'Unknown';
              const policyStr = policyViolation ? ' **(does not comply with project policy)**' : '';
              lines.push(`- **${name}** \`${version}\` — license: ${licStr}; ${fmtVuln(vulnCounts)}${policyStr}`);
            }
            if (transitive.length > 20) lines.push(`- ...and ${transitive.length - 20} more`);
            lines.push('');
          }
        }

        if (!headLock && !baseLock) {
          lines.push('*No lockfile found — transitive dependency analysis unavailable.*');
          lines.push('');
        }
      } else {
        // 8D.2: Shallow analysis for non-npm ecosystems
        const manifestFiles = changedFiles.filter(f => {
          const match = detectAffectedWorkspaces([f]);
          return match.size > 0;
        }).filter(f => {
          const w = (workspace ? workspace + '/' : '');
          return f.startsWith(w) || workspace === '';
        });

        if (manifestFiles.length > 0) {
          lines.push('**Manifest files changed:**');
          for (const f of manifestFiles) {
            lines.push(`- \`${f}\``);
          }
          lines.push('');
          lines.push('*Detailed dependency diff analysis for this ecosystem will be available once full extraction support lands.*');
          lines.push('');
        }
      }

      if (blocked) {
        lines.push('---');
        lines.push('');
        lines.push('**This project cannot be merged until the above issues are resolved.**');
        lines.push('');
      }

      // Update check run to completed
      const checkConclusion = blocked ? 'failure' : 'success';
      const issueCount = Object.values(blockedBy).reduce((a, b) => a + b, 0);
      const checkTitle = blocked ? `Failed — ${issueCount} issues found` : 'Passed — all checks clear';
      const checkSummary = blocked
        ? Object.entries(blockedBy).map(([k, v]) => `${v} ${k.replace(/_/g, ' ')}`).join(', ')
        : 'All checked dependencies meet this project\'s guardrails.';

      if (checkRunId) {
        try {
          const textContent = lines.join('\n').slice(0, MAX_CHECK_RUN_TEXT);
          await updateCheckRun(token, repoFullName, checkRunId, {
            status: 'completed',
            conclusion: checkConclusion,
            output: { title: checkTitle, summary: checkSummary, text: textContent },
          });
        } catch (err: any) {
          console.error(`[PR check] Failed to update check run for ${projectName}:`, err?.message);
        }
      }

      // 8G.2: Track PR
      await supabase.from('project_pull_requests').upsert({
        project_id: projectId, pr_number: prNumber, title: pr?.title, author_login: pr?.user?.login,
        author_avatar_url: pr?.user?.avatar_url, status: 'open', check_result: blocked ? 'failed' : 'passed',
        check_summary: checkSummary, deps_added: depsAdded, deps_updated: depsUpdated,
        deps_removed: depsRemoved, transitive_changes: transitiveChanges,
        blocked_by: Object.keys(blockedBy).length > 0 ? blockedBy : null,
        provider: 'github', provider_url: pr?.html_url,
        base_branch: targetBranch, head_branch: pr?.head?.ref, head_sha: headSha,
        opened_at: pr?.created_at, last_checked_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      }, { onConflict: 'project_id,pr_number,provider' }).catch((err: any) => {
        console.warn('[PR check] Failed to upsert PR tracking:', err?.message);
      });

      results.push({
        projectId, projectName, workspace, section: lines.join('\n'),
        blocked, depsAdded, depsUpdated, depsRemoved, transitiveChanges, blockedBy, commentsEnabled,
      });
    } catch (err: any) {
      console.error(`[PR check] Error processing ${projectName}:`, err?.message);
      if (checkRunId) {
        await updateCheckRun(token, repoFullName, checkRunId, {
          status: 'completed', conclusion: 'failure',
          output: { title: 'Internal error', summary: `Analysis failed: ${err?.message?.slice(0, 200)}` },
        }).catch(() => {});
      }
    }

    await supabase.from('project_repositories').update({
      last_webhook_at: new Date().toISOString(),
      last_webhook_event: 'pull_request',
      webhook_status: 'active',
    }).eq('project_id', projectId);
  }

  // 8F: Smart comment system — single aggregated comment with per-project sections
  const commentableResults = results.filter(r => r.commentsEnabled);
  if (commentableResults.length > 0) {
    const { data: repoSettings } = await supabase
      .from('project_repositories')
      .select('pull_request_comments_enabled')
      .eq('repo_full_name', repoFullName)
      .limit(1);

    let commentBody = `${DEPTEX_COMMENT_MARKER}\n## Deptex Dependency Check\n\n`;
    for (const r of commentableResults) {
      commentBody += r.section + '\n---\n\n';
    }

    const { data: lastExtraction } = await supabase
      .from('project_repositories')
      .select('last_extracted_at')
      .eq('repo_full_name', repoFullName)
      .limit(1)
      .single();
    const lastScanned = lastExtraction?.last_extracted_at
      ? new Date(lastExtraction.last_extracted_at).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
      : 'Never';

    commentBody += `*Last updated: ${new Date().toISOString().replace('T', ' ').slice(0, 16)} UTC | Last scanned: ${lastScanned}*`;

    // Truncate if needed
    if (commentBody.length > MAX_COMMENT_LENGTH) {
      commentBody = commentBody.slice(0, MAX_COMMENT_LENGTH - 200) + '\n\n---\n*Comment truncated. View full results in Deptex.*';
    }

    try {
      // 8F.2: Find existing Deptex comment and edit it
      const comments = await listIssueComments(token, repoFullName, prNumber);
      const existingComment = comments.find(c => c.body?.includes(DEPTEX_COMMENT_MARKER));

      if (existingComment) {
        await updateIssueComment(token, repoFullName, existingComment.id, commentBody);
      } else {
        await createIssueComment(token, repoFullName, prNumber, commentBody);
      }
    } catch (err: any) {
      console.error('[PR check] Failed to post/edit comment:', err?.message);
    }
  }
}

// ============================================================
// GitHub Installation Event Handler
// Handles: created, deleted, suspend, unsuspend, new_permissions_accepted
// ============================================================
async function handleInstallationEvent(payload: any) {
  const { action, installation } = payload;
  const installationId = installation?.id?.toString();
  const accountLogin = installation?.account?.login;
  const accountType = installation?.account?.type; // 'User' or 'Organization'
  const accountAvatarUrl = installation?.account?.avatar_url;
  
  console.log('GitHub App installation event:', {
    action,
    installation_id: installationId,
    account_login: accountLogin,
    account_type: accountType,
  });
  
  if (!installationId) {
    console.error('Installation event missing installation_id');
    return;
  }
  
  switch (action) {
    case 'created':
      // New installation - update metadata if we have the org connected
      await handleInstallationCreated(installationId, accountLogin, accountType, accountAvatarUrl);
      break;
      
    case 'deleted':
      // User uninstalled the app from GitHub - disconnect from our side
      await handleInstallationDeleted(installationId, accountLogin);
      break;
      
    case 'suspend':
      // App was suspended (e.g., billing issue)
      await handleInstallationSuspended(installationId, accountLogin);
      break;
      
    case 'unsuspend':
      // App was unsuspended
      await handleInstallationUnsuspended(installationId, accountLogin);
      break;
      
    case 'new_permissions_accepted':
      console.log('New permissions accepted for installation:', installationId);
      break;
      
    default:
      console.log('Unhandled installation action:', action);
  }
}

// Handle new GitHub App installation (update metadata)
async function handleInstallationCreated(
  installationId: string,
  accountLogin: string | undefined,
  accountType: string | undefined,
  accountAvatarUrl: string | undefined
) {
  // Find organization with this installation_id and update metadata
  const { data: org, error: findError } = await supabase
    .from('organizations')
    .select('id, name')
    .eq('github_installation_id', installationId)
    .single();
  
  if (findError || !org) {
    console.log('Installation created but no matching org found yet (may come via callback):', installationId);
    return;
  }
  
  // Update organization_integrations row for this installation
  const { error: updateError } = await supabase
    .from('organization_integrations')
    .update({
      metadata: {
        account_login: accountLogin,
        account_type: accountType,
        account_avatar_url: accountAvatarUrl,
      },
      updated_at: new Date().toISOString(),
    })
    .eq('organization_id', org.id)
    .eq('provider', 'github')
    .eq('installation_id', installationId);
  
  if (updateError) {
    console.error('Failed to update integration metadata:', updateError);
  } else {
    console.log('Updated GitHub integration metadata for org:', org.name);
  }
}

// Handle GitHub App uninstallation (user removed from GitHub Settings)
async function handleInstallationDeleted(
  installationId: string,
  accountLogin: string | undefined
) {
  console.log('Processing GitHub App uninstall:', { installationId, accountLogin });
  
  // Find organization with this installation_id
  const { data: org, error: findError } = await supabase
    .from('organizations')
    .select('id, name')
    .eq('github_installation_id', installationId)
    .single();
  
  if (findError || !org) {
    console.log('No organization found with installation_id:', installationId);
    return;
  }
  
  console.log('Disconnecting GitHub from organization:', { orgId: org.id, orgName: org.name });
  
  // Clear github_installation_id from organization
  const { error: orgUpdateError } = await supabase
    .from('organizations')
    .update({
      github_installation_id: null,
      updated_at: new Date().toISOString(),
    })
    .eq('id', org.id);
  
  if (orgUpdateError) {
    console.error('Failed to clear github_installation_id:', orgUpdateError);
  }
  
  // Update organization_integrations table
  const { error: integrationError } = await supabase
    .from('organization_integrations')
    .update({
      status: 'disconnected',
      installation_id: null,
      metadata: {
        account_login: accountLogin,
        disconnected_via: 'github_webhook',
        disconnected_at: new Date().toISOString(),
      },
      updated_at: new Date().toISOString(),
    })
    .eq('organization_id', org.id)
    .eq('provider', 'github');
  
  if (integrationError) {
    console.error('Failed to update integration status:', integrationError);
  }

  // 8P.3: Mark all project repos using this installation as disconnected
  await supabase
    .from('project_repositories')
    .update({ status: 'installation_removed', updated_at: new Date().toISOString() })
    .eq('installation_id', installationId);
  
  // Log the disconnection event
  console.log('GitHub App disconnected via webhook:', {
    organization_id: org.id,
    organization_name: org.name,
    installation_id: installationId,
    account_login: accountLogin,
    timestamp: new Date().toISOString(),
  });
  
  // TODO: Optionally log to activities table
  // TODO: Optionally send notification to org admins
}

// Handle GitHub App suspension
async function handleInstallationSuspended(
  installationId: string,
  accountLogin: string | undefined
) {
  console.log('GitHub App suspended:', { installationId, accountLogin });
  
  // Find organization and update status
  const { data: org } = await supabase
    .from('organizations')
    .select('id')
    .eq('github_installation_id', installationId)
    .single();
  
  if (!org) return;
  
  await supabase
    .from('organization_integrations')
    .update({
      status: 'suspended',
      metadata: {
        account_login: accountLogin,
        suspended_at: new Date().toISOString(),
      },
      updated_at: new Date().toISOString(),
    })
    .eq('organization_id', org.id)
    .eq('provider', 'github');
}

// Handle GitHub App unsuspension
async function handleInstallationUnsuspended(
  installationId: string,
  accountLogin: string | undefined
) {
  console.log('GitHub App unsuspended:', { installationId, accountLogin });
  
  // Find organization and update status
  const { data: org } = await supabase
    .from('organizations')
    .select('id')
    .eq('github_installation_id', installationId)
    .single();
  
  if (!org) return;
  
  await supabase
    .from('organization_integrations')
    .update({
      status: 'connected',
      metadata: {
        account_login: accountLogin,
        unsuspended_at: new Date().toISOString(),
      },
      updated_at: new Date().toISOString(),
    })
    .eq('organization_id', org.id)
    .eq('provider', 'github');
}

// ============================================================
// ORG-LEVEL GitLab connect (OAuth -> organization_integrations)
// ============================================================
router.get('/gitlab/install', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { org_id } = req.query;
    if (!org_id || typeof org_id !== 'string') {
      return res.status(400).json({ error: 'Organization ID is required' });
    }
    const clientId = process.env.GITLAB_CLIENT_ID;
    const gitlabUrl = process.env.GITLAB_URL || 'https://gitlab.com';
    if (!clientId) {
      return res.status(500).json({ error: 'GitLab client ID not configured' });
    }
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', org_id)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    const redirectUri = `${getBackendUrl()}/api/integrations/gitlab/org-callback`;
    const scopes = 'api read_user read_repository';
    const state = Buffer.from(JSON.stringify({ userId: req.user!.id, orgId: org_id })).toString('base64');
    const authUrl = `${gitlabUrl}/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent(scopes)}&state=${encodeURIComponent(state)}`;
    res.json({ redirectUrl: authUrl });
  } catch (error: any) {
    console.error('GitLab org install error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/gitlab/org-callback', async (req, res) => {
  const { code, state, error } = req.query;
  const frontendUrl = getFrontendUrl();
  const gitlabUrl = process.env.GITLAB_URL || 'https://gitlab.com';

  if (error) {
    return res.redirect(`${frontendUrl}?error=gitlab&message=${encodeURIComponent(error as string)}`);
  }
  if (!code) {
    return res.redirect(`${frontendUrl}?error=gitlab&message=No authorization code`);
  }

  try {
    let userId: string;
    let orgId: string;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
      orgId = stateData.orgId;
    } catch {
      return res.redirect(`${frontendUrl}?error=gitlab&message=Invalid state`);
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();
    if (!membership) {
      return res.redirect(`${frontendUrl}?error=gitlab&message=Not authorized`);
    }

    const redirectUri = `${getBackendUrl()}/api/integrations/gitlab/org-callback`;

    const tokenRes = await fetch(`${gitlabUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.GITLAB_CLIENT_ID!,
        client_secret: process.env.GITLAB_CLIENT_SECRET!,
        code: code as string,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri,
      }),
    });
    const tokenData = await tokenRes.json() as any;
    if (tokenData.error) {
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings?section=integrations&error=gitlab&message=${encodeURIComponent(tokenData.error_description || tokenData.error)}`);
    }

    const userRes = await fetch(`${gitlabUrl}/api/v4/user`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const userData = await userRes.json() as any;

    const { error: dbError } = await supabase
      .from('organization_integrations')
      .insert({
        organization_id: orgId,
        provider: 'gitlab',
        installation_id: userData.id?.toString() || null,
        display_name: userData.username || userData.name || 'GitLab',
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token || null,
        status: 'connected',
        metadata: {
          gitlab_url: gitlabUrl,
          username: userData.username,
          name: userData.name,
          avatar_url: userData.avatar_url,
          scope: tokenData.scope,
        },
        connected_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      } as any);

    if (dbError) {
      console.error('GitLab org integration DB error:', dbError);
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings?section=integrations&error=gitlab&message=Failed to save integration`);
    }

    try { await emitEvent({ type: 'integration_connected', organizationId: orgId, payload: { provider: 'gitlab', displayName: userData.username || userData.name || 'GitLab' }, source: 'system', priority: 'normal' }); } catch (e) {}

    res.redirect(`${frontendUrl}/organizations/${orgId}/settings?section=integrations&connected=gitlab`);
  } catch (err: any) {
    console.error('GitLab org callback error:', err);
    res.redirect(`${frontendUrl}?error=gitlab&message=${encodeURIComponent(err.message || 'Unknown error')}`);
  }
});

// ============================================================
// ORG-LEVEL Bitbucket connect (OAuth -> organization_integrations)
// ============================================================
router.get('/bitbucket/install', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { org_id } = req.query;
    if (!org_id || typeof org_id !== 'string') {
      return res.status(400).json({ error: 'Organization ID is required' });
    }
    const clientId = process.env.BITBUCKET_CLIENT_ID;
    if (!clientId) {
      return res.status(500).json({ error: 'Bitbucket client ID not configured' });
    }
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', org_id)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    const redirectUri = `${getBackendUrl()}/api/integrations/bitbucket/org-callback`;
    const state = Buffer.from(JSON.stringify({ userId: req.user!.id, orgId: org_id })).toString('base64');
    const authUrl = `https://bitbucket.org/site/oauth2/authorize?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
    res.json({ redirectUrl: authUrl });
  } catch (error: any) {
    console.error('Bitbucket org install error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/bitbucket/org-callback', async (req, res) => {
  const { code, state, error } = req.query;
  const frontendUrl = getFrontendUrl();

  if (error) {
    return res.redirect(`${frontendUrl}?error=bitbucket&message=${encodeURIComponent(error as string)}`);
  }
  if (!code) {
    return res.redirect(`${frontendUrl}?error=bitbucket&message=No authorization code`);
  }

  try {
    let userId: string;
    let orgId: string;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
      orgId = stateData.orgId;
    } catch {
      return res.redirect(`${frontendUrl}?error=bitbucket&message=Invalid state`);
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();
    if (!membership) {
      return res.redirect(`${frontendUrl}?error=bitbucket&message=Not authorized`);
    }

    const redirectUri = `${getBackendUrl()}/api/integrations/bitbucket/org-callback`;
    const clientId = process.env.BITBUCKET_CLIENT_ID!;
    const clientSecret = process.env.BITBUCKET_CLIENT_SECRET!;

    const tokenRes = await fetch('https://bitbucket.org/site/oauth2/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: redirectUri,
      }),
    });
    const tokenData = await tokenRes.json() as any;
    if (tokenData.error) {
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings?section=integrations&error=bitbucket&message=${encodeURIComponent(tokenData.error_description || tokenData.error)}`);
    }

    const userRes = await fetch('https://api.bitbucket.org/2.0/user', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const userData = await userRes.json() as any;

    let workspaceName: string | null = null;
    try {
      const wsRes = await fetch('https://api.bitbucket.org/2.0/workspaces?pagelen=1', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      const wsData = await wsRes.json() as any;
      if (wsData.values?.[0]?.slug) {
        workspaceName = wsData.values[0].slug;
      }
    } catch { /* ignore */ }

    const { error: dbError } = await supabase
      .from('organization_integrations')
      .insert({
        organization_id: orgId,
        provider: 'bitbucket',
        installation_id: userData.uuid || userData.account_id || null,
        display_name: userData.display_name || userData.username || 'Bitbucket',
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token || null,
        status: 'connected',
        metadata: {
          username: userData.username,
          display_name: userData.display_name,
          avatar_url: userData.links?.avatar?.href,
          workspace: workspaceName,
          uuid: userData.uuid,
        },
        connected_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      } as any);

    if (dbError) {
      console.error('Bitbucket org integration DB error:', dbError);
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings?section=integrations&error=bitbucket&message=Failed to save integration`);
    }

    try { await emitEvent({ type: 'integration_connected', organizationId: orgId, payload: { provider: 'bitbucket', displayName: userData.display_name || userData.username || 'Bitbucket' }, source: 'system', priority: 'normal' }); } catch (e) {}

    res.redirect(`${frontendUrl}/organizations/${orgId}/settings?section=integrations&connected=bitbucket`);
  } catch (err: any) {
    console.error('Bitbucket org callback error:', err);
    res.redirect(`${frontendUrl}?error=bitbucket&message=${encodeURIComponent(err.message || 'Unknown error')}`);
  }
});

// ============================================================
// ORG-LEVEL Slack connect (OAuth -> organization_integrations)
// ============================================================
router.get('/slack/install', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { org_id, project_id, team_id } = req.query;
    if (!org_id || typeof org_id !== 'string') {
      return res.status(400).json({ error: 'Organization ID is required' });
    }
    const clientId = process.env.SLACK_CLIENT_ID;
    if (!clientId) {
      return res.status(500).json({ error: 'Slack client ID not configured' });
    }
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', org_id)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    if (project_id && typeof project_id === 'string') {
      const { data: proj } = await supabase.from('projects').select('id').eq('id', project_id).eq('organization_id', org_id).single();
      if (!proj) return res.status(400).json({ error: 'Project not found' });
    }
    if (team_id && typeof team_id === 'string') {
      const { data: team } = await supabase.from('teams').select('id').eq('id', team_id).eq('organization_id', org_id).single();
      if (!team) return res.status(400).json({ error: 'Team not found' });
    }
    const backendUrl = (process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`).replace(/\/$/, '');
    const frontendUrl = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
    const redirectUri = `${backendUrl}/api/integrations/slack/org-callback`;
    const scopes = 'chat:write,channels:read,channels:history,files:write,incoming-webhook';
    const statePayload: { userId: string; orgId: string; projectId?: string; teamId?: string; successRedirect?: string } = { userId: req.user!.id, orgId: org_id };
    if (project_id && typeof project_id === 'string') {
      statePayload.projectId = project_id;
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/projects/${project_id}/settings/notifications?connected=slack`;
    } else if (team_id && typeof team_id === 'string') {
      statePayload.teamId = team_id;
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/teams/${team_id}/settings/notifications?connected=slack`;
    } else {
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/settings/integrations?connected=slack`;
    }
    const state = Buffer.from(JSON.stringify(statePayload)).toString('base64');
    const authUrl = `https://slack.com/oauth/v2/authorize?client_id=${clientId}&scope=${encodeURIComponent(scopes)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
    res.json({ redirectUrl: authUrl });
  } catch (error: any) {
    console.error('Slack org install error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/slack/org-callback', async (req, res) => {
  const { code, state, error } = req.query;
  const frontendUrl = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');

  if (error) {
    return res.redirect(`${frontendUrl}?error=slack&message=${encodeURIComponent(error as string)}`);
  }
  if (!code) {
    return res.redirect(`${frontendUrl}?error=slack&message=No authorization code`);
  }

  try {
    let userId: string;
    let orgId: string;
    let projectId: string | undefined;
    let teamId: string | undefined;
    let successRedirect: string | undefined;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
      orgId = stateData.orgId;
      projectId = stateData.projectId;
      teamId = stateData.teamId;
      successRedirect = stateData.successRedirect;
      // If projectId/teamId were lost (e.g. state corruption), infer from successRedirect path
      if (!projectId && !teamId && successRedirect) {
        const teamMatch = successRedirect.match(/\/organizations\/[^/]+\/teams\/([^/]+)\/settings\/notifications/);
        const projectMatch = successRedirect.match(/\/organizations\/[^/]+\/projects\/([^/]+)\/settings/);
        if (teamMatch) teamId = teamMatch[1];
        else if (projectMatch) projectId = projectMatch[1];
      }
    } catch {
      return res.redirect(`${frontendUrl}?error=slack&message=Invalid state`);
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();
    if (!membership) {
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=slack&message=Not authorized`);
    }

    const backendUrl = (process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`).replace(/\/$/, '');
    const redirectUri = `${backendUrl}/api/integrations/slack/org-callback`;

    const tokenRes = await fetch('https://slack.com/api/oauth.v2.access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.SLACK_CLIENT_ID!,
        client_secret: process.env.SLACK_CLIENT_SECRET!,
        code: code as string,
        redirect_uri: redirectUri,
      }),
    });
    const tokenData = await tokenRes.json() as any;

    if (!tokenData.ok) {
      console.error('Slack OAuth error:', tokenData.error);
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=slack&message=${encodeURIComponent(tokenData.error || 'Unknown error')}`);
    }

    const webhook = tokenData.incoming_webhook || null;
    const channelId = webhook?.channel_id;
    const installationId = channelId
      ? `${tokenData.team?.id}:${channelId}`
      : tokenData.team?.id || null;

    const insertPayload = {
      provider: 'slack',
      installation_id: installationId,
      display_name: tokenData.team?.name || 'Slack Workspace',
      access_token: tokenData.access_token,
      status: 'connected',
      metadata: {
        bot_user_id: tokenData.bot_user_id,
        team_id: tokenData.team?.id,
        team_name: tokenData.team?.name,
        channel: webhook?.channel || null,
        channel_id: channelId || null,
        authed_user_id: tokenData.authed_user?.id,
        scope: tokenData.scope,
        incoming_webhook: webhook,
      },
      connected_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const redirectOnSuccess = successRedirect || `${frontendUrl}/organizations/${orgId}/settings/integrations?connected=slack`;

    if (projectId) {
      const { data: proj } = await supabase.from('projects').select('id').eq('id', projectId).eq('organization_id', orgId).single();
      if (!proj) {
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=slack&message=Project not found`);
      }
      const { error: dbError } = await supabase
        .from('project_integrations')
        .insert({ project_id: projectId, ...insertPayload } as any);

      if (dbError) {
        console.error('Slack project integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/projects/${projectId}/settings/notifications?error=slack&message=Failed to save integration`);
      }
      res.redirect(redirectOnSuccess);
    } else if (teamId) {
      const { data: team } = await supabase.from('teams').select('id').eq('id', teamId).eq('organization_id', orgId).single();
      if (!team) {
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=slack&message=Team not found`);
      }
      const { error: dbError } = await supabase
        .from('team_integrations')
        .insert({ team_id: teamId, ...insertPayload } as any);

      if (dbError) {
        console.error('Slack team integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/teams/${teamId}/settings/notifications?error=slack&message=Failed to save integration`);
      }
      res.redirect(redirectOnSuccess);
    } else {
      const { error: dbError } = await supabase
        .from('organization_integrations')
        .insert({ organization_id: orgId, ...insertPayload } as any);

      if (dbError) {
        console.error('Slack org integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=slack&message=Failed to save integration`);
      }
      try { await emitEvent({ type: 'integration_connected', organizationId: orgId, payload: { provider: 'slack', displayName: tokenData.team?.name || 'Slack Workspace' }, source: 'system', priority: 'normal' }); } catch (e) {}
      res.redirect(redirectOnSuccess);
    }
  } catch (err: any) {
    console.error('Slack org callback error:', err);
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(`${frontendUrl}?error=slack&message=${encodeURIComponent(err.message || 'Unknown error')}`);
  }
});

// ============================================================
// TICKETING: Jira Cloud, Jira Data Center (PAT), Linear, Asana
// ============================================================

router.get('/jira/install', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { org_id, project_id, team_id } = req.query;
    if (!org_id || typeof org_id !== 'string') {
      return res.status(400).json({ error: 'Organization ID is required' });
    }
    const clientId = process.env.JIRA_CLIENT_ID;
    if (!clientId) {
      return res.status(500).json({ error: 'Jira client ID not configured' });
    }
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', org_id)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    if (project_id && typeof project_id === 'string') {
      const { data: proj } = await supabase.from('projects').select('id').eq('id', project_id).eq('organization_id', org_id).single();
      if (!proj) return res.status(400).json({ error: 'Project not found' });
    }
    if (team_id && typeof team_id === 'string') {
      const { data: team } = await supabase.from('teams').select('id').eq('id', team_id).eq('organization_id', org_id).single();
      if (!team) return res.status(400).json({ error: 'Team not found' });
    }
    const backendUrl = getBackendUrl();
    const frontendUrl = getFrontendUrl();
    const redirectUri = `${backendUrl}/api/integrations/jira/org-callback`;
    const scopes = 'read:jira-work write:jira-work read:jira-user';
    const statePayload: { userId: string; orgId: string; projectId?: string; teamId?: string; successRedirect?: string } = { userId: req.user!.id, orgId: org_id };
    if (project_id && typeof project_id === 'string') {
      statePayload.projectId = project_id;
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/projects/${project_id}/settings?connected=jira`;
    } else if (team_id && typeof team_id === 'string') {
      statePayload.teamId = team_id;
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/teams/${team_id}/settings/notifications?connected=jira`;
    } else {
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/settings/integrations?connected=jira`;
    }
    const state = Buffer.from(JSON.stringify(statePayload)).toString('base64');
    const authUrl = `https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=${clientId}&scope=${encodeURIComponent(scopes)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&response_type=code&prompt=consent`;
    res.json({ redirectUrl: authUrl });
  } catch (error: any) {
    console.error('Jira org install error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/jira/org-callback', async (req, res) => {
  const { code, state, error } = req.query;
  const frontendUrl = getFrontendUrl();

  const buildErrorRedirect = (msg: string) => {
    let target = `${frontendUrl}?error=jira&message=${encodeURIComponent(msg)}`;
    if (state && typeof state === 'string') {
      try {
        const stateData = JSON.parse(Buffer.from(state, 'base64').toString());
        if (stateData.orgId) {
          target = `${frontendUrl}/organizations/${stateData.orgId}/settings/integrations?error=jira&message=${encodeURIComponent(msg)}`;
        }
      } catch { /* use root fallback */ }
    }
    return target;
  };

  if (error) {
    return res.redirect(buildErrorRedirect(error as string));
  }
  if (!code) {
    return res.redirect(buildErrorRedirect('No authorization code'));
  }

  try {
    let userId: string;
    let orgId: string;
    let projectId: string | undefined;
    let teamId: string | undefined;
    let successRedirect: string | undefined;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
      orgId = stateData.orgId;
      projectId = stateData.projectId;
      teamId = stateData.teamId;
      successRedirect = stateData.successRedirect;
      if (!projectId && !teamId && successRedirect) {
        const teamMatch = successRedirect.match(/\/organizations\/[^/]+\/teams\/([^/]+)\/settings\/notifications/);
        const projectMatch = successRedirect.match(/\/organizations\/[^/]+\/projects\/([^/]+)\/settings/);
        if (teamMatch) teamId = teamMatch[1];
        else if (projectMatch) projectId = projectMatch[1];
      }
    } catch {
      return res.redirect(`${frontendUrl}?error=jira&message=Invalid state`);
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();
    if (!membership) {
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=jira&message=Not authorized`);
    }

    const backendUrl = getBackendUrl();
    const redirectUri = `${backendUrl}/api/integrations/jira/org-callback`;

    const tokenRes = await fetch('https://auth.atlassian.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: process.env.JIRA_CLIENT_ID!,
        client_secret: process.env.JIRA_CLIENT_SECRET!,
        code: code as string,
        redirect_uri: redirectUri,
      }),
    });
    const tokenData = await tokenRes.json() as any;

    if (tokenData.error) {
      console.error('Jira OAuth error:', tokenData.error);
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=jira&message=${encodeURIComponent(tokenData.error_description || tokenData.error || 'Unknown error')}`);
    }

    const sitesRes = await fetch('https://api.atlassian.com/oauth/token/accessible-resources', {
      headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: 'application/json' },
    });
    const sites = await sitesRes.json() as Array<{ id: string; name: string; url: string }>;
    const primarySite = sites?.[0];
    const displayName = primarySite?.name || 'Jira Cloud';

    const jiraInsert = {
      provider: 'jira',
      installation_id: primarySite?.id || null,
      display_name: displayName,
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token || null,
      status: 'connected',
      metadata: {
        cloud_id: primarySite?.id,
        site_name: primarySite?.name,
        site_url: primarySite?.url,
        all_sites: sites,
        scope: tokenData.scope,
      },
      connected_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    } as any;

    const redirectOnSuccess = successRedirect || `${frontendUrl}/organizations/${orgId}/settings/integrations?connected=jira`;

    if (projectId) {
      const { data: proj } = await supabase.from('projects').select('id').eq('id', projectId).eq('organization_id', orgId).single();
      if (!proj) {
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=jira&message=Project not found`);
      }
      const { error: dbError } = await supabase.from('project_integrations').insert({ project_id: projectId, ...jiraInsert });
      if (dbError) {
        console.error('Jira project integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/projects/${projectId}/settings?error=jira&message=Failed to save integration`);
      }
      res.redirect(redirectOnSuccess);
    } else if (teamId) {
      const { data: team } = await supabase.from('teams').select('id').eq('id', teamId).eq('organization_id', orgId).single();
      if (!team) {
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=jira&message=Team not found`);
      }
      const { error: dbError } = await supabase.from('team_integrations').insert({ team_id: teamId, ...jiraInsert });
      if (dbError) {
        console.error('Jira team integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/teams/${teamId}/settings/notifications?error=jira&message=Failed to save integration`);
      }
      res.redirect(redirectOnSuccess);
    } else {
      const { error: dbError } = await supabase.from('organization_integrations').insert({ organization_id: orgId, ...jiraInsert });
      if (dbError) {
        console.error('Jira org integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=jira&message=Failed to save integration`);
      }
      try { await emitEvent({ type: 'integration_connected', organizationId: orgId, payload: { provider: 'jira', displayName }, source: 'system', priority: 'normal' }); } catch (e) {}
      res.redirect(redirectOnSuccess);
    }
  } catch (err: any) {
    console.error('Jira org callback error:', err);
    const frontendUrl = getFrontendUrl();
    res.redirect(`${frontendUrl}?error=jira&message=${encodeURIComponent(err.message || 'Unknown error')}`);
  }
});

router.post('/jira/connect-pat', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { org_id, project_id, team_id, base_url, token } = req.body;
    if (!org_id || !base_url || !token) {
      return res.status(400).json({ error: 'Organization ID, base URL, and personal access token are required' });
    }
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', org_id)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    if (project_id && typeof project_id === 'string') {
      const { data: proj } = await supabase.from('projects').select('id').eq('id', project_id).eq('organization_id', org_id).single();
      if (!proj) return res.status(400).json({ error: 'Project not found' });
    }
    if (team_id && typeof team_id === 'string') {
      const { data: team } = await supabase.from('teams').select('id').eq('id', team_id).eq('organization_id', org_id).single();
      if (!team) return res.status(400).json({ error: 'Team not found' });
    }

    const normalizedUrl = (base_url as string).replace(/\/$/, '');
    const verifyRes = await fetch(`${normalizedUrl}/rest/api/2/myself`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    });
    if (!verifyRes.ok) {
      return res.status(401).json({ error: 'Invalid credentials. Could not authenticate with the provided Jira server and token.' });
    }
    const userData = await verifyRes.json() as { displayName?: string; name?: string; key?: string };

    const jiraPatInsert = {
      provider: 'jira',
      installation_id: `dc:${Buffer.from(normalizedUrl).toString('base64url').slice(0, 32)}`,
      display_name: userData.displayName || userData.name || normalizedUrl,
      access_token: token,
      status: 'connected',
      metadata: {
        type: 'data_center',
        base_url: normalizedUrl,
        username: userData.name || userData.key,
        display_name: userData.displayName,
      },
      connected_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    } as any;

    if (project_id && typeof project_id === 'string') {
      const { error: dbError } = await supabase.from('project_integrations').insert({ project_id, ...jiraPatInsert });
      if (dbError) {
        console.error('Jira DC project integration DB error:', dbError);
        return res.status(500).json({ error: 'Failed to save integration' });
      }
    } else if (team_id && typeof team_id === 'string') {
      const { error: dbError } = await supabase.from('team_integrations').insert({ team_id, ...jiraPatInsert });
      if (dbError) {
        console.error('Jira DC team integration DB error:', dbError);
        return res.status(500).json({ error: 'Failed to save integration' });
      }
    } else {
      const { error: dbError } = await supabase.from('organization_integrations').insert({ organization_id: org_id, ...jiraPatInsert });
      if (dbError) {
        console.error('Jira DC integration DB error:', dbError);
        return res.status(500).json({ error: 'Failed to save integration' });
      }
    }
    res.json({ success: true });
  } catch (error: any) {
    console.error('Jira PAT connect error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/linear/install', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { org_id, project_id, team_id } = req.query;
    if (!org_id || typeof org_id !== 'string') {
      return res.status(400).json({ error: 'Organization ID is required' });
    }
    const clientId = process.env.LINEAR_CLIENT_ID;
    if (!clientId) {
      return res.status(500).json({ error: 'Linear client ID not configured' });
    }
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', org_id)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    if (project_id && typeof project_id === 'string') {
      const { data: proj } = await supabase.from('projects').select('id').eq('id', project_id).eq('organization_id', org_id).single();
      if (!proj) return res.status(400).json({ error: 'Project not found' });
    }
    if (team_id && typeof team_id === 'string') {
      const { data: team } = await supabase.from('teams').select('id').eq('id', team_id).eq('organization_id', org_id).single();
      if (!team) return res.status(400).json({ error: 'Team not found' });
    }
    const backendUrl = getBackendUrl();
    const frontendUrl = getFrontendUrl();
    const redirectUri = `${backendUrl}/api/integrations/linear/org-callback`;
    const statePayload: { userId: string; orgId: string; projectId?: string; teamId?: string; successRedirect?: string } = { userId: req.user!.id, orgId: org_id };
    if (project_id && typeof project_id === 'string') {
      statePayload.projectId = project_id;
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/projects/${project_id}/settings?connected=linear`;
    } else if (team_id && typeof team_id === 'string') {
      statePayload.teamId = team_id;
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/teams/${team_id}/settings/notifications?connected=linear`;
    } else {
      statePayload.successRedirect = `${frontendUrl}/organizations/${org_id}/settings/integrations?connected=linear`;
    }
    const state = Buffer.from(JSON.stringify(statePayload)).toString('base64');
    const authUrl = `https://linear.app/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&response_type=code&scope=${encodeURIComponent('read,write,issues:create')}&prompt=consent`;
    res.json({ redirectUrl: authUrl });
  } catch (error: any) {
    console.error('Linear org install error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/linear/org-callback', async (req, res) => {
  const { code, state, error } = req.query;
  const frontendUrl = getFrontendUrl();

  const buildErrorRedirect = (msg: string) => {
    let target = `${frontendUrl}?error=linear&message=${encodeURIComponent(msg)}`;
    if (state && typeof state === 'string') {
      try {
        const stateData = JSON.parse(Buffer.from(state, 'base64').toString());
        if (stateData.orgId) {
          target = `${frontendUrl}/organizations/${stateData.orgId}/settings/integrations?error=linear&message=${encodeURIComponent(msg)}`;
        }
      } catch { /* use root fallback */ }
    }
    return target;
  };

  if (error) {
    return res.redirect(buildErrorRedirect(error as string));
  }
  if (!code) {
    return res.redirect(buildErrorRedirect('No authorization code'));
  }

  try {
    let userId: string;
    let orgId: string;
    let projectId: string | undefined;
    let teamId: string | undefined;
    let successRedirect: string | undefined;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
      orgId = stateData.orgId;
      projectId = stateData.projectId;
      teamId = stateData.teamId;
      successRedirect = stateData.successRedirect;
      if (!projectId && !teamId && successRedirect) {
        const teamMatch = successRedirect.match(/\/organizations\/[^/]+\/teams\/([^/]+)\/settings\/notifications/);
        const projectMatch = successRedirect.match(/\/organizations\/[^/]+\/projects\/([^/]+)\/settings/);
        if (teamMatch) teamId = teamMatch[1];
        else if (projectMatch) projectId = projectMatch[1];
      }
    } catch {
      return res.redirect(`${frontendUrl}?error=linear&message=Invalid state`);
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();
    if (!membership) {
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=linear&message=Not authorized`);
    }

    const backendUrl = getBackendUrl();
    const redirectUri = `${backendUrl}/api/integrations/linear/org-callback`;

    const tokenRes = await fetch('https://api.linear.app/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.LINEAR_CLIENT_ID!,
        client_secret: process.env.LINEAR_CLIENT_SECRET!,
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: redirectUri,
      }),
    });
    const tokenData = await tokenRes.json() as any;

    if (tokenData.error) {
      console.error('Linear OAuth error:', tokenData.error);
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=linear&message=${encodeURIComponent(tokenData.error_description || tokenData.error || 'Unknown error')}`);
    }

    let displayName = 'Linear Workspace';
    let orgKey: string | null = null;
    try {
      const gqlRes = await fetch('https://api.linear.app/graphql', {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokenData.access_token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: '{ organization { id name urlKey } }' }),
      });
      const gqlData = await gqlRes.json() as any;
      if (gqlData.data?.organization) {
        displayName = gqlData.data.organization.name;
        orgKey = gqlData.data.organization.id;
      }
    } catch (_) { /* use defaults */ }

    const linearInsert = {
      provider: 'linear',
      installation_id: orgKey,
      display_name: displayName,
      access_token: tokenData.access_token,
      status: 'connected',
      metadata: { linear_org_id: orgKey, scope: tokenData.scope },
      connected_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    } as any;

    const redirectOnSuccess = successRedirect || `${frontendUrl}/organizations/${orgId}/settings/integrations?connected=linear`;

    if (projectId) {
      const { data: proj } = await supabase.from('projects').select('id').eq('id', projectId).eq('organization_id', orgId).single();
      if (!proj) {
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=linear&message=Project not found`);
      }
      const { error: dbError } = await supabase.from('project_integrations').insert({ project_id: projectId, ...linearInsert });
      if (dbError) {
        console.error('Linear project integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/projects/${projectId}/settings?error=linear&message=Failed to save integration`);
      }
      res.redirect(redirectOnSuccess);
    } else if (teamId) {
      const { data: team } = await supabase.from('teams').select('id').eq('id', teamId).eq('organization_id', orgId).single();
      if (!team) {
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=linear&message=Team not found`);
      }
      const { error: dbError } = await supabase.from('team_integrations').insert({ team_id: teamId, ...linearInsert });
      if (dbError) {
        console.error('Linear team integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/teams/${teamId}/settings/notifications?error=linear&message=Failed to save integration`);
      }
      res.redirect(redirectOnSuccess);
    } else {
      const { error: dbError } = await supabase.from('organization_integrations').insert({ organization_id: orgId, ...linearInsert });
      if (dbError) {
        console.error('Linear org integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=linear&message=Failed to save integration`);
      }
      try { await emitEvent({ type: 'integration_connected', organizationId: orgId, payload: { provider: 'linear', displayName }, source: 'system', priority: 'normal' }); } catch (e) {}
      res.redirect(redirectOnSuccess);
    }
  } catch (err: any) {
    console.error('Linear org callback error:', err);
    const frontendUrl = getFrontendUrl();
    res.redirect(`${frontendUrl}?error=linear&message=${encodeURIComponent(err.message || 'Unknown error')}`);
  }
});

router.get('/asana/install', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { org_id, project_id } = req.query;
    if (!org_id || typeof org_id !== 'string') {
      return res.status(400).json({ error: 'Organization ID is required' });
    }
    const clientId = process.env.ASANA_CLIENT_ID;
    if (!clientId) {
      return res.status(500).json({ error: 'Asana client ID not configured' });
    }
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', org_id)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }
    if (project_id && typeof project_id === 'string') {
      const { data: proj } = await supabase.from('projects').select('id').eq('id', project_id).eq('organization_id', org_id).single();
      if (!proj) return res.status(400).json({ error: 'Project not found' });
    }
    const backendUrl = getBackendUrl();
    const redirectUri = `${backendUrl}/api/integrations/asana/org-callback`;
    const statePayload: { userId: string; orgId: string; projectId?: string } = { userId: req.user!.id, orgId: org_id };
    if (project_id && typeof project_id === 'string') statePayload.projectId = project_id;
    const state = Buffer.from(JSON.stringify(statePayload)).toString('base64');
    const authUrl = `https://app.asana.com/-/oauth_authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}&response_type=code`;
    res.json({ redirectUrl: authUrl });
  } catch (error: any) {
    console.error('Asana org install error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/asana/org-callback', async (req, res) => {
  const { code, state, error } = req.query;
  const frontendUrl = getFrontendUrl();

  const buildErrorRedirect = (msg: string) => {
    let target = `${frontendUrl}?error=asana&message=${encodeURIComponent(msg)}`;
    if (state && typeof state === 'string') {
      try {
        const stateData = JSON.parse(Buffer.from(state, 'base64').toString());
        if (stateData.orgId) {
          target = `${frontendUrl}/organizations/${stateData.orgId}/settings/integrations?error=asana&message=${encodeURIComponent(msg)}`;
        }
      } catch { /* use root fallback */ }
    }
    return target;
  };

  if (error) {
    return res.redirect(buildErrorRedirect(error as string));
  }
  if (!code) {
    return res.redirect(buildErrorRedirect('No authorization code'));
  }

  try {
    let userId: string;
    let orgId: string;
    let projectId: string | undefined;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
      orgId = stateData.orgId;
      projectId = stateData.projectId;
    } catch {
      return res.redirect(`${frontendUrl}?error=asana&message=Invalid state`);
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();
    if (!membership) {
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=asana&message=Not authorized`);
    }

    const backendUrl = getBackendUrl();
    const redirectUri = `${backendUrl}/api/integrations/asana/org-callback`;

    const tokenRes = await fetch('https://app.asana.com/-/oauth_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.ASANA_CLIENT_ID!,
        client_secret: process.env.ASANA_CLIENT_SECRET!,
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: redirectUri,
      }),
    });
    const tokenData = await tokenRes.json() as any;

    if (tokenData.error) {
      console.error('Asana OAuth error:', tokenData.error);
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=asana&message=${encodeURIComponent(tokenData.error_description || tokenData.error || 'Unknown error')}`);
    }

    let displayName = 'Asana Workspace';
    let workspaceGid: string | null = null;
    try {
      const meRes = await fetch('https://app.asana.com/api/1.0/users/me?opt_fields=workspaces,workspaces.name', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      const meData = await meRes.json() as any;
      const workspace = meData.data?.workspaces?.[0];
      if (workspace) {
        displayName = workspace.name;
        workspaceGid = workspace.gid;
      }
    } catch (_) { /* use defaults */ }

    const asanaInsert = {
      provider: 'asana',
      installation_id: workspaceGid,
      display_name: displayName,
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token || null,
      status: 'connected',
      metadata: { workspace_gid: workspaceGid, workspace_name: displayName },
      connected_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    } as any;

    if (projectId) {
      const { data: proj } = await supabase.from('projects').select('id').eq('id', projectId).eq('organization_id', orgId).single();
      if (!proj) {
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=asana&message=Project not found`);
      }
      const { error: dbError } = await supabase.from('project_integrations').insert({ project_id: projectId, ...asanaInsert });
      if (dbError) {
        console.error('Asana project integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/projects/${projectId}/settings?error=asana&message=Failed to save integration`);
      }
      res.redirect(`${frontendUrl}/organizations/${orgId}/projects/${projectId}/settings?connected=asana`);
    } else {
      const { error: dbError } = await supabase.from('organization_integrations').insert({ organization_id: orgId, ...asanaInsert });
      if (dbError) {
        console.error('Asana org integration DB error:', dbError);
        return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=asana&message=Failed to save integration`);
      }
      try { await emitEvent({ type: 'integration_connected', organizationId: orgId, payload: { provider: 'asana', displayName }, source: 'system', priority: 'normal' }); } catch (e) {}
      res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?connected=asana`);
    }
  } catch (err: any) {
    console.error('Asana org callback error:', err);
    const frontendUrl = getFrontendUrl();
    res.redirect(`${frontendUrl}?error=asana&message=${encodeURIComponent(err.message || 'Unknown error')}`);
  }
});

// ============================================================
// CONNECTIONS CRUD: list all + delete by id
// ============================================================
router.get('/organizations/:orgId/connections', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { orgId } = req.params;
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }

    const { data, error: dbError } = await supabase
      .from('organization_integrations')
      .select('id, organization_id, provider, installation_id, display_name, metadata, status, connected_at, created_at, updated_at')
      .eq('organization_id', orgId)
      .eq('status', 'connected')
      .in('provider', ['github', 'gitlab', 'bitbucket', 'slack', 'discord', 'jira', 'linear', 'asana', 'custom_notification', 'custom_ticketing', 'email'])
      .order('created_at', { ascending: true });
    if (dbError) {
      return res.status(500).json({ error: dbError.message });
    }
    res.json(data || []);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/organizations/:orgId/connections/:connectionId', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { orgId, connectionId } = req.params;
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }

    const { data: connection } = await supabase
      .from('organization_integrations')
      .select('*')
      .eq('id', connectionId)
      .eq('organization_id', orgId)
      .single();

    if (!connection) {
      return res.status(404).json({ error: 'Connection not found' });
    }

    if (connection.provider === 'github' && connection.installation_id) {
      await supabase
        .from('organizations')
        .update({ github_installation_id: null, updated_at: new Date().toISOString() })
        .eq('id', orgId)
        .eq('github_installation_id', connection.installation_id);
    }

    const { error: deleteError } = await supabase
      .from('organization_integrations')
      .delete()
      .eq('id', connectionId)
      .eq('organization_id', orgId);

    if (deleteError) {
      return res.status(500).json({ error: deleteError.message });
    }

    try { await emitEvent({ type: 'integration_disconnected', organizationId: orgId, payload: { provider: connection.provider, displayName: connection.display_name }, source: 'system', priority: 'normal' }); } catch (e) {}

    // Return URL for user to revoke/uninstall on provider side (GitHub uses installationId; GitLab/Bitbucket use revokeUrl)
    let revokeUrl: string | undefined;
    if (connection.provider === 'gitlab') {
      const gitlabUrl = process.env.GITLAB_URL || 'https://gitlab.com';
      revokeUrl = `${gitlabUrl.replace(/\/$/, '')}/-/user_settings/applications`;
    } else if (connection.provider === 'bitbucket') {
      revokeUrl = 'https://bitbucket.org/account/settings/applications/';
    } else if (connection.provider === 'slack') {
      revokeUrl = 'https://app.slack.com/';
    } else if (connection.provider === 'discord') {
      // If we have guild_id, take user to their server so they can remove the bot from Server Settings → Integrations
      const guildId = connection.installation_id || connection.metadata?.guild_id;
      revokeUrl = guildId
        ? `https://discord.com/channels/${guildId}`
        : 'https://discord.com/developers/applications';
    }

    res.json({
      success: true,
      provider: connection.provider,
      installationId: connection.installation_id ?? undefined,
      revokeUrl,
    });
  } catch (error: any) {
    console.error('Delete connection error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// EMAIL NOTIFICATIONS (store email addresses for future alerts)
// ============================================================
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

router.post('/organizations/:orgId/email-notifications', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { orgId } = req.params;
    const { email } = req.body;

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'email is required' });
    }
    const normalizedEmail = email.trim().toLowerCase();
    if (!normalizedEmail) {
      return res.status(400).json({ error: 'email is required' });
    }
    if (!EMAIL_REGEX.test(normalizedEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }

    const { data, error: dbError } = await supabase
      .from('organization_integrations')
      .insert({
        organization_id: orgId,
        provider: 'email',
        installation_id: crypto.randomUUID(),
        display_name: normalizedEmail,
        status: 'connected',
        metadata: { email: normalizedEmail },
        connected_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      } as any)
      .select('id')
      .single();

    if (dbError) {
      console.error('Email notification DB error:', dbError);
      return res.status(500).json({ error: 'Failed to add email notification' });
    }

    res.json({ success: true, id: data?.id });
  } catch (error: any) {
    console.error('Add email notification error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// CUSTOM / BYO INTEGRATIONS (webhook with HMAC signing)
// ============================================================

router.post('/organizations/:orgId/custom-integrations', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { orgId } = req.params;
    const { name, type, webhook_url, icon_url } = req.body;

    if (!name || !type || !webhook_url) {
      return res.status(400).json({ error: 'name, type (notification|ticketing), and webhook_url are required' });
    }
    const trimmedUrl = String(webhook_url).trim();
    if (!/^https:\/\/[^\s]+$/i.test(trimmedUrl)) {
      return res.status(400).json({ error: 'webhook_url must start with https://' });
    }
    if (type !== 'notification' && type !== 'ticketing') {
      return res.status(400).json({ error: 'type must be "notification" or "ticketing"' });
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }

    const secret = `whsec_${crypto.randomBytes(32).toString('hex')}`;
    const provider = type === 'notification' ? 'custom_notification' : 'custom_ticketing';

    const { data, error: dbError } = await supabase
      .from('organization_integrations')
      .insert({
        organization_id: orgId,
        provider,
        installation_id: crypto.randomUUID(),
        display_name: name,
        access_token: secret,
        status: 'connected',
        metadata: {
          webhook_url: trimmedUrl,
          icon_url: icon_url || null,
          custom_name: name,
          type,
        },
        connected_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      } as any)
      .select('id')
      .single();

    if (dbError) {
      console.error('Custom integration DB error:', dbError);
      return res.status(500).json({ error: 'Failed to create custom integration' });
    }

    res.json({ success: true, id: data?.id, secret });
  } catch (error: any) {
    console.error('Create custom integration error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.put('/organizations/:orgId/custom-integrations/:id', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { orgId, id } = req.params;
    const { name, webhook_url, icon_url, regenerate_secret } = req.body;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }

    const { data: existing } = await supabase
      .from('organization_integrations')
      .select('*')
      .eq('id', id)
      .eq('organization_id', orgId)
      .in('provider', ['custom_notification', 'custom_ticketing'])
      .single();
    if (!existing) {
      return res.status(404).json({ error: 'Custom integration not found' });
    }

    const updates: Record<string, any> = { updated_at: new Date().toISOString() };
    const metadataUpdates = { ...existing.metadata };
    let newSecret: string | undefined;

    if (name) {
      updates.display_name = name;
      metadataUpdates.custom_name = name;
    }
    if (webhook_url !== undefined) {
      const trimmedUrl = String(webhook_url).trim();
      if (!/^https:\/\/[^\s]+$/i.test(trimmedUrl)) {
        return res.status(400).json({ error: 'webhook_url must start with https://' });
      }
      metadataUpdates.webhook_url = trimmedUrl;
    }
    if (icon_url !== undefined) {
      metadataUpdates.icon_url = icon_url;
    }
    if (regenerate_secret) {
      newSecret = `whsec_${crypto.randomBytes(32).toString('hex')}`;
      updates.access_token = newSecret;
    }

    updates.metadata = metadataUpdates;

    const { error: dbError } = await supabase
      .from('organization_integrations')
      .update(updates)
      .eq('id', id)
      .eq('organization_id', orgId);

    if (dbError) {
      return res.status(500).json({ error: dbError.message });
    }

    res.json({ success: true, ...(newSecret ? { secret: newSecret } : {}) });
  } catch (error: any) {
    console.error('Update custom integration error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/organizations/:orgId/custom-integrations/:id/test', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { orgId, id } = req.params;
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }

    const { data: integration } = await supabase
      .from('organization_integrations')
      .select('id, access_token, metadata')
      .eq('id', id)
      .eq('organization_id', orgId)
      .in('provider', ['custom_notification', 'custom_ticketing'])
      .single();
    if (!integration) {
      return res.status(404).json({ error: 'Custom integration not found' });
    }

    const webhookUrl = integration.metadata?.webhook_url;
    if (!webhookUrl || typeof webhookUrl !== 'string') {
      return res.status(400).json({ error: 'Webhook URL not configured' });
    }

    const secret = integration.access_token;
    const payload = JSON.stringify({
      event: 'test.ping',
      timestamp: new Date().toISOString(),
      organization_id: orgId,
      data: { message: 'This is a test ping from Deptex. Your webhook is configured correctly.' },
    });
    const signature = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Deptex-Signature': signature,
        'X-Deptex-Event': 'test.ping',
      },
      body: payload,
      signal: controller.signal,
    });
    clearTimeout(timeout);

    res.json({
      success: response.ok,
      status: response.status,
      statusText: response.statusText,
      message: response.ok ? 'Test ping sent successfully.' : `Request failed with status ${response.status}.`,
    });
  } catch (error: any) {
    if (error.name === 'AbortError') {
      return res.status(504).json({ error: 'Request timed out. The webhook endpoint did not respond within 10 seconds.' });
    }
    console.error('Custom integration test ping error:', error);
    res.status(500).json({ error: error.message || 'Failed to send test ping.' });
  }
});

router.post('/organizations/:orgId/custom-integrations/upload-icon', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const { orgId } = req.params;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', req.user!.id)
      .single();
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }

    const contentType = req.headers['content-type'] || '';
    if (!contentType.startsWith('image/png') && !contentType.startsWith('image/jpeg') && !contentType.startsWith('image/webp')) {
      return res.status(400).json({ error: 'Only PNG, JPEG, and WebP images are supported' });
    }

    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.from(chunk));
    }
    const buffer = Buffer.concat(chunks);

    if (buffer.length > 256 * 1024) {
      return res.status(400).json({ error: 'Image must be under 256KB' });
    }

    const ext = contentType.includes('png') ? 'png' : contentType.includes('webp') ? 'webp' : 'jpg';
    const fileName = `${orgId}/${crypto.randomUUID()}.${ext}`;

    const { error: uploadError } = await supabase.storage
      .from('integration-icons')
      .upload(fileName, buffer, { contentType, upsert: false });

    if (uploadError) {
      console.error('Icon upload error:', uploadError);
      return res.status(500).json({ error: 'Failed to upload icon' });
    }

    const { data: urlData } = supabase.storage
      .from('integration-icons')
      .getPublicUrl(fileName);

    res.json({ url: urlData.publicUrl });
  } catch (error: any) {
    console.error('Icon upload error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
