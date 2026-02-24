import express from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import {
  createInstallationToken,
  getInstallationAccount,
  getCompareChangedFiles,
  getRepositoryFileContent,
  listCheckRunsForRef,
  createCheckRun,
  updateCheckRun,
  createIssueComment,
  type CheckRunOutput,
} from '../lib/github';
import { queueASTParsingJob } from '../lib/redis';
import { invalidateProjectCaches } from '../lib/cache';
import { extractDependencies } from './workers';
import { getEffectivePolicies, isLicenseAllowed } from '../lib/project-policies';
import { getVulnCountsForPackageVersion, exceedsThreshold, type VulnCounts } from '../lib/vuln-counts';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const PR_GUARDRAILS_CHECK_NAME = 'Deptex PR guardrails';

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
    
    // Return installation_id so frontend can open GitHub's uninstall page
    res.json({ success: true, installationId });
  } catch (error: any) {
    console.error('GitHub App disconnect error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// Push event: re-extract dependencies and conditionally queue AST
// ============================================================
type PushProjectRow = {
  project_id: string;
  default_branch: string;
  package_json_path: string | null;
  installation_id: string;
  projects: { organization_id: string }[] | { organization_id: string } | null;
};

async function handlePushEvent(payload: any): Promise<void> {
  const repoFullName = payload.repository?.full_name;
  const ref = payload.ref; // e.g. refs/heads/main
  const installationId = payload.installation?.id;
  const before = payload.before;
  const after = payload.after;

  if (!repoFullName || !ref || !installationId) {
    console.log('[webhook push] Missing repository.full_name, ref, or installation.id; skipping.');
    return;
  }
  // Branch deleted (e.g. after is all zeros)
  if (!after || /^0+$/.test(String(after))) {
    return;
  }

  const { data: rows, error: fetchError } = await supabase
    .from('project_repositories')
    .select('project_id, default_branch, package_json_path, installation_id, projects(organization_id)')
    .eq('repo_full_name', repoFullName);

  if (fetchError) {
    console.error('[webhook push] Failed to fetch project_repositories:', fetchError);
    return;
  }
  const expectedRef = (branch: string) => `refs/heads/${branch}`;
  const rowList = (rows ?? []) as PushProjectRow[];
  const projects = rowList.filter(
    (r) => r.default_branch && ref === expectedRef(r.default_branch)
  );
  if (projects.length === 0) {
    return;
  }

  const repoRecord = {
    repo_full_name: repoFullName,
    default_branch: projects[0].default_branch,
    installation_id: projects[0].installation_id,
    package_json_path: (projects[0].package_json_path ?? '').trim(),
  };

  for (const row of projects) {
    const proj = row.projects;
    const organizationId = Array.isArray(proj) ? proj[0]?.organization_id : proj?.organization_id;
    if (!organizationId) continue;
    try {
      const result = await extractDependencies(row.project_id, organizationId, {
        installation_id: Number(row.installation_id),
        repo_full_name: repoRecord.repo_full_name,
        default_branch: row.default_branch,
        package_json_path: (row.package_json_path ?? '').trim(),
      });
      await invalidateProjectCaches(organizationId, row.project_id).catch(() => {});
      console.log('[webhook push] Extracted dependencies for project', row.project_id, result);
    } catch (err: any) {
      console.error('[webhook push] Extract failed for project', row.project_id, err?.message || err);
    }
  }

  let changedFiles: string[] = [];
  try {
    const token = await createInstallationToken(String(installationId));
    changedFiles = await getCompareChangedFiles(token, repoFullName, before, after);
  } catch (err: any) {
    console.error('[webhook push] Compare API failed; skipping AST eligibility:', err?.message || err);
  }

  function isFileInWorkspace(filePath: string, packageJsonPath: string): boolean {
    const workspace = (packageJsonPath ?? '').trim();
    if (workspace === '') return true; // root: any file counts
    return filePath === workspace || filePath.startsWith(workspace + '/');
  }

  for (const row of projects) {
    const workspacePath = (row.package_json_path ?? '').trim();
    const shouldRunAst = changedFiles.some((f) => isFileInWorkspace(f, workspacePath));
    if (!shouldRunAst) continue;
    const ok = await queueASTParsingJob(row.project_id, {
      repo_full_name: repoFullName,
      installation_id: row.installation_id,
      default_branch: row.default_branch,
      package_json_path: (row.package_json_path ?? '').trim(),
    });
    if (!ok.success) {
      console.warn('[webhook push] AST job not queued for project', row.project_id, ok.error);
    }
  }
}

/**
 * Verify GitHub webhook signature (HMAC-SHA256).
 * Uses req.rawBody which must be set by express.json verify callback.
 */
function verifyGitHubWebhookSignature(req: express.Request): boolean {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) {
    console.warn('GITHUB_WEBHOOK_SECRET not set; skipping webhook signature verification.');
    return true;
  }
  const signature = req.headers['x-hub-signature-256'] as string | undefined;
  if (!signature || !signature.startsWith('sha256=')) {
    return false;
  }
  const rawBody = (req as any).rawBody;
  if (typeof rawBody !== 'string') {
    return false;
  }
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature, 'utf8'), Buffer.from(expected, 'utf8'));
}

// GitHub webhook handler (exported for direct mounting)
export async function githubWebhookHandler(req: express.Request, res: express.Response) {
  try {
    if (!verifyGitHubWebhookSignature(req)) {
      res.status(401).json({ error: 'Invalid webhook signature' });
      return;
    }

    const event = req.headers['x-github-event'];
    const payload = req.body;
    
    console.log('GitHub webhook received:', event, payload?.action || '');
    
    // Handle different event types
    switch (event) {
      case 'installation':
        await handleInstallationEvent(payload);
        break;
      case 'installation_repositories':
        // Handle repository selection changes
        console.log('GitHub App repository selection changed:', {
          action: payload.action,
          installation_id: payload.installation?.id,
          repositories_added: payload.repositories_added?.map((r: any) => r.full_name),
          repositories_removed: payload.repositories_removed?.map((r: any) => r.full_name),
        });
        break;
      case 'push':
        console.log('GitHub push event received:', {
          repository: payload.repository?.full_name,
          ref: payload.ref,
          pusher: payload.pusher?.name,
        });
        await handlePushEvent(payload);
        break;
      case 'pull_request':
        if (['opened', 'synchronize', 'reopened'].includes(payload?.action)) {
          handlePullRequestEvent(payload).catch((err) =>
            console.error('[PR guardrails]', err?.message || err)
          );
        }
        break;
      case 'repository':
        // Handle repository creation/deletion
        console.log('GitHub repository event:', payload.action, payload.repository?.full_name);
        break;
      default:
        console.log('Unhandled GitHub event:', event);
    }
    
    // Always respond with 200 to acknowledge receipt
    res.json({ received: true });
  } catch (error: any) {
    console.error('GitHub webhook error:', error);
    // Still return 200 to prevent GitHub from retrying
    res.status(200).json({ received: true, error: error.message });
  }
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

  if (!repoFullName || !baseSha || !headSha || !prNumber || !installationId) {
    console.log('[PR guardrails] Missing repo, refs, pr number, or installation; skipping.');
    return;
  }

  let token: string;
  try {
    token = await createInstallationToken(installationId);
  } catch (err: any) {
    console.error('[PR guardrails] Failed to get installation token:', err?.message);
    return;
  }

  let changedFiles: string[] = [];
  try {
    changedFiles = await getCompareChangedFiles(token, repoFullName, baseSha, headSha);
  } catch (err: any) {
    console.error('[PR guardrails] getCompareChangedFiles failed:', err?.message);
    return;
  }

  const affectedWorkspaces = new Set<string>();
  for (const filePath of changedFiles) {
    if (filePath === 'package.json' || filePath === 'package-lock.json') {
      affectedWorkspaces.add('');
      continue;
    }
    const match = filePath.match(/^(.+)\/(?:package\.json|package-lock\.json)$/);
    if (match) affectedWorkspaces.add(match[1]);
  }
  if (affectedWorkspaces.size === 0) {
    console.log('[PR guardrails] No package.json or package-lock.json changed; skipping.');
    return;
  }

  const packageJsonPaths = [...affectedWorkspaces];

  const { data: projectRows, error: fetchError } = await supabase
    .from('project_repositories')
    .select('project_id, package_json_path, installation_id, projects(name, organization_id)')
    .eq('repo_full_name', repoFullName)
    .in('package_json_path', packageJsonPaths);

  if (fetchError || !projectRows?.length) {
    console.log('[PR guardrails] No linked projects for this repo and affected paths.');
    return;
  }

  type WorkspaceResult = {
    projectName: string;
    packageJsonPath: string;
    commentBody: string;
    blocked: boolean;
  };

  const results: WorkspaceResult[] = [];
  let anyBlocked = false;

  for (const row of projectRows as any[]) {
    const projectId = row.project_id;
    const packageJsonPath = (row.package_json_path ?? '').trim();
    const organizationId = row.projects?.organization_id;
    const projectName = row.projects?.name || 'Project';

    if (!organizationId) continue;

    const { data: guardrailsRow } = await supabase
      .from('project_pr_guardrails')
      .select('*')
      .eq('project_id', projectId)
      .single();
    const guardrails = guardrailsRow as {
      block_critical_vulns?: boolean;
      block_high_vulns?: boolean;
      block_medium_vulns?: boolean;
      block_low_vulns?: boolean;
      block_policy_violations?: boolean;
      block_transitive_vulns?: boolean;
    } | null;

    const hasVulnBlocking =
      guardrails?.block_critical_vulns ||
      guardrails?.block_high_vulns ||
      guardrails?.block_medium_vulns ||
      guardrails?.block_low_vulns;
    if (!guardrails || (!hasVulnBlocking && !guardrails.block_policy_violations && !guardrails.block_transitive_vulns)) {
      continue;
    }

    const { acceptedLicenses } = await getEffectivePolicies(organizationId, projectId);

    const pkgPath = packageJsonPath ? `${packageJsonPath}/package.json` : 'package.json';
    const lockPath = packageJsonPath ? `${packageJsonPath}/package-lock.json` : 'package-lock.json';

    let basePkg: Record<string, string> = {};
    let headPkg: Record<string, string> = {};
    let baseLock: any = null;
    let headLock: any = null;

    try {
      const basePkgContent = await getRepositoryFileContent(token, repoFullName, pkgPath, baseSha);
      basePkg = getDirectDepsFromPackageJson(JSON.parse(basePkgContent));
    } catch {
      // base might not have this workspace
    }
    try {
      const headPkgContent = await getRepositoryFileContent(token, repoFullName, pkgPath, headSha);
      headPkg = getDirectDepsFromPackageJson(JSON.parse(headPkgContent));
    } catch {
      // skip this workspace
      continue;
    }
    try {
      const baseLockContent = await getRepositoryFileContent(token, repoFullName, lockPath, baseSha);
      baseLock = JSON.parse(baseLockContent);
    } catch {
      // no base lock
    }
    try {
      const headLockContent = await getRepositoryFileContent(token, repoFullName, lockPath, headSha);
      headLock = JSON.parse(headLockContent);
    } catch {
      // no head lock
    }

    const directAdded: Array<{ name: string; version: string }> = [];
    const directBumped: Array<{ name: string; oldVersion: string; newVersion: string }> = [];

    for (const [name, _spec] of Object.entries(headPkg)) {
      const newVersion = headLock ? getResolvedVersion(headLock, name) : null;
      if (!newVersion) continue;
      if (!(name in basePkg)) {
        directAdded.push({ name, version: newVersion });
      } else {
        const oldVersion = baseLock ? getResolvedVersion(baseLock, name) : null;
        if (oldVersion && oldVersion !== newVersion) {
          directBumped.push({ name, oldVersion, newVersion });
        }
      }
    }

    let transitiveToCheck: Array<{ name: string; version: string }> = [];
    if (guardrails.block_transitive_vulns && headLock && baseLock) {
      const baseSet = getLockfilePackagesSet(baseLock);
      const headSet = getLockfilePackagesSet(headLock);
      const directNames = new Set([...Object.keys(basePkg), ...Object.keys(headPkg)]);
      for (const key of headSet) {
        if (baseSet.has(key)) continue;
        const idx = key.lastIndexOf('@');
        const name = idx >= 0 ? key.slice(0, idx) : key;
        const version = idx >= 0 ? key.slice(idx + 1) : '';
        if (directNames.has(name) || !version) continue;
        transitiveToCheck.push({ name, version });
      }
    }

    const lines: string[] = [];
    const workspaceLabel = packageJsonPath || 'Root';
    lines.push(`## Deptex — ${projectName} (${workspaceLabel})`);
    lines.push('');

    let workspaceBlocked = false;

    const checkPackage = async (
      name: string,
      version: string
    ): Promise<{ vulnCounts: VulnCounts; license: string | null; policyViolation: boolean }> => {
      const vulnCounts = await getVulnCountsForPackageVersion(supabase, name, version);
      const license = await getLicenseForPackage(name, version);
      const policyViolation = Boolean(
        guardrails.block_policy_violations &&
        acceptedLicenses.length > 0 &&
        isLicenseAllowed(license, acceptedLicenses) === false
      );

      if (guardrails.block_policy_violations && acceptedLicenses.length > 0 && policyViolation) {
        workspaceBlocked = true;
      }
      if (hasVulnBlocking) {
        if (guardrails.block_critical_vulns && exceedsThreshold(vulnCounts, 'critical')) workspaceBlocked = true;
        if (guardrails.block_high_vulns && exceedsThreshold(vulnCounts, 'high')) workspaceBlocked = true;
        if (guardrails.block_medium_vulns && exceedsThreshold(vulnCounts, 'medium')) workspaceBlocked = true;
        if (guardrails.block_low_vulns && exceedsThreshold(vulnCounts, 'low')) workspaceBlocked = true;
      }

      return { vulnCounts, license, policyViolation };
    };

    const fmtVuln = (v: VulnCounts) =>
      [v.critical_vulns, v.high_vulns, v.medium_vulns, v.low_vulns].some((n) => n > 0)
        ? `${v.critical_vulns} critical, ${v.high_vulns} high, ${v.medium_vulns} medium, ${v.low_vulns} low vulnerabilities`
        : '0 vulnerabilities';

    if (directBumped.length > 0) {
      lines.push('### Packages updated');
      for (const { name, oldVersion, newVersion } of directBumped) {
        const { vulnCounts } = await checkPackage(name, newVersion);
        lines.push(`- **${name}** \`${oldVersion}\` → \`${newVersion}\` — ${fmtVuln(vulnCounts)}`);
      }
      lines.push('');
    }

    if (directAdded.length > 0) {
      lines.push('### Packages added');
      for (const { name, version } of directAdded) {
        const { vulnCounts, license, policyViolation } = await checkPackage(name, version);
        const licStr = license ?? 'Unknown';
        const policyStr = policyViolation ? ' **(does not comply with project policy)**' : '';
        lines.push(`- **${name}** \`${version}\` — license: ${licStr}; ${fmtVuln(vulnCounts)}${policyStr}`);
      }
      lines.push('');
    }

    if (transitiveToCheck.length > 0) {
      lines.push('### Transitive dependencies (new/updated)');
      for (const { name, version } of transitiveToCheck) {
        const { vulnCounts, license, policyViolation } = await checkPackage(name, version);
        const licStr = license ?? 'Unknown';
        const policyStr = policyViolation ? ' **(does not comply with project policy)**' : '';
        lines.push(`- **${name}** \`${version}\` — license: ${licStr}; ${fmtVuln(vulnCounts)}${policyStr}`);
      }
      lines.push('');
    }

    if (workspaceBlocked) {
      lines.push('---');
      lines.push('**This PR cannot be merged until the above issues are resolved.**');
      anyBlocked = true;
    }

    results.push({
      projectName,
      packageJsonPath,
      commentBody: lines.join('\n'),
      blocked: workspaceBlocked,
    });
  }

  for (const r of results) {
    try {
      await createIssueComment(token, repoFullName, prNumber, r.commentBody);
    } catch (err: any) {
      console.error('[PR guardrails] Failed to post comment:', err?.message);
    }
  }

  const checkRunOutput: CheckRunOutput = {
    title: anyBlocked ? 'PR guardrails — failed' : 'PR guardrails — passed',
    summary: anyBlocked
      ? 'One or more dependencies do not meet this project\'s guardrails (vulnerabilities or policy).'
      : 'All checked dependencies meet this project\'s guardrails.',
  };

  try {
    const existing = await listCheckRunsForRef(token, repoFullName, headSha, PR_GUARDRAILS_CHECK_NAME);
    if (existing.length > 0) {
      await updateCheckRun(token, repoFullName, existing[0].id, {
        status: 'completed',
        conclusion: anyBlocked ? 'failure' : 'success',
        output: checkRunOutput,
      });
    } else {
      await createCheckRun(token, repoFullName, headSha, PR_GUARDRAILS_CHECK_NAME, {
        status: 'completed',
        conclusion: anyBlocked ? 'failure' : 'success',
        output: checkRunOutput,
      });
    }
  } catch (err: any) {
    console.error('[PR guardrails] Failed to create/update check run:', err?.message);
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
    const { org_id } = req.query;
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
    const backendUrl = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
    const redirectUri = `${backendUrl}/api/integrations/slack/org-callback`;
    const scopes = 'chat:write,channels:read,channels:history,files:write,incoming-webhook';
    const state = Buffer.from(JSON.stringify({ userId: req.user!.id, orgId: org_id })).toString('base64');
    const authUrl = `https://slack.com/oauth/v2/authorize?client_id=${clientId}&scope=${encodeURIComponent(scopes)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
    res.json({ redirectUrl: authUrl });
  } catch (error: any) {
    console.error('Slack org install error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/slack/org-callback', async (req, res) => {
  const { code, state, error } = req.query;
  const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';

  if (error) {
    return res.redirect(`${frontendUrl}?error=slack&message=${encodeURIComponent(error as string)}`);
  }
  if (!code) {
    return res.redirect(`${frontendUrl}?error=slack&message=No authorization code`);
  }

  try {
    let userId: string;
    let orgId: string;
    try {
      const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = stateData.userId;
      orgId = stateData.orgId;
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
      return res.redirect(`${frontendUrl}?error=slack&message=Not authorized`);
    }

    const backendUrl = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
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

    const { error: dbError } = await supabase
      .from('organization_integrations')
      .insert({
        organization_id: orgId,
        provider: 'slack',
        installation_id: tokenData.team?.id || null,
        display_name: tokenData.team?.name || 'Slack Workspace',
        access_token: tokenData.access_token,
        status: 'connected',
        metadata: {
          bot_user_id: tokenData.bot_user_id,
          team_id: tokenData.team?.id,
          team_name: tokenData.team?.name,
          authed_user_id: tokenData.authed_user?.id,
          scope: tokenData.scope,
          incoming_webhook: tokenData.incoming_webhook || null,
        },
        connected_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      } as any);

    if (dbError) {
      console.error('Slack org integration DB error:', dbError);
      return res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?error=slack&message=Failed to save integration`);
    }

    res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?connected=slack`);
  } catch (err: any) {
    console.error('Slack org callback error:', err);
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(`${frontendUrl}?error=slack&message=${encodeURIComponent(err.message || 'Unknown error')}`);
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
      .in('provider', ['github', 'gitlab', 'bitbucket', 'slack'])
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

    res.json({ success: true, provider: connection.provider, installationId: connection.installation_id });
  } catch (error: any) {
    console.error('Delete connection error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;

