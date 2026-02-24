import express from 'express';
import { supabase } from '../lib/supabase';

const router = express.Router();

/** Base URL of this backend (no trailing slash). */
function getBackendUrl(): string {
  const url = process.env.BACKEND_URL || `http://localhost:${process.env.PORT || 3001}`;
  return url.replace(/\/$/, '');
}

/** Base URL of the frontend (no trailing slash). */
function getFrontendUrl(): string {
  const url = process.env.FRONTEND_URL || 'http://localhost:3000';
  return url.replace(/\/$/, '');
}

/** Frontend path GitHub redirects to — so GitHub shows "Redirect to yourapp.com" (your domain), not your backend. */
const GITHUB_CALLBACK_PATH = '/auth/callback';

/**
 * Start GitHub OAuth for login. Callback URL is on the frontend (e.g. deptex.dev/auth/callback)
 * so GitHub displays your app domain, not the backend.
 */
router.get('/github', (req, res) => {
  const clientId = process.env.GITHUB_OAUTH_CLIENT_ID;
  if (!clientId) {
    return res.redirect(`${getFrontendUrl()}/login?error=github_config`);
  }
  const returnTo = (req.query.returnTo as string) || '/organizations';
  const state = Buffer.from(JSON.stringify({ returnTo })).toString('base64url');
  const redirectUri = `${getFrontendUrl()}${GITHUB_CALLBACK_PATH}`;
  const scope = 'read:user user:email';
  const url = `https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scope)}&state=${encodeURIComponent(state)}`;
  res.redirect(url);
});

/**
 * Exchange GitHub OAuth code for a session. Called by the frontend from /auth/callback
 * after GitHub redirects there (so GitHub shows your app domain). Returns magic link URL
 * so the frontend can complete the sign-in.
 */
router.post('/github/exchange', async (req, res) => {
  const frontendUrl = getFrontendUrl();
  const { code, state } = req.body || {};

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'No authorization code' });
  }

  let returnTo = '/organizations';
  if (state && typeof state === 'string') {
    try {
      const decoded = JSON.parse(Buffer.from(state, 'base64url').toString());
      if (decoded.returnTo) returnTo = decoded.returnTo;
    } catch {
      // keep default
    }
  }

  const clientId = process.env.GITHUB_OAUTH_CLIENT_ID;
  const clientSecret = process.env.GITHUB_OAUTH_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return res.status(500).json({ error: 'Server configuration error' });
  }

  const redirectUri = `${frontendUrl}${GITHUB_CALLBACK_PATH}`;

  // Exchange code for access token
  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri }),
  });
  if (!tokenRes.ok) {
    return res.status(502).json({ error: 'Token exchange failed' });
  }
  const tokenData = (await tokenRes.json()) as { access_token?: string; error?: string };
  if (tokenData.error || !tokenData.access_token) {
    return res.status(400).json({ error: tokenData.error || 'No access token' });
  }

  // Fetch user from GitHub
  const userRes = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: 'application/vnd.github.v3+json' },
  });
  if (!userRes.ok) {
    return res.status(502).json({ error: 'Failed to load profile' });
  }
  const ghUser = (await userRes.json()) as {
    id: number;
    login: string;
    email?: string | null;
    name?: string | null;
    avatar_url?: string | null;
  };

  const email = ghUser.email || null;
  if (!email) {
    // GitHub may hide email; try emails endpoint
    const emailsRes = await fetch('https://api.github.com/user/emails', {
      headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: 'application/vnd.github.v3+json' },
    });
    if (emailsRes.ok) {
      const emails = (await emailsRes.json()) as Array<{ email: string; primary?: boolean }>;
      const primary = emails.find((e) => e.primary) || emails[0];
      if (primary) (ghUser as any).email = primary.email;
    }
  }
  const primaryEmail = ghUser.email || (ghUser as any).email;
  if (!primaryEmail) {
    return res.status(400).json({ error: 'GitHub account must have a visible email' });
  }

  // Get or create Supabase user and get a magic link to establish session
  const { data: existingUsers } = await supabase.auth.admin.listUsers({ perPage: 1000 });
  const existing = existingUsers?.users?.find((u) => u.email?.toLowerCase() === primaryEmail.toLowerCase());

  let magicLinkUrl: string;

  if (existing) {
    const { data: linkData, error: linkError } = await supabase.auth.admin.generateLink({
      type: 'magiclink',
      email: primaryEmail,
    });
    if (linkError || !linkData?.properties?.action_link) {
      console.error('Auth generateLink error:', linkError);
      return res.status(502).json({ error: 'Session error' });
    }
    magicLinkUrl = (linkData.properties as { action_link?: string }).action_link!;
  } else {
    // Create user then generate magic link
    const { error: createError } = await supabase.auth.admin.createUser({
      email: primaryEmail,
      email_confirm: true,
      user_metadata: {
        full_name: ghUser.name || ghUser.login,
        avatar_url: ghUser.avatar_url,
        user_name: ghUser.login,
        provider: 'github',
        provider_id: String(ghUser.id),
      },
    });
    if (createError) {
      // May already exist from another provider
      const { data: linkData, error: linkError } = await supabase.auth.admin.generateLink({
        type: 'magiclink',
        email: primaryEmail,
      });
      if (linkError || !linkData?.properties?.action_link) {
        return res.status(400).json({ error: createError.message });
      }
      magicLinkUrl = (linkData.properties as { action_link?: string }).action_link!;
    } else {
      const { data: linkData, error: linkError } = await supabase.auth.admin.generateLink({
        type: 'magiclink',
        email: primaryEmail,
      });
      if (linkError || !linkData?.properties?.action_link) {
        return res.status(502).json({ error: 'Session error' });
      }
      magicLinkUrl = (linkData.properties as { action_link?: string }).action_link!;
    }
  }

  const redirect = `${frontendUrl}${returnTo.startsWith('/') ? returnTo : `/${returnTo}`}`;
  const separator = magicLinkUrl.includes('?') ? '&' : '?';
  const finalUrl = `${magicLinkUrl}${separator}redirect_to=${encodeURIComponent(redirect)}`;
  return res.json({ magicLinkUrl: finalUrl });
});

export default router;
