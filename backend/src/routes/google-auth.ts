import { Router, Request, Response } from 'express';

const router = Router();

/**
 * Exchanges a Google OAuth authorization code (from the GIS popup code flow on
 * the login page) for an ID token, which the frontend then hands to
 * supabase.auth.signInWithIdToken().
 *
 * Why this exists: running the Google OAuth ourselves (our client, our domain)
 * lets the consent screen read "continue to deptex.dev" with our branding,
 * instead of Supabase's default "<project-ref>.supabase.co" callback. The code
 * exchange needs the Google client secret, so it has to happen server-side.
 *
 * Only the id_token is returned to the client — never the access or refresh
 * token. The code is single-use and bound to our client_id.
 */
router.post('/google/exchange', async (req: Request, res: Response) => {
  const code = req.body?.code as string | undefined;
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'missing_code' });
  }

  const clientId = process.env.GOOGLE_OAUTH_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_OAUTH_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return res.status(500).json({ error: 'google_oauth_not_configured' });
  }

  try {
    const body = new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      // The GIS popup code flow uses this sentinel rather than a real redirect URI.
      redirect_uri: 'postmessage',
      grant_type: 'authorization_code',
    });

    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const data: any = await tokenResp.json().catch(() => ({}));
    if (!tokenResp.ok || !data.id_token) {
      return res.status(401).json({ error: 'exchange_failed' });
    }

    return res.json({ id_token: data.id_token });
  } catch {
    return res.status(502).json({ error: 'exchange_error' });
  }
});

export default router;
