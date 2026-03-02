import { Request, Response, NextFunction } from 'express';
import { createHash, randomBytes } from 'crypto';
import { supabase } from '../lib/supabase';

export interface AuthRequest extends Request {
  user?: {
    id: string;
    email?: string;
  };
  apiToken?: {
    id: string;
    organizationId: string;
    scopes: string[];
  };
  sessionMeta?: {
    aal: string;
    sessionId: string;
  };
}

const API_TOKEN_PREFIX = 'dptx_';

function hashToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

export function generateApiToken(): { raw: string; prefix: string; hash: string } {
  const hex = randomBytes(20).toString('hex');
  const raw = `${API_TOKEN_PREFIX}${hex}`;
  const prefix = raw.substring(0, 13);
  return { raw, prefix, hash: hashToken(raw) };
}

async function authenticateViaApiToken(
  token: string,
  req: AuthRequest,
  res: Response,
): Promise<boolean> {
  const hash = hashToken(token);

  const { data: tokenRow, error } = await supabase
    .from('api_tokens')
    .select('id, user_id, organization_id, scopes, expires_at, revoked_at')
    .eq('token_hash', hash)
    .is('revoked_at', null)
    .single();

  if (error || !tokenRow) return false;

  if (tokenRow.expires_at && new Date(tokenRow.expires_at) < new Date()) {
    return false;
  }

  const scopes: string[] = tokenRow.scopes || ['read'];
  const method = req.method.toUpperCase();
  const isReadOnly = ['GET', 'HEAD', 'OPTIONS'].includes(method);

  if (!scopes.includes('admin')) {
    if (!isReadOnly && !scopes.includes('write')) {
      res.status(403).json({ error: 'Token scope insufficient', required: 'write', current: scopes });
      return true;
    }
  }

  req.user = { id: tokenRow.user_id };
  req.apiToken = {
    id: tokenRow.id,
    organizationId: tokenRow.organization_id,
    scopes,
  };

  supabase
    .from('api_tokens')
    .update({ last_used_at: new Date().toISOString(), last_used_ip: req.ip || null })
    .eq('id', tokenRow.id)
    .then(() => {});

  return true;
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1], 'base64url').toString('utf-8');
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

export const authenticateUser = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.error('Auth error: Missing or invalid authorization header', {
        hasHeader: !!authHeader,
        header: authHeader ? 'present' : 'missing',
        method: req.method,
        path: req.path,
      });
      return res.status(401).json({ error: 'Missing or invalid authorization header' });
    }

    const token = authHeader.substring(7);

    if (token.startsWith(API_TOKEN_PREFIX)) {
      const handled = await authenticateViaApiToken(token, req, res);
      if (handled && !req.user) return;
      if (req.user) return next();
      return res.status(401).json({ error: 'Invalid or expired API token' });
    }

    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
      console.error('Auth error: Invalid or expired token', { error });
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    req.user = {
      id: user.id,
      email: user.email,
    };

    const payload = decodeJwtPayload(token);
    if (payload) {
      req.sessionMeta = {
        aal: (payload.aal as string) || 'aal1',
        sessionId: (payload.session_id as string) || '',
      };
    }

    trackSession(req).catch(() => {});

    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(401).json({ error: 'Authentication failed' });
  }
};

export const optionalAuth = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);

      if (token.startsWith(API_TOKEN_PREFIX)) {
        await authenticateViaApiToken(token, req, res);
        return next();
      }

      const { data: { user }, error } = await supabase.auth.getUser(token);

      if (!error && user) {
        req.user = {
          id: user.id,
          email: user.email,
        };

        const payload = decodeJwtPayload(token);
        if (payload) {
          req.sessionMeta = {
            aal: (payload.aal as string) || 'aal1',
            sessionId: (payload.session_id as string) || '',
          };
        }
      }
    }

    next();
  } catch (error) {
    next();
  }
};

export async function checkMFACompliance(
  req: AuthRequest,
  orgId: string,
): Promise<{ ok: boolean; error?: string }> {
  const aal = req.sessionMeta?.aal || 'aal1';
  if (aal === 'aal2') return { ok: true };

  if (req.apiToken) return { ok: true };

  const { data: org } = await supabase
    .from('organizations')
    .select('mfa_enforced, mfa_grace_period_days, mfa_enforcement_started_at')
    .eq('id', orgId)
    .single();

  if (!org?.mfa_enforced) return { ok: true };

  if (org.mfa_enforcement_started_at) {
    const started = new Date(org.mfa_enforcement_started_at);
    const graceEnd = new Date(started.getTime() + (org.mfa_grace_period_days || 7) * 86400000);
    if (new Date() < graceEnd) return { ok: true };
  }

  const userId = req.user?.id;
  if (userId) {
    const { data: exemption } = await supabase
      .from('organization_mfa_exemptions')
      .select('id, expires_at')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .gt('expires_at', new Date().toISOString())
      .single();

    if (exemption) return { ok: true };
  }

  return { ok: false, error: 'MFA_REQUIRED' };
}

async function trackSession(req: AuthRequest): Promise<void> {
  const userId = req.user?.id;
  const sessionId = req.sessionMeta?.sessionId;
  if (!userId || !sessionId) return;

  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || '';

  const deviceInfo = parseUserAgent(ua);

  await supabase.from('user_sessions').upsert(
    {
      user_id: userId,
      session_id: sessionId,
      ip_address: ip,
      user_agent: ua.substring(0, 512),
      device_info: deviceInfo,
      last_active_at: new Date().toISOString(),
    },
    { onConflict: 'session_id' },
  );
}

function parseUserAgent(ua: string): { browser: string; os: string } {
  let browser = 'Unknown';
  let os = 'Unknown';

  if (ua.includes('Firefox/')) browser = 'Firefox';
  else if (ua.includes('Edg/')) browser = 'Edge';
  else if (ua.includes('Chrome/')) browser = 'Chrome';
  else if (ua.includes('Safari/')) browser = 'Safari';

  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Mac OS')) os = 'macOS';
  else if (ua.includes('Linux')) os = 'Linux';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';

  return { browser, os };
}
