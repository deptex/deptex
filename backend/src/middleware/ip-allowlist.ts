import { Response, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { AuthRequest } from './auth';

let ipaddr: any = null;
try {
  ipaddr = require('ipaddr.js');
} catch {}

const allowlistCache = new Map<string, { entries: string[]; fetchedAt: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000;

async function getOrgAllowlist(orgId: string): Promise<string[]> {
  const cached = allowlistCache.get(orgId);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.entries;
  }

  const { data } = await supabase
    .from('organization_ip_allowlist')
    .select('cidr')
    .eq('organization_id', orgId);

  const entries = (data || []).map((r: any) => r.cidr);
  allowlistCache.set(orgId, { entries, fetchedAt: Date.now() });
  return entries;
}

function isIpInCidr(clientIp: string, cidr: string): boolean {
  if (!ipaddr) {
    if (cidr.includes('/')) {
      const [network] = cidr.split('/');
      return clientIp === network;
    }
    return clientIp === cidr;
  }

  try {
    const addr = ipaddr.parse(clientIp);
    const [range, bits] = ipaddr.parseCIDR(cidr);
    return addr.match(range, parseInt(bits as any));
  } catch {
    return clientIp === cidr || cidr.startsWith(clientIp);
  }
}

export function createIPAllowlistMiddleware() {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    const orgId = req.params.id || req.params.orgId;
    if (!orgId) return next();

    try {
      const { data: org } = await supabase
        .from('organizations')
        .select('ip_allowlist_enabled')
        .eq('id', orgId)
        .single();

      if (!org?.ip_allowlist_enabled) return next();

      const clientIp = req.ip || req.socket?.remoteAddress || '';
      const entries = await getOrgAllowlist(orgId);

      if (entries.length === 0) return next();

      const allowed = entries.some((cidr) => isIpInCidr(clientIp, cidr));

      if (allowed) return next();

      try {
        const { logSecurityEvent } = require('../lib/security-audit');
        await logSecurityEvent({
          organizationId: orgId,
          actorId: req.user?.id,
          action: 'ip_access_denied',
          req,
          metadata: { blocked_ip: clientIp },
          severity: 'warning',
        });
      } catch {}

      return res.status(403).json({
        error: 'IP_NOT_ALLOWED',
        ip: clientIp,
        message: 'Your IP address is not in the organization allowlist. Contact your administrator.',
      });
    } catch (error) {
      console.error('[ip-allowlist] Error checking IP:', error);
      return next();
    }
  };
}

export function invalidateIPAllowlistCache(orgId: string): void {
  allowlistCache.delete(orgId);
}
