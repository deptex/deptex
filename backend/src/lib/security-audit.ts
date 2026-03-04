import { Request } from 'express';
import { supabase } from '../lib/supabase';

export type AuditSeverity = 'info' | 'warning' | 'critical';

export interface SecurityEventParams {
  organizationId: string;
  actorId?: string;
  action: string;
  targetType?: string;
  targetId?: string;
  req?: Request;
  metadata?: Record<string, unknown>;
  severity?: AuditSeverity;
}

function extractClientIp(req?: Request): string | undefined {
  if (!req) return undefined;
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') return forwarded.split(',')[0].trim();
  if (Array.isArray(forwarded)) return forwarded[0];
  return req.ip || req.socket?.remoteAddress;
}

export async function logSecurityEvent(params: SecurityEventParams): Promise<void> {
  const {
    organizationId,
    actorId,
    action,
    targetType,
    targetId,
    req,
    metadata = {},
    severity = 'info',
  } = params;

  try {
    await supabase.from('security_audit_logs').insert({
      organization_id: organizationId,
      actor_id: actorId || null,
      action,
      target_type: targetType || null,
      target_id: targetId || null,
      ip_address: extractClientIp(req) || null,
      user_agent: req?.headers['user-agent'] || null,
      metadata,
      severity,
    });
  } catch (err) {
    console.error('[security-audit] Failed to log event:', action, err);
  }
}

export function getClientIp(req: Request): string {
  return extractClientIp(req) || '0.0.0.0';
}
