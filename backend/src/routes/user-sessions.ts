import { Router } from 'express';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';

const router = Router();

router.get('/', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const { data: sessions, error } = await supabase
      .from('user_sessions')
      .select('id, session_id, ip_address, user_agent, device_info, last_active_at, created_at')
      .eq('user_id', userId)
      .order('last_active_at', { ascending: false })
      .limit(50);

    if (error) {
      return res.status(500).json({ error: 'Failed to fetch sessions' });
    }

    const currentSessionId = req.sessionMeta?.sessionId || '';

    const result = (sessions || []).map((s: any) => ({
      ...s,
      is_current: s.session_id === currentSessionId,
    }));

    res.json({ sessions: result });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

router.delete('/:sessionId', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const targetSessionId = req.params.sessionId;

    const { data: session } = await supabase
      .from('user_sessions')
      .select('id, session_id')
      .eq('id', targetSessionId)
      .eq('user_id', userId)
      .single();

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    await supabase.from('user_sessions').delete().eq('id', session.id);

    try {
      const { logSecurityEvent } = require('../lib/security-audit');
      const orgId = req.query.organization_id as string;
      if (orgId) {
        await logSecurityEvent({
          organizationId: orgId,
          actorId: userId,
          action: 'session_revoked',
          targetType: 'session',
          targetId: session.session_id,
          req,
        });
      }
    } catch {}

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to revoke session' });
  }
});

router.delete('/', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const currentSessionId = req.sessionMeta?.sessionId || '';

    const { error } = await supabase
      .from('user_sessions')
      .delete()
      .eq('user_id', userId)
      .neq('session_id', currentSessionId);

    if (error) {
      return res.status(500).json({ error: 'Failed to revoke sessions' });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to revoke sessions' });
  }
});

export default router;
