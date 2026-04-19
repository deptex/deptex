import { Router } from 'express';
import { authenticateUser, AuthRequest, generateApiToken } from '../middleware/auth';
import { supabase } from '../lib/supabase';

const router = Router();

router.get('/', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const { data: tokens, error } = await supabase
      .from('api_tokens')
      .select('id, name, token_prefix, organization_id, scopes, last_used_at, last_used_ip, expires_at, created_at')
      .eq('user_id', userId)
      .is('revoked_at', null)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ error: 'Failed to fetch tokens' });
    }

    res.json({ tokens: tokens || [] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch tokens' });
  }
});

router.post('/', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const { name, organization_id, scopes, expires_in_days } = req.body;

    if (!name || !organization_id) {
      return res.status(400).json({ error: 'name and organization_id are required' });
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('id')
      .eq('organization_id', organization_id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(403).json({ error: 'You are not a member of this organization' });
    }

    const { raw, prefix, hash } = generateApiToken();

    const expiresAt = expires_in_days
      ? new Date(Date.now() + expires_in_days * 86400000).toISOString()
      : null;

    const { data: tokenRow, error } = await supabase
      .from('api_tokens')
      .insert({
        user_id: userId,
        organization_id,
        name,
        token_prefix: prefix,
        token_hash: hash,
        scopes: scopes || ['read'],
        expires_at: expiresAt,
      })
      .select('id, name, token_prefix, organization_id, scopes, expires_at, created_at')
      .single();

    if (error) {
      return res.status(500).json({ error: 'Failed to create token' });
    }

    try {
      const { logSecurityEvent } = require('../lib/security-audit');
      await logSecurityEvent({
        organizationId: organization_id,
        actorId: userId,
        action: 'api_token_created',
        targetType: 'api_token',
        targetId: tokenRow.id,
        req,
        metadata: { name, scopes: scopes || ['read'] },
      });
    } catch {}

    res.status(201).json({
      token: raw,
      ...tokenRow,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create token' });
  }
});

router.delete('/:id', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const tokenId = req.params.id;

    const { data: tokenRow } = await supabase
      .from('api_tokens')
      .select('id, organization_id, name')
      .eq('id', tokenId)
      .eq('user_id', userId)
      .is('revoked_at', null)
      .single();

    if (!tokenRow) {
      return res.status(404).json({ error: 'Token not found' });
    }

    await supabase
      .from('api_tokens')
      .update({ revoked_at: new Date().toISOString() })
      .eq('id', tokenId);

    try {
      const { logSecurityEvent } = require('../lib/security-audit');
      await logSecurityEvent({
        organizationId: tokenRow.organization_id,
        actorId: userId,
        action: 'api_token_revoked',
        targetType: 'api_token',
        targetId: tokenId,
        req,
        metadata: { name: tokenRow.name },
      });
    } catch {}

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to revoke token' });
  }
});

router.post('/:id/rotate', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const tokenId = req.params.id;

    const { data: oldToken } = await supabase
      .from('api_tokens')
      .select('*')
      .eq('id', tokenId)
      .eq('user_id', userId)
      .is('revoked_at', null)
      .single();

    if (!oldToken) {
      return res.status(404).json({ error: 'Token not found' });
    }

    await supabase
      .from('api_tokens')
      .update({ revoked_at: new Date().toISOString() })
      .eq('id', tokenId);

    const { raw, prefix, hash } = generateApiToken();

    const { data: newTokenRow, error } = await supabase
      .from('api_tokens')
      .insert({
        user_id: userId,
        organization_id: oldToken.organization_id,
        name: oldToken.name,
        token_prefix: prefix,
        token_hash: hash,
        scopes: oldToken.scopes,
        expires_at: oldToken.expires_at,
      })
      .select('id, name, token_prefix, organization_id, scopes, expires_at, created_at')
      .single();

    if (error) {
      return res.status(500).json({ error: 'Failed to rotate token' });
    }

    try {
      const { logSecurityEvent } = require('../lib/security-audit');
      await logSecurityEvent({
        organizationId: oldToken.organization_id,
        actorId: userId,
        action: 'api_token_rotated',
        targetType: 'api_token',
        targetId: newTokenRow.id,
        req,
        metadata: { old_token_id: tokenId, name: oldToken.name },
      });
    } catch {}

    res.status(201).json({
      token: raw,
      ...newTokenRow,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to rotate token' });
  }
});

export default router;
