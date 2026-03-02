import { Router } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser } from '../middleware/auth';

const router = Router();

router.get('/', authenticateUser, async (req: any, res) => {
  const userId = req.user.id;
  const orgId = req.query.org_id as string;
  const unreadOnly = req.query.unread_only === 'true';
  const page = parseInt(req.query.page as string) || 1;
  const perPage = Math.min(parseInt(req.query.per_page as string) || 20, 50);
  const offset = (page - 1) * perPage;

  let query = supabase
    .from('user_notifications')
    .select('*', { count: 'exact' })
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .range(offset, offset + perPage - 1);

  if (orgId) query = query.eq('organization_id', orgId);
  if (unreadOnly) query = query.is('read_at', null);

  const { data, count, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ notifications: data || [], total: count || 0, page, perPage });
});

router.get('/unread-count', authenticateUser, async (req: any, res) => {
  const userId = req.user.id;
  const orgId = req.query.org_id as string;

  let query = supabase
    .from('user_notifications')
    .select('id', { count: 'exact', head: true })
    .eq('user_id', userId)
    .is('read_at', null);

  if (orgId) query = query.eq('organization_id', orgId);
  const { count, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ count: count || 0 });
});

router.patch('/:id/read', authenticateUser, async (req: any, res) => {
  const userId = req.user.id;
  const { id } = req.params;

  const { error } = await supabase
    .from('user_notifications')
    .update({ read_at: new Date().toISOString() })
    .eq('id', id)
    .eq('user_id', userId);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

router.post('/mark-all-read', authenticateUser, async (req: any, res) => {
  const userId = req.user.id;
  const orgId = req.body.organization_id;

  let query = supabase
    .from('user_notifications')
    .update({ read_at: new Date().toISOString() })
    .eq('user_id', userId)
    .is('read_at', null);

  if (orgId) query = query.eq('organization_id', orgId);
  const { error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

router.get('/preferences/:orgId', authenticateUser, async (req: any, res) => {
  const userId = req.user.id;
  const { orgId } = req.params;

  const { data, error } = await supabase
    .from('user_notification_preferences')
    .select('*')
    .eq('user_id', userId)
    .eq('organization_id', orgId)
    .single();

  if (error && error.code !== 'PGRST116') return res.status(500).json({ error: error.message });
  res.json(data || { email_opted_out: false, muted_event_types: [], muted_project_ids: [], digest_preference: 'instant' });
});

router.put('/preferences/:orgId', authenticateUser, async (req: any, res) => {
  const userId = req.user.id;
  const { orgId } = req.params;
  const { email_opted_out, muted_event_types, muted_project_ids, dnd_start_hour, dnd_end_hour, digest_preference } = req.body;

  const { data, error } = await supabase
    .from('user_notification_preferences')
    .upsert({
      user_id: userId,
      organization_id: orgId,
      email_opted_out: email_opted_out ?? false,
      muted_event_types: muted_event_types ?? [],
      muted_project_ids: muted_project_ids ?? [],
      dnd_start_hour: dnd_start_hour ?? null,
      dnd_end_hour: dnd_end_hour ?? null,
      digest_preference: digest_preference ?? 'instant',
      updated_at: new Date().toISOString(),
    }, { onConflict: 'user_id,organization_id' })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

export default router;
