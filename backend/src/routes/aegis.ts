import { Router, Response } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { userHasOrgPermission } from '../lib/permissions';
import { rowToMessage, rowToThread } from '../lib/aegis/types';

const router = Router();

const AEGIS_PERMISSION = 'interact_with_aegis';

router.use(authenticateUser);

async function ensureThreadOwnership(
  threadId: string,
  userId: string,
): Promise<{ id: string; organization_id: string; user_id: string; title: string } | null> {
  const { data } = await supabase
    .from('aegis_chat_threads')
    .select('id, organization_id, user_id, title')
    .eq('id', threadId)
    .single();
  if (!data) return null;
  if (data.user_id !== userId) return null;
  return data;
}

// GET /api/aegis/threads?organizationId=...
router.get('/threads', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const organizationId = req.query.organizationId as string | undefined;
  if (!organizationId) return res.status(400).json({ error: 'Missing organizationId' });

  if (!(await userHasOrgPermission(userId, organizationId, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  const { data, error } = await supabase
    .from('aegis_chat_threads')
    .select('id, organization_id, user_id, title, created_at, updated_at')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .order('updated_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ threads: (data ?? []).map(rowToThread) });
});

// POST /api/aegis/threads
router.post('/threads', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const { organizationId, title } = req.body ?? {};
  if (!organizationId) return res.status(400).json({ error: 'Missing organizationId' });

  if (!(await userHasOrgPermission(userId, organizationId, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  const { data, error } = await supabase
    .from('aegis_chat_threads')
    .insert({
      organization_id: organizationId,
      user_id: userId,
      title: typeof title === 'string' && title.trim() ? title.trim().slice(0, 120) : 'New chat',
    })
    .select('id, organization_id, user_id, title, created_at, updated_at')
    .single();

  if (error || !data) return res.status(500).json({ error: error?.message ?? 'Failed to create thread' });
  res.status(201).json({ thread: rowToThread(data) });
});

// PATCH /api/aegis/threads/:id  { title }
router.patch('/threads/:id', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;
  const { title } = req.body ?? {};
  if (typeof title !== 'string' || !title.trim()) {
    return res.status(400).json({ error: 'title is required' });
  }

  const thread = await ensureThreadOwnership(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  if (!(await userHasOrgPermission(userId, thread.organization_id, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  const { data, error } = await supabase
    .from('aegis_chat_threads')
    .update({ title: title.trim().slice(0, 120) })
    .eq('id', threadId)
    .select('id, organization_id, user_id, title, created_at, updated_at')
    .single();

  if (error || !data) return res.status(500).json({ error: error?.message ?? 'Update failed' });
  res.json({ thread: rowToThread(data) });
});

// DELETE /api/aegis/threads/:id
router.delete('/threads/:id', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;

  const thread = await ensureThreadOwnership(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  if (!(await userHasOrgPermission(userId, thread.organization_id, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  const { error } = await supabase.from('aegis_chat_threads').delete().eq('id', threadId);
  if (error) return res.status(500).json({ error: error.message });
  res.status(204).send();
});

// GET /api/aegis/threads/:id/messages
router.get('/threads/:id/messages', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;

  const thread = await ensureThreadOwnership(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  if (!(await userHasOrgPermission(userId, thread.organization_id, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  const { data, error } = await supabase
    .from('aegis_chat_messages')
    .select('id, thread_id, role, content, metadata, created_at')
    .eq('thread_id', threadId)
    .order('created_at', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ messages: (data ?? []).map(rowToMessage) });
});

// DELETE /api/aegis/messages/:id/below
// Deletes this message and every later message in the same thread.
router.delete('/messages/:id/below', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const messageId = req.params.id;

  const { data: message } = await supabase
    .from('aegis_chat_messages')
    .select('id, thread_id, created_at')
    .eq('id', messageId)
    .single();
  if (!message) return res.status(404).json({ error: 'Message not found' });

  const thread = await ensureThreadOwnership(message.thread_id, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  if (!(await userHasOrgPermission(userId, thread.organization_id, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  const { error } = await supabase
    .from('aegis_chat_messages')
    .delete()
    .eq('thread_id', message.thread_id)
    .gte('created_at', message.created_at);

  if (error) return res.status(500).json({ error: error.message });
  res.status(204).send();
});

export default router;
