import { Router, Response } from 'express';
import { generateText, type UIMessage } from 'ai';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { userHasOrgPermission } from '../lib/permissions';
import { rowToMessage, rowToThread, type MessagePart } from '../lib/aegis/types';
import { streamChat } from '../lib/aegis/chat';
import { getAegisModel } from '../lib/aegis/provider';

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

// POST /api/aegis/chat — streaming chat endpoint
router.post('/chat', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const { organizationId, threadId: incomingThreadId, messages } = req.body ?? {};

  if (!organizationId || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'organizationId and messages are required' });
  }
  if (!(await userHasOrgPermission(userId, organizationId, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  const { data: org } = await supabase
    .from('organizations')
    .select('id, name')
    .eq('id', organizationId)
    .single();
  if (!org) return res.status(404).json({ error: 'Organization not found' });

  let threadId: string | null = null;
  if (incomingThreadId) {
    const thread = await ensureThreadOwnership(incomingThreadId, userId);
    if (!thread || thread.organization_id !== organizationId) {
      return res.status(404).json({ error: 'Thread not found' });
    }
    threadId = thread.id;
  } else {
    const { data: created, error: createErr } = await supabase
      .from('aegis_chat_threads')
      .insert({ organization_id: organizationId, user_id: userId, title: 'New chat' })
      .select('id')
      .single();
    if (createErr || !created) return res.status(500).json({ error: createErr?.message ?? 'Thread create failed' });
    threadId = created.id;
  }

  const lastUserMessage = [...messages].reverse().find((m: any) => m.role === 'user');
  if (lastUserMessage) {
    const userParts: MessagePart[] = Array.isArray(lastUserMessage.parts)
      ? lastUserMessage.parts.filter((p: any) => p.type === 'text').map((p: any) => ({ type: 'text', text: p.text }))
      : [{ type: 'text', text: lastUserMessage.content ?? '' }];
    const userContent =
      typeof lastUserMessage.content === 'string' && lastUserMessage.content.length > 0
        ? lastUserMessage.content
        : userParts.map((p) => (p.type === 'text' ? p.text : '')).join('');

    // Regenerate flow leaves the user message in-place on the server — avoid
    // double-persisting by skipping the insert when the most recent row is
    // already that same user message.
    const { data: mostRecent } = await supabase
      .from('aegis_chat_messages')
      .select('role, content')
      .eq('thread_id', threadId)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    const alreadyPersisted =
      mostRecent && mostRecent.role === 'user' && mostRecent.content === userContent;

    if (!alreadyPersisted) {
      await supabase.from('aegis_chat_messages').insert({
        thread_id: threadId,
        role: 'user',
        content: userContent,
        metadata: { parts: userParts },
      });
    }
  }

  const activeThreadId = threadId!;
  res.setHeader('X-Thread-Id', activeThreadId);
  res.setHeader('Access-Control-Expose-Headers', 'X-Thread-Id');

  const result = await streamChat({
    organizationId,
    orgName: org.name,
    userId,
    uiMessages: messages as UIMessage[],
    onFinishPersist: async ({ text, parts }) => {
      await supabase.from('aegis_chat_messages').insert({
        thread_id: activeThreadId,
        role: 'assistant',
        content: text,
        metadata: { parts },
      });
      await supabase
        .from('aegis_chat_threads')
        .update({ updated_at: new Date().toISOString() })
        .eq('id', activeThreadId);
    },
  });

  result.pipeUIMessageStreamToResponse(res);
});

// POST /api/aegis/threads/:id/auto-title — generate a short title from the first exchange
router.post('/threads/:id/auto-title', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;

  const thread = await ensureThreadOwnership(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  if (!(await userHasOrgPermission(userId, thread.organization_id, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  const { data: firstMessages } = await supabase
    .from('aegis_chat_messages')
    .select('role, content')
    .eq('thread_id', threadId)
    .order('created_at', { ascending: true })
    .limit(2);
  if (!firstMessages || firstMessages.length === 0) {
    return res.status(400).json({ error: 'Thread has no messages yet' });
  }

  const prompt = `Summarize this chat in 3-5 words, Title Case, no quotes, no trailing punctuation.

User: ${(firstMessages[0]?.content ?? '').slice(0, 800)}
Assistant: ${(firstMessages[1]?.content ?? '').slice(0, 800)}

Title:`;

  let title: string;
  try {
    const { text } = await generateText({ model: getAegisModel(), prompt, temperature: 0.3 });
    title = text.trim().replace(/^["']|["']$/g, '').replace(/[.?!]+$/, '').slice(0, 80) || 'New chat';
  } catch (err: any) {
    return res.status(500).json({ error: err?.message ?? 'Auto-title failed' });
  }

  const { data: updated, error } = await supabase
    .from('aegis_chat_threads')
    .update({ title })
    .eq('id', threadId)
    .select('id, organization_id, user_id, title, created_at, updated_at')
    .single();
  if (error || !updated) return res.status(500).json({ error: error?.message ?? 'Update failed' });
  res.json({ thread: rowToThread(updated) });
});

export default router;
