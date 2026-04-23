import { Router, Response } from 'express';
import { generateText } from 'ai';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { userHasOrgPermission } from '../lib/permissions';
import { rowToMessage, rowToThread, type ThreadRow, type UserStateRow } from '../lib/aegis/types';
import { generateChat } from '../lib/aegis/chat';
import { getAegisModel } from '../lib/aegis/provider';
import {
  isParticipant,
  isCreator,
  getThreadForParticipant,
  addParticipant,
  removeParticipant,
  listParticipants,
  transferOwnership,
} from '../lib/aegis/participants';
import { randomBytes } from 'crypto';

const router = Router();

const AEGIS_PERMISSION = 'interact_with_aegis';

router.use(authenticateUser);

const THREAD_COLUMNS = 'id, organization_id, user_id, created_by, title, created_at, updated_at';

async function getSenderNameAndRole(userId: string, organizationId: string): Promise<{ name: string | null; role: string | null }> {
  const [{ data: profile }, { data: membership }] = await Promise.all([
    supabase.from('user_profiles').select('full_name').eq('user_id', userId).maybeSingle(),
    supabase.from('organization_members').select('role').eq('organization_id', organizationId).eq('user_id', userId).maybeSingle(),
  ]);
  return { name: profile?.full_name ?? null, role: membership?.role ?? null };
}

// GET /api/aegis/threads?organizationId=...
router.get('/threads', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const organizationId = req.query.organizationId as string | undefined;
  if (!organizationId) return res.status(400).json({ error: 'Missing organizationId' });

  if (!(await userHasOrgPermission(userId, organizationId, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  // Threads in this org where viewer is a participant.
  const { data: participantRows } = await supabase
    .from('aegis_chat_participants')
    .select('thread_id')
    .eq('user_id', userId);
  const threadIds = (participantRows ?? []).map((r) => r.thread_id);
  if (threadIds.length === 0) return res.json({ threads: [] });

  const { data: threadRows, error } = await supabase
    .from('aegis_chat_threads')
    .select(THREAD_COLUMNS)
    .eq('organization_id', organizationId)
    .in('id', threadIds)
    .order('updated_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  const threads = (threadRows ?? []) as ThreadRow[];
  if (threads.length === 0) return res.json({ threads: [] });

  const ids = threads.map((t) => t.id);
  const [{ data: stateRows }, { data: allParticipantRows }] = await Promise.all([
    supabase
      .from('aegis_chat_user_state')
      .select('thread_id, pinned_at, archived_at')
      .eq('user_id', userId)
      .in('thread_id', ids),
    supabase
      .from('aegis_chat_participants')
      .select('thread_id')
      .in('thread_id', ids),
  ]);

  const stateByThread = new Map<string, UserStateRow>(
    (stateRows ?? []).map((r: any) => [r.thread_id, { pinned_at: r.pinned_at, archived_at: r.archived_at }]),
  );
  const countByThread = new Map<string, number>();
  for (const row of allParticipantRows ?? []) {
    countByThread.set(row.thread_id, (countByThread.get(row.thread_id) ?? 0) + 1);
  }

  res.json({
    threads: threads.map((t) =>
      rowToThread(t, userId, stateByThread.get(t.id) ?? null, countByThread.get(t.id) ?? 1),
    ),
  });
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
      created_by: userId,
      title: typeof title === 'string' && title.trim() ? title.trim().slice(0, 120) : 'New chat',
    })
    .select(THREAD_COLUMNS)
    .single();

  if (error || !data) return res.status(500).json({ error: error?.message ?? 'Failed to create thread' });

  await addParticipant(data.id, userId);

  res.status(201).json({ thread: rowToThread(data as ThreadRow, userId, null, 1) });
});

// PATCH /api/aegis/threads/:id  { title?, pinned?, archived? }
// Rename is creator-only (affects everyone). Pin/archive are per-user.
router.patch('/threads/:id', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;
  const { title, pinned, archived } = req.body ?? {};

  const thread = await getThreadForParticipant(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  if (!(await userHasOrgPermission(userId, thread.organization_id, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  // Title: creator only.
  if (typeof title === 'string') {
    if (thread.user_id !== userId) return res.status(403).json({ error: 'Only the creator can rename this chat' });
    if (!title.trim()) return res.status(400).json({ error: 'title must not be empty' });
    const { error: renameErr } = await supabase
      .from('aegis_chat_threads')
      .update({ title: title.trim().slice(0, 120) })
      .eq('id', threadId);
    if (renameErr) return res.status(500).json({ error: renameErr.message });
  }

  // Per-user pin/archive in aegis_chat_user_state.
  if (typeof pinned === 'boolean' || typeof archived === 'boolean') {
    const patch: Record<string, unknown> = {
      thread_id: threadId,
      user_id: userId,
    };
    if (typeof pinned === 'boolean') patch.pinned_at = pinned ? new Date().toISOString() : null;
    if (typeof archived === 'boolean') patch.archived_at = archived ? new Date().toISOString() : null;
    const { error: stateErr } = await supabase
      .from('aegis_chat_user_state')
      .upsert(patch, { onConflict: 'thread_id,user_id' });
    if (stateErr) return res.status(500).json({ error: stateErr.message });
  }

  if (typeof title !== 'string' && typeof pinned !== 'boolean' && typeof archived !== 'boolean') {
    return res.status(400).json({ error: 'No updatable fields provided' });
  }

  const { data: updated } = await supabase
    .from('aegis_chat_threads')
    .select(THREAD_COLUMNS)
    .eq('id', threadId)
    .single();
  const { data: state } = await supabase
    .from('aegis_chat_user_state')
    .select('pinned_at, archived_at')
    .eq('thread_id', threadId)
    .eq('user_id', userId)
    .maybeSingle();
  const { count } = await supabase
    .from('aegis_chat_participants')
    .select('user_id', { count: 'exact', head: true })
    .eq('thread_id', threadId);

  if (!updated) return res.status(500).json({ error: 'Update failed' });
  res.json({
    thread: rowToThread(
      updated as ThreadRow,
      userId,
      (state as UserStateRow | null) ?? null,
      count ?? 1,
    ),
  });
});

// DELETE /api/aegis/threads/:id — creator only.
router.delete('/threads/:id', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;

  const thread = await getThreadForParticipant(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  if (!(await userHasOrgPermission(userId, thread.organization_id, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }
  if (thread.user_id !== userId) {
    return res.status(403).json({ error: 'Only the creator can delete this chat' });
  }

  const { error } = await supabase.from('aegis_chat_threads').delete().eq('id', threadId);
  if (error) return res.status(500).json({ error: error.message });
  res.status(204).send();
});

// GET /api/aegis/threads/:id/messages
router.get('/threads/:id/messages', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;

  const thread = await getThreadForParticipant(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  if (!(await userHasOrgPermission(userId, thread.organization_id, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  const { data, error } = await supabase
    .from('aegis_chat_messages')
    .select('id, thread_id, role, user_id, content, metadata, created_at')
    .eq('thread_id', threadId)
    .order('created_at', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ messages: (data ?? []).map(rowToMessage) });
});

// DELETE /api/aegis/messages/:id/below
router.delete('/messages/:id/below', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const messageId = req.params.id;

  const { data: message } = await supabase
    .from('aegis_chat_messages')
    .select('id, thread_id, user_id, created_at')
    .eq('id', messageId)
    .single();
  if (!message) return res.status(404).json({ error: 'Message not found' });

  const thread = await getThreadForParticipant(message.thread_id, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  if (!(await userHasOrgPermission(userId, thread.organization_id, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }
  // Only the author of the user message can truncate from it.
  if (message.user_id && message.user_id !== userId) {
    return res.status(403).json({ error: 'Only the author can edit this message' });
  }

  const { error } = await supabase
    .from('aegis_chat_messages')
    .delete()
    .eq('thread_id', message.thread_id)
    .gte('created_at', message.created_at);

  if (error) return res.status(500).json({ error: error.message });
  res.status(204).send();
});

// POST /api/aegis/chat  { organizationId, threadId, message }
// Saves the user message, returns { threadId } immediately, then generates
// the AI reply in the background. The assistant message lands in DB and
// triggers a Supabase Realtime event the client is already subscribed to.
router.post('/chat', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const { organizationId, threadId: incomingThreadId, message } = req.body ?? {};

  if (!organizationId || typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ error: 'organizationId and message are required' });
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

  // Resolve existing thread or create a new one.
  let threadId: string;
  if (incomingThreadId) {
    const thread = await getThreadForParticipant(incomingThreadId, userId);
    if (!thread || thread.organization_id !== organizationId) {
      return res.status(404).json({ error: 'Thread not found' });
    }
    threadId = thread.id;
  } else {
    const { data: created, error: createErr } = await supabase
      .from('aegis_chat_threads')
      .insert({ organization_id: organizationId, user_id: userId, created_by: userId, title: 'New chat' })
      .select('id')
      .single();
    if (createErr || !created) return res.status(500).json({ error: createErr?.message ?? 'Thread create failed' });
    threadId = created.id;
    await addParticipant(threadId, userId);
  }

  const userText = message.trim();

  // Save user message synchronously so it's in DB before we return.
  const { error: msgErr } = await supabase.from('aegis_chat_messages').insert({
    thread_id: threadId,
    role: 'user',
    user_id: userId,
    content: userText,
    metadata: { parts: [{ type: 'text', text: userText }] },
  });
  if (msgErr) {
    console.error('[aegis] save user message failed', msgErr);
    return res.status(500).json({ error: 'Failed to save message' });
  }

  // Return immediately — the AI reply will arrive via Supabase Realtime.
  res.json({ threadId });

  // Fire-and-forget: generate AI reply and save it to DB.
  (async () => {
    try {
      const { data: rows } = await supabase
        .from('aegis_chat_messages')
        .select('role, content')
        .eq('thread_id', threadId)
        .order('created_at', { ascending: true });

      const { name: senderName, role: senderRole } = await getSenderNameAndRole(userId, organizationId);

      const { text, parts } = await generateChat({
        organizationId,
        orgName: org.name,
        userId,
        senderName,
        senderRole,
        messages: (rows ?? []) as Array<{ role: 'user' | 'assistant'; content: string }>,
      });

      // Auto-title on the first exchange (title before saving so the Realtime
      // event fires after the title is already updated).
      const totalMessages = (rows ?? []).length + 1;
      if (totalMessages <= 3) {
        try {
          const prompt = `Summarize this chat in 3-5 words, Title Case, no quotes, no trailing punctuation.\n\nUser: ${userText.slice(0, 800)}\nAssistant: ${text.slice(0, 800)}\n\nTitle:`;
          const { text: titleText } = await generateText({ model: getAegisModel(), prompt, temperature: 0.3 });
          const title = titleText.trim().replace(/^["']|["']$/g, '').replace(/[.?!]+$/, '').slice(0, 80) || 'New chat';
          await supabase.from('aegis_chat_threads').update({ title }).eq('id', threadId);
        } catch (err) {
          console.error('[aegis] auto-title failed', err);
        }
      }

      await Promise.all([
        supabase.from('aegis_chat_messages').insert({
          thread_id: threadId,
          role: 'assistant',
          user_id: null,
          content: text,
          metadata: { parts },
        }),
        supabase.from('aegis_chat_threads').update({ updated_at: new Date().toISOString() }).eq('id', threadId),
      ]);
    } catch (err) {
      console.error('[aegis] background generation failed', err);
    }
  })();
});

// POST /api/aegis/threads/:id/auto-title
router.post('/threads/:id/auto-title', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;

  const thread = await getThreadForParticipant(threadId, userId);
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
    .select(THREAD_COLUMNS)
    .single();
  if (error || !updated) return res.status(500).json({ error: error?.message ?? 'Update failed' });

  const { data: state } = await supabase
    .from('aegis_chat_user_state')
    .select('pinned_at, archived_at')
    .eq('thread_id', threadId)
    .eq('user_id', userId)
    .maybeSingle();
  const { count } = await supabase
    .from('aegis_chat_participants')
    .select('user_id', { count: 'exact', head: true })
    .eq('thread_id', threadId);

  res.json({
    thread: rowToThread(
      updated as ThreadRow,
      userId,
      (state as UserStateRow | null) ?? null,
      count ?? 1,
    ),
  });
});

// ---------- Participants ----------

// GET /api/aegis/threads/:id/participants
router.get('/threads/:id/participants', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;
  const thread = await getThreadForParticipant(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  res.json({ participants: await listParticipants(threadId) });
});

// POST /api/aegis/threads/:id/participants  { userId }
router.post('/threads/:id/participants', async (req: AuthRequest, res: Response) => {
  const callerId = req.user!.id;
  const threadId = req.params.id;
  const targetUserId = req.body?.userId as string | undefined;
  if (!targetUserId) return res.status(400).json({ error: 'Missing userId' });

  const thread = await getThreadForParticipant(threadId, callerId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  // Target must be a member of the org and have interact_with_aegis.
  const { data: targetMembership } = await supabase
    .from('organization_members')
    .select('user_id')
    .eq('organization_id', thread.organization_id)
    .eq('user_id', targetUserId)
    .maybeSingle();
  if (!targetMembership) return res.status(403).json({ error: 'User is not in this organization' });
  if (!(await userHasOrgPermission(targetUserId, thread.organization_id, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: "That user doesn't have the Aegis permission." });
  }

  // Caller must have visibility to the target under current RBAC.
  const invitable = await getInvitableUserIds(callerId, thread.organization_id);
  if (!invitable.has(targetUserId)) {
    return res.status(403).json({ error: "You can't invite this user directly. Share the invite code instead." });
  }

  await addParticipant(threadId, targetUserId);
  res.status(201).json({ ok: true });
});

// DELETE /api/aegis/threads/:id/participants/:userId — remove (creator) or leave (self).
router.delete('/threads/:id/participants/:userId', async (req: AuthRequest, res: Response) => {
  const callerId = req.user!.id;
  const threadId = req.params.id;
  const targetUserId = req.params.userId;

  const thread = await getThreadForParticipant(threadId, callerId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  const isSelfLeaving = callerId === targetUserId;
  const callerIsCreator = thread.user_id === callerId;
  if (!isSelfLeaving && !callerIsCreator) {
    return res.status(403).json({ error: 'Only the creator can remove other participants' });
  }

  await removeParticipant(threadId, targetUserId);

  // If the creator left, transfer ownership or delete orphan.
  if (isSelfLeaving && targetUserId === thread.user_id) {
    const newOwner = await transferOwnership(threadId);
    if (!newOwner) {
      await supabase.from('aegis_chat_threads').delete().eq('id', threadId);
    }
  }

  res.status(204).send();
});

// ---------- Invite codes ----------

// GET /api/aegis/threads/:id/invite-code
router.get('/threads/:id/invite-code', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;
  const thread = await getThreadForParticipant(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  const { data } = await supabase
    .from('aegis_chat_invite_codes')
    .select('code, created_by, created_at, revoked_at')
    .eq('thread_id', threadId)
    .maybeSingle();
  if (!data || data.revoked_at) return res.json({ code: null });
  res.json({ code: data.code, createdBy: data.created_by, createdAt: data.created_at });
});

// POST /api/aegis/threads/:id/invite-code
router.post('/threads/:id/invite-code', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;
  const thread = await getThreadForParticipant(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  const { data: existing } = await supabase
    .from('aegis_chat_invite_codes')
    .select('code, revoked_at')
    .eq('thread_id', threadId)
    .maybeSingle();
  if (existing && !existing.revoked_at) {
    return res.status(409).json({ error: 'An invite code is already active for this chat', code: existing.code });
  }

  const code = randomBytes(6).toString('base64url'); // ~8 chars, URL-safe
  if (existing) {
    // Row exists but revoked — replace it.
    await supabase.from('aegis_chat_invite_codes').delete().eq('thread_id', threadId);
  }
  const { error } = await supabase.from('aegis_chat_invite_codes').insert({
    thread_id: threadId,
    code,
    created_by: userId,
  });
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json({ code });
});

// DELETE /api/aegis/threads/:id/invite-code
router.delete('/threads/:id/invite-code', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const threadId = req.params.id;
  const thread = await getThreadForParticipant(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  const { error } = await supabase
    .from('aegis_chat_invite_codes')
    .update({ revoked_at: new Date().toISOString() })
    .eq('thread_id', threadId);
  if (error) return res.status(500).json({ error: error.message });
  res.status(204).send();
});

// POST /api/aegis/invite/redeem  { code }
router.post('/invite/redeem', async (req: AuthRequest, res: Response) => {
  const userId = req.user!.id;
  const code = req.body?.code as string | undefined;
  if (!code || typeof code !== 'string') return res.status(400).json({ error: 'Missing code' });

  const { data: invite } = await supabase
    .from('aegis_chat_invite_codes')
    .select('thread_id, revoked_at')
    .eq('code', code)
    .maybeSingle();
  if (!invite || invite.revoked_at) {
    return res.status(404).json({ error: 'Invite code is invalid or has been revoked' });
  }

  const { data: thread } = await supabase
    .from('aegis_chat_threads')
    .select('id, organization_id')
    .eq('id', invite.thread_id)
    .maybeSingle();
  if (!thread) return res.status(404).json({ error: 'Chat no longer exists' });

  const { data: membership } = await supabase
    .from('organization_members')
    .select('user_id')
    .eq('organization_id', thread.organization_id)
    .eq('user_id', userId)
    .maybeSingle();
  if (!membership) return res.status(403).json({ error: 'You are not a member of this organization' });

  if (!(await userHasOrgPermission(userId, thread.organization_id, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: "You don't have the Aegis permission — ask an admin." });
  }

  await addParticipant(thread.id, userId);
  res.json({ threadId: thread.id });
});

// ---------- Invitable-users (visibility-gated picker) ----------

async function getInvitableUserIds(callerId: string, organizationId: string): Promise<Set<string>> {
  // Broad visibility: all org members minus caller.
  const broad = await userHasOrgPermission(callerId, organizationId, 'manage_members')
    || await userHasOrgPermission(callerId, organizationId, 'view_all_teams_and_projects')
    || await userHasOrgPermission(callerId, organizationId, 'manage_teams_and_projects');

  if (broad) {
    const { data: members } = await supabase
      .from('organization_members')
      .select('user_id')
      .eq('organization_id', organizationId);
    const ids = new Set<string>();
    for (const m of members ?? []) if (m.user_id !== callerId) ids.add(m.user_id);
    return ids;
  }

  // Scoped visibility: members of shared teams + shared projects.
  const [{ data: myTeams }, { data: myProjects }] = await Promise.all([
    supabase.from('team_members').select('team_id').eq('user_id', callerId),
    supabase.from('project_members').select('project_id').eq('user_id', callerId),
  ]);
  const teamIds = (myTeams ?? []).map((r) => r.team_id);
  const projectIds = (myProjects ?? []).map((r) => r.project_id);

  const visible = new Set<string>();

  if (teamIds.length > 0) {
    // Scope to the given org via teams(organization_id).
    const { data: orgTeams } = await supabase
      .from('teams')
      .select('id')
      .eq('organization_id', organizationId)
      .in('id', teamIds);
    const scopedTeamIds = (orgTeams ?? []).map((t) => t.id);
    if (scopedTeamIds.length > 0) {
      const { data: teamPeople } = await supabase
        .from('team_members')
        .select('user_id')
        .in('team_id', scopedTeamIds);
      for (const r of teamPeople ?? []) if (r.user_id !== callerId) visible.add(r.user_id);
    }
  }

  if (projectIds.length > 0) {
    const { data: orgProjects } = await supabase
      .from('projects')
      .select('id')
      .eq('organization_id', organizationId)
      .in('id', projectIds);
    const scopedProjectIds = (orgProjects ?? []).map((p) => p.id);
    if (scopedProjectIds.length > 0) {
      const { data: projPeople } = await supabase
        .from('project_members')
        .select('user_id')
        .in('project_id', scopedProjectIds);
      for (const r of projPeople ?? []) if (r.user_id !== callerId) visible.add(r.user_id);
    }
  }

  return visible;
}

// GET /api/aegis/organizations/:orgId/invitable-users?threadId=...
router.get('/organizations/:orgId/invitable-users', async (req: AuthRequest, res: Response) => {
  const callerId = req.user!.id;
  const organizationId = req.params.orgId;
  const threadId = req.query.threadId as string | undefined;

  if (!(await userHasOrgPermission(callerId, organizationId, AEGIS_PERMISSION))) {
    return res.status(403).json({ error: 'Permission denied: interact_with_aegis' });
  }

  const ids = Array.from(await getInvitableUserIds(callerId, organizationId));
  if (ids.length === 0) return res.json({ users: [] });

  // Exclude existing participants if threadId is provided.
  let excluded = new Set<string>();
  if (threadId) {
    const { data: existing } = await supabase
      .from('aegis_chat_participants')
      .select('user_id')
      .eq('thread_id', threadId);
    excluded = new Set((existing ?? []).map((r) => r.user_id));
  }

  const filtered = ids.filter((id) => !excluded.has(id));
  if (filtered.length === 0) return res.json({ users: [] });

  const [{ data: profiles }, { data: roles }] = await Promise.all([
    supabase.from('user_profiles').select('user_id, full_name, avatar_url').in('user_id', filtered),
    supabase.from('organization_members').select('user_id, role').eq('organization_id', organizationId).in('user_id', filtered),
  ]);
  const profileMap = new Map((profiles ?? []).map((p: any) => [p.user_id, p]));
  const roleMap = new Map((roles ?? []).map((r: any) => [r.user_id, r.role]));

  // Emails via auth admin.
  const emailByUser = new Map<string, string | null>();
  await Promise.all(
    filtered.map(async (uid) => {
      try {
        const { data } = await supabase.auth.admin.getUserById(uid);
        emailByUser.set(uid, data?.user?.email ?? null);
      } catch {
        emailByUser.set(uid, null);
      }
    }),
  );

  const users = filtered.map((uid) => {
    const profile: any = profileMap.get(uid) ?? {};
    return {
      userId: uid,
      displayName: profile.full_name ?? null,
      avatarUrl: profile.avatar_url ?? null,
      email: emailByUser.get(uid) ?? null,
      role: roleMap.get(uid) ?? null,
    };
  });

  res.json({ users });
});

export { isParticipant, isCreator };

export default router;
