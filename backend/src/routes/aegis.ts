import { Router, Response } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { userHasOrgPermission } from '../lib/permissions';
import { checkRateLimit } from '../lib/rate-limit';
import { rowToMessage, rowToThread, mapFixStatusToBadge, type ThreadRow, type UserStateRow, type FixStatusForBadge } from '../lib/aegis/types';
import { generateThreadTitle } from '../lib/aegis/title';
import { createAegisAgent } from '../lib/aegis/agent';
import { getOrCreateThread, loadThreadHistory } from '../lib/aegis/thread';
import { queryRelevantMemories } from '../lib/aegis/memory';
import { saveUserMessage } from '../lib/aegis/persistence';
import { classifyChatError, writeAegisChatError } from '../lib/aegis/errors';
import { getProviderInfoForOrg } from '../lib/aegis/provider';
import {
  registerStream,
  createChunkSink,
  clearActiveStream,
  getActiveStreamId,
  replayStream,
} from '../lib/aegis/resumable-stream';
import { canCharge } from '../lib/billing/ledger';
import {
  getAegisTurnEstimateCents,
  FRESH_ORG_DEFAULT_MODEL_ID,
} from '../lib/billing/aegis-estimate';
import {
  isParticipant,
  isCreator,
  getThreadForParticipant,
  addParticipant,
  removeParticipant,
  listParticipants,
  transferOwnership,
} from '../lib/aegis/participants';
import { randomBytes, randomUUID } from 'crypto';
import type { ModelMessage } from 'ai';

const router = Router();

const AEGIS_PERMISSION = 'interact_with_aegis';

router.use(authenticateUser);

const THREAD_COLUMNS = 'id, organization_id, user_id, created_by, title, created_at, updated_at, context_type, context_id';

/** Batch-load fix status for any threads linked to fixes via context_type='fix'. */
async function loadFixStatusesForThreads(
  threads: ThreadRow[],
): Promise<Map<string, FixStatusForBadge>> {
  const fixIds = threads
    .filter((t) => t.context_type === 'fix' && t.context_id)
    .map((t) => t.context_id as string);
  if (fixIds.length === 0) return new Map();
  const { data } = await supabase
    .from('project_security_fixes')
    .select('id, status, error_message')
    .in('id', fixIds);
  const byFixId = new Map<string, { status: string; errorMessage: string | null }>();
  for (const row of data ?? []) {
    byFixId.set(row.id, { status: row.status, errorMessage: row.error_message ?? null });
  }
  const byThreadId = new Map<string, FixStatusForBadge>();
  for (const t of threads) {
    if (t.context_type !== 'fix' || !t.context_id) continue;
    const fix = byFixId.get(t.context_id);
    if (!fix) continue;
    const badge = mapFixStatusToBadge(fix.status, fix.errorMessage);
    if (badge) byThreadId.set(t.id, badge);
  }
  return byThreadId;
}

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
  const [{ data: stateRows }, { data: allParticipantRows }, fixStatusByThread] = await Promise.all([
    supabase
      .from('aegis_chat_user_state')
      .select('thread_id, pinned_at, archived_at')
      .eq('user_id', userId)
      .in('thread_id', ids),
    supabase
      .from('aegis_chat_participants')
      .select('thread_id')
      .in('thread_id', ids),
    loadFixStatusesForThreads(threads),
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
      rowToThread(
        t,
        userId,
        stateByThread.get(t.id) ?? null,
        countByThread.get(t.id) ?? 1,
        fixStatusByThread.get(t.id) ?? null,
      ),
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

  await generateThreadTitle(
    threadId,
    firstMessages[0]?.content ?? '',
    firstMessages[1]?.content ?? '',
  );

  const { data: updated, error } = await supabase
    .from('aegis_chat_threads')
    .select(THREAD_COLUMNS)
    .eq('id', threadId)
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


// ============================================================
// Phase 7B+: tasks, memory, settings, approvals, etc.
// (preserved from main, not part of v2 chat surface)
// ============================================================

async function isAegisEnabled(organizationId: string): Promise<boolean> {
  const { data } = await supabase
    .from('aegis_config')
    .select('enabled')
    .eq('organization_id', organizationId)
    .single();
  
  return data?.enabled === true;
}

async function hasAegisPermission(orgId: string, userId: string): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();
  if (!membership) return false;

  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', membership.role)
    .single();

  // Support both old and new permission names during migration
  return role?.permissions?.interact_with_aegis === true ||
    role?.permissions?.interact_with_security_agent === true;
}

// GET /api/aegis/status/:organizationId - Check if Aegis is enabled
router.get('/status/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const enabled = await isAegisEnabled(organizationId);
    res.json({ enabled });
  } catch (error: any) {
    console.error('Error checking Aegis status:', error);
    res.status(500).json({ error: error.message || 'Failed to check Aegis status' });
  }
});

// POST /api/aegis/enable/:organizationId - Enable Aegis for organization
router.post('/enable/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;

    // Check if user is admin or owner
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins and owners can enable Aegis' });
    }

    // Check if config already exists
    const { data: existing } = await supabase
      .from('aegis_config')
      .select('id')
      .eq('organization_id', organizationId)
      .single();

    if (existing) {
      // Update existing config
      const { error } = await supabase
        .from('aegis_config')
        .update({ enabled: true })
        .eq('organization_id', organizationId);

      if (error) throw error;
    } else {
      // Create new config
      const { error } = await supabase
        .from('aegis_config')
        .insert({
          organization_id: organizationId,
          enabled: true,
        });

      if (error) throw error;
    }

    res.json({ enabled: true });
  } catch (error: any) {
    console.error('Error enabling Aegis:', error);
    res.status(500).json({ error: error.message || 'Failed to enable Aegis' });
  }
});
// GET /api/aegis/activity/:organizationId - Get activity logs
router.get('/activity/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;
    const { start_date, end_date, limit = '100', offset = '0' } = req.query;

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    let query = supabase
      .from('aegis_activity_logs')
      .select('*')
      .eq('organization_id', organizationId)
      .order('timestamp', { ascending: false })
      .limit(parseInt(limit as string, 10))
      .range(parseInt(offset as string, 10), parseInt(offset as string, 10) + parseInt(limit as string, 10) - 1);

    if (start_date) {
      query = query.gte('timestamp', start_date as string);
    }
    if (end_date) {
      query = query.lte('timestamp', end_date as string);
    }

    const { data: logs, error } = await query;

    if (error) throw error;

    res.json(logs || []);
  } catch (error: any) {
    console.error('Error fetching activity logs:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch activity logs' });
  }
});

// GET /api/aegis/inbox/:organizationId - Get inbox messages
router.get('/inbox/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const { data: messages, error } = await supabase
      .from('aegis_inbox')
      .select('*')
      .eq('organization_id', organizationId)
      .or(`user_id.is.null,user_id.eq.${userId}`)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json(messages || []);
  } catch (error: any) {
    console.error('Error fetching inbox:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch inbox' });
  }
});

// PUT /api/aegis/inbox/:id/read - Mark message as read
router.put('/inbox/:id/read', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    // Get message to verify access
    const { data: message } = await supabase
      .from('aegis_inbox')
      .select('organization_id, user_id')
      .eq('id', id)
      .single();

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', message.organization_id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Check if message is for this user or org-wide
    if (message.user_id && message.user_id !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const { data: updated, error } = await supabase
      .from('aegis_inbox')
      .update({ read: true })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    res.json(updated);
  } catch (error: any) {
    console.error('Error marking message as read:', error);
    res.status(500).json({ error: error.message || 'Failed to mark message as read' });
  }
});


// ============================================================
// Task System Endpoints
// ============================================================

// GET /api/aegis/tasks/:organizationId -- list tasks
router.get('/tasks/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;
    const { status: statusFilter } = req.query;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();
    if (!membership) return res.status(404).json({ error: 'Not found' });

    let query = supabase
      .from('aegis_tasks')
      .select('*')
      .eq('organization_id', organizationId)
      .order('created_at', { ascending: false })
      .limit(50);

    if (statusFilter) query = query.eq('status', statusFilter as string);

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aegis/tasks/:organizationId/:taskId -- task detail with steps
router.get('/tasks/:organizationId/:taskId', async (req: AuthRequest, res) => {
  try {
    const { getTaskStatus } = await import('../lib/aegis/tasks');
    const task = await getTaskStatus(req.params.taskId);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    res.json(task);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/tasks/:taskId/approve -- approve a task
router.post('/tasks/:taskId/approve', async (req: AuthRequest, res) => {
  try {
    const { approveTask } = await import('../lib/aegis/tasks');
    await approveTask(req.params.taskId);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/tasks/:taskId/cancel -- cancel a task
router.post('/tasks/:taskId/cancel', async (req: AuthRequest, res) => {
  try {
    const { cancelTask } = await import('../lib/aegis/tasks');
    await cancelTask(req.params.taskId);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/tasks/:taskId/pause -- pause a task
router.post('/tasks/:taskId/pause', async (req: AuthRequest, res) => {
  try {
    const { pauseTask } = await import('../lib/aegis/tasks');
    await pauseTask(req.params.taskId);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// Approval Endpoints
// ============================================================

// GET /api/aegis/approvals/:organizationId -- list pending approvals
router.get('/approvals/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { data } = await supabase
      .from('aegis_approval_requests')
      .select('*')
      .eq('organization_id', req.params.organizationId)
      .eq('status', 'pending')
      .order('created_at', { ascending: false });
    res.json(data || []);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/approvals/:id/approve
router.post('/approvals/:id/approve', async (req: AuthRequest, res) => {
  try {
    const { error } = await supabase
      .from('aegis_approval_requests')
      .update({ status: 'approved', reviewed_by: req.user!.id, reviewed_at: new Date().toISOString() })
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/approvals/:id/reject
router.post('/approvals/:id/reject', async (req: AuthRequest, res) => {
  try {
    const { error } = await supabase
      .from('aegis_approval_requests')
      .update({ status: 'rejected', reviewed_by: req.user!.id, reviewed_at: new Date().toISOString() })
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// Memory Endpoints
// ============================================================

// GET /api/aegis/memory/:organizationId -- list memories
router.get('/memory/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { category, search, limit = '20', offset = '0' } = req.query;
    let query = supabase
      .from('aegis_memory')
      .select('id, category, key, content, created_at, created_by, metadata', { count: 'exact' })
      .eq('organization_id', req.params.organizationId)
      .order('created_at', { ascending: false })
      .range(parseInt(offset as string), parseInt(offset as string) + parseInt(limit as string) - 1);

    if (category) query = query.eq('category', category as string);
    if (search) query = query.or(`key.ilike.%${search}%,content.ilike.%${search}%`);

    const { data, count, error } = await query;
    if (error) throw error;
    res.json({ total: count || 0, memories: data || [] });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/memory -- create a manual memory (Teach Aegis)
router.post('/memory', async (req: AuthRequest, res) => {
  try {
    const { organizationId, category, key, content } = req.body;
    const { data, error } = await supabase
      .from('aegis_memory')
      .insert({
        organization_id: organizationId,
        category: category || 'knowledge',
        key,
        content,
        created_by: req.user!.id,
      })
      .select()
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/aegis/memory/:id -- update memory
router.put('/memory/:id', async (req: AuthRequest, res) => {
  try {
    const { key, content, category } = req.body;
    const updateData: any = {};
    if (key) updateData.key = key;
    if (content) updateData.content = content;
    if (category) updateData.category = category;
    const { data, error } = await supabase
      .from('aegis_memory')
      .update(updateData)
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/aegis/memory/:id -- delete memory
router.delete('/memory/:id', async (req: AuthRequest, res) => {
  try {
    await supabase.from('aegis_memory').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/aegis/memory/clear/:organizationId -- clear all memories
router.delete('/memory/clear/:organizationId', async (req: AuthRequest, res) => {
  try {
    await supabase.from('aegis_memory').delete().eq('organization_id', req.params.organizationId);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// Management Console Endpoints (Org Settings)
// ============================================================

// GET /api/aegis/settings/:organizationId -- get Aegis org settings
router.get('/settings/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { data } = await supabase
      .from('aegis_org_settings')
      .select('*')
      .eq('organization_id', req.params.organizationId)
      .single();
    res.json(data || {
      operating_mode: 'propose',
      monthly_budget: null,
      daily_budget: null,
      per_task_budget: 25,
      tool_permissions: {},
      pr_review_mode: 'advisory',
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/aegis/settings/:organizationId -- update settings
router.put('/settings/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { operating_mode, monthly_budget, daily_budget, per_task_budget, tool_permissions, default_delivery_channel, preferred_provider, preferred_model, pr_review_mode } = req.body;
    const updateData: any = { updated_at: new Date().toISOString() };
    if (operating_mode !== undefined) updateData.operating_mode = operating_mode;
    if (monthly_budget !== undefined) updateData.monthly_budget = monthly_budget;
    if (daily_budget !== undefined) updateData.daily_budget = daily_budget;
    if (per_task_budget !== undefined) updateData.per_task_budget = per_task_budget;
    if (tool_permissions !== undefined) updateData.tool_permissions = tool_permissions;
    if (default_delivery_channel !== undefined) updateData.default_delivery_channel = default_delivery_channel;
    if (preferred_provider !== undefined) updateData.preferred_provider = preferred_provider;
    if (preferred_model !== undefined) updateData.preferred_model = preferred_model;
    if (pr_review_mode !== undefined) updateData.pr_review_mode = pr_review_mode;

    const { data: existing } = await supabase
      .from('aegis_org_settings')
      .select('id')
      .eq('organization_id', req.params.organizationId)
      .single();

    let result;
    if (existing) {
      const { data, error } = await supabase
        .from('aegis_org_settings')
        .update(updateData)
        .eq('organization_id', req.params.organizationId)
        .select()
        .single();
      if (error) throw error;
      result = data;
    } else {
      const { data, error } = await supabase
        .from('aegis_org_settings')
        .insert({ organization_id: req.params.organizationId, ...updateData })
        .select()
        .single();
      if (error) throw error;
      result = data;
    }
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aegis/tool-executions/:organizationId -- audit log
router.get('/tool-executions/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { limit = '50', offset = '0', user_id, category, tool_name, start_date, end_date } = req.query;
    let query = supabase
      .from('aegis_tool_executions')
      .select('*', { count: 'exact' })
      .eq('organization_id', req.params.organizationId)
      .order('created_at', { ascending: false })
      .range(parseInt(offset as string), parseInt(offset as string) + parseInt(limit as string) - 1);

    if (user_id) query = query.eq('user_id', user_id as string);
    if (category) query = query.eq('tool_category', category as string);
    if (tool_name) query = query.eq('tool_name', tool_name as string);
    if (start_date) query = query.gte('created_at', start_date as string);
    if (end_date) query = query.lte('created_at', end_date as string);

    const { data, count, error } = await query;
    if (error) throw error;
    res.json({ total: count || 0, executions: data || [] });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aegis/spending/:organizationId -- spending data
router.get('/spending/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { data: settings } = await supabase
      .from('aegis_org_settings')
      .select('monthly_budget, daily_budget, per_task_budget')
      .eq('organization_id', req.params.organizationId)
      .single();

    // Get monthly spending from ai_usage_logs
    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);

    const { data: monthlyLogs } = await supabase
      .from('ai_usage_logs')
      .select('estimated_cost, feature, created_at')
      .eq('organization_id', req.params.organizationId)
      .gte('created_at', monthStart.toISOString());

    const monthlySpend = (monthlyLogs || []).reduce((sum, l) => sum + (l.estimated_cost || 0), 0);

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const dailySpend = (monthlyLogs || [])
      .filter(l => new Date(l.created_at) >= todayStart)
      .reduce((sum, l) => sum + (l.estimated_cost || 0), 0);

    // Spending by category
    const byCategory: Record<string, number> = {};
    for (const log of monthlyLogs || []) {
      byCategory[log.feature] = (byCategory[log.feature] || 0) + (log.estimated_cost || 0);
    }

    res.json({
      monthly: { spent: monthlySpend, budget: settings?.monthly_budget || null },
      daily: { spent: dailySpend, budget: settings?.daily_budget || null },
      perTask: { limit: settings?.per_task_budget || 25 },
      byCategory,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aegis/usage-stats/:organizationId -- usage analytics
router.get('/usage-stats/:organizationId', async (req: AuthRequest, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();

    const { data: messages } = await supabase
      .from('aegis_chat_messages')
      .select('created_at, role')
      .eq('role', 'user')
      .gte('created_at', thirtyDaysAgo);

    const { data: toolExecs } = await supabase
      .from('aegis_tool_executions')
      .select('tool_name, success, created_at')
      .eq('organization_id', req.params.organizationId)
      .gte('created_at', thirtyDaysAgo);

    const { data: fixes } = await supabase
      .from('project_security_fixes')
      .select('status')
      .eq('organization_id', req.params.organizationId)
      .gte('created_at', thirtyDaysAgo);

    const totalMessages = messages?.length || 0;
    const fixSuccessRate = fixes?.length
      ? fixes.filter(f => f.status === 'completed' || f.status === 'merged').length / fixes.length
      : 0;

    // Most used tools
    const toolCounts: Record<string, number> = {};
    for (const exec of toolExecs || []) {
      toolCounts[exec.tool_name] = (toolCounts[exec.tool_name] || 0) + 1;
    }
    const topTools = Object.entries(toolCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, count]) => ({ name, count }));

    res.json({
      messagesThisMonth: totalMessages,
      avgMessagesPerDay: Math.round(totalMessages / 30),
      fixSuccessRate: Math.round(fixSuccessRate * 100),
      topTools,
      totalToolExecutions: toolExecs?.length || 0,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aegis/threads-by-project/:organizationId -- threads filtered by project
router.get('/threads-by-project/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;
    const projectId = req.query.projectId as string;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();
    if (!membership) return res.status(404).json({ error: 'Not found' });

    let query = supabase
      .from('aegis_chat_threads')
      .select('*')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .order('updated_at', { ascending: false });

    if (projectId) {
      query = query.eq('project_id', projectId);
    }

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (error: any) {
    console.error('Error fetching threads by project:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch threads' });
  }
});

// ============================================================
// Chat streaming (AI SDK SSE) — formerly routes/aegis-v3.ts
// Uses the shared hasAegisPermission helper above (interact_with_aegis,
// with the legacy interact_with_security_agent fallback).
// ============================================================

router.post('/stream', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { organizationId, threadId, message, context, modelId } = req.body ?? {};

  if (!organizationId || !message) {
    return res.status(400).json({ error: 'organizationId and message are required' });
  }

  if (!(await hasAegisPermission(organizationId, userId))) {
    return res.status(403).json({ error: 'You do not have permission to use Aegis' });
  }

  const dailyLimit = await checkRateLimit(`ai:aegis:user:${userId}`, 200, 86400);
  if (!dailyLimit.allowed) {
    return res.status(429).json({ error: 'Daily message limit reached. Try again tomorrow.' });
  }

  let resolvedThreadId: string | null = null;
  try {
    resolvedThreadId = await getOrCreateThread(
      organizationId,
      userId,
      threadId,
      message,
      context,
    );

    // PREFLIGHT — every read-only setup that can fail goes BEFORE writeHead,
    // so a provider loader rejection / cost-cap block / DB error returns a
    // clean 500 + JSON body instead of a half-flushed SSE stream the client
    // can't make sense of. Once writeHead fires, we're committed to the SSE
    // channel.
    // Fresh-org rule: orgs that haven't topped up yet default to Haiku
    // regardless of what the client requested, so they can complete a turn
    // on the $5 grant. paid-up orgs respect the request.
    const { data: paidTxnRow } = await supabase
      .from('billing_transactions')
      .select('id')
      .eq('organization_id', organizationId)
      .in('kind', ['topup', 'auto_recharge_topup'])
      .limit(1)
      .maybeSingle();
    const effectiveModelId = paidTxnRow ? modelId : FRESH_ORG_DEFAULT_MODEL_ID;

    const [history, memoryContext, providerInfo] = await Promise.all([
      loadThreadHistory(resolvedThreadId),
      queryRelevantMemories(organizationId, message),
      getProviderInfoForOrg(organizationId, effectiveModelId),
    ]);

    const estimateCents = getAegisTurnEstimateCents(providerInfo.model);
    const gate = await canCharge(organizationId, estimateCents);
    // Only block (and surface the top-up CTA) when the balance is genuinely too
    // low. canCharge also returns reason:'db_unavailable' when it can't READ the
    // balance (a Supabase blip) — failing closed there would block EVERY org,
    // including well-funded ones, the instant the DB hiccups, and tell them to
    // pay for our outage. Fail open on any non-credit reason: allow the turn and
    // log it; metering reconciles post-hoc and the drift cron catches leaks.
    const blockedForCredit = !gate.allowed && gate.reason === 'insufficient_credit';
    if (!gate.allowed && gate.reason !== 'insufficient_credit') {
      console.warn('[aegis] canCharge non-credit block — failing open', {
        organizationId,
        reason: gate.reason ?? null,
      });
    }
    if (blockedForCredit) {
      // Funnel marker: a paywall block was shown. Pairs with the client-side
      // topup_modal_opened / topup_credited events for launch conversion.
      console.info('[monetize] aegis_cost_cap_block', { organizationId });
    }
    const cap = {
      allowed: !blockedForCredit,
      message: blockedForCredit
        ? `Your prepaid balance is too low to start a turn. Add credit to continue.`
        : undefined,
    };

    // Build the agent here too — getLanguageModelForOrg throws on missing /
    // disabled platform keys, and we want that as a 500 not as a torn-down
    // SSE. If cap blocked above we skip agent construction (no model call
    // needed).
    const agent = cap.allowed
      ? await createAegisAgent({
          orgId: organizationId,
          userId,
          threadId: resolvedThreadId,
          userMessage: message,
          priorMessageCount: history.length,
          context,
          memoryContext,
          modelId: effectiveModelId,
        })
      : null;

    // Flush response headers (including X-Thread-Id) eagerly, BEFORE we
    // start streaming — but only AFTER preflight has succeeded. The client
    // needs the threadId on the wire before any SSE chunks arrive so a fast
    // Stop click during submission can still resolve the thread; flushing
    // earlier (pre-preflight) means a provider failure can't return a 500
    // anymore because the status is already 200. We bypass pipeUIMessageStreamToResponse
    // here so we control when writeHead fires.
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Vercel-AI-UI-Message-Stream': 'v1',
      'X-Accel-Buffering': 'no',
      'X-Thread-Id': resolvedThreadId,
    });

    if (!cap.allowed) {
      // Pre-flight cost cap blocked. Record a cost_cap error assistant
      // message and skip the model call. We deliberately also skip saving
      // the user message — there's nothing to answer it with. Headers are
      // flushed so the client picks up X-Thread-Id and treats no-content +
      // persisted error row the same as any other turn.
      await writeAegisChatError(resolvedThreadId, { type: 'cost_cap', message: cap.message });
      return res.end();
    }

    // Persist the user message before streaming starts. A refresh mid-stream
    // then keeps the question visible; only the in-flight assistant tokens
    // are lost (the user can resend).
    await saveUserMessage({ threadId: resolvedThreadId, userId, content: message });

    // Kick off title generation in parallel with the model stream. Decoupled
    // from the assistant onFinish so a Stop click on the response doesn't
    // also cancel the title gen — the user's intent to keep this thread is
    // committed the moment they sent the first message. We use the user
    // message alone (assistant text empty); the title prompt handles that
    // gracefully and the result is good enough for the sidebar.
    if (history.length === 0) {
      void generateThreadTitle(resolvedThreadId, message, '').catch((err) =>
        console.error('[aegis] auto-title failed', err),
      );
    }

    const messages: ModelMessage[] = [...history, { role: 'user', content: message }];
    const result = await agent!.stream({ messages });

    // Force the agent to drive to completion regardless of whether the HTTP
    // response is consumed. This is the canonical AI SDK guarantee for
    // "client might disconnect mid-stream but I need onFinish to fire" —
    // without it, when the user navigates to another chat mid-stream the
    // server-side response gets torn down, the SDK stops generating, and
    // the agent's onFinish (which calls saveAssistantMessage) never runs.
    // consumeStream tees the underlying generation into a background drain
    // that's independent of the response pipe, so the agent always runs to
    // completion and onFinish always fires. Errors are swallowed — any
    // meaningful failure surfaces in toUIMessageStreamResponse's onError
    // below and/or in the agent's onFinish error path.
    void result.consumeStream({
      onError: (err: unknown) =>
        console.error('[aegis] consumeStream error:', err),
    });

    // Resumable-stream registration. Each stream gets a fresh streamId; we
    // store thread->streamId in Redis so a reconnecting client can find it
    // via GET /:threadId/stream. The chunk sink tees every SSE byte into a
    // Redis list so the resume endpoint can replay. Best-effort — a Redis
    // outage just means resume falls back to the seed-load + tail-poll path
    // (the live HTTP write is the source of truth).
    const streamId = randomUUID();
    await registerStream(resolvedThreadId, streamId);
    const sink = createChunkSink(streamId);

    // onError fires for mid-stream failures (provider 429/5xx, network drops).
    // We persist the error as an assistant message so a subsequent /stream
    // call loads it as part of history; the SDK still sends a generic string
    // down the SSE channel for the live `useChat.error` hook on the client.
    // Persist is fire-and-forget — the SDK requires the callback to be sync.
    const sseResponse = result.toUIMessageStreamResponse({
      onError: (err) => {
        console.error('[aegis] Stream error:', err);
        if (resolvedThreadId) {
          void writeAegisChatError(resolvedThreadId, classifyChatError(err)).catch(
            (writeErr) => console.error('[aegis] error persistence failed', writeErr),
          );
        }
        return 'Something went wrong while generating a response.';
      },
    });

    // Pipe SDK response bytes to BOTH the live HTTP socket AND the Redis
    // chunk sink. The Redis tee is independent of the HTTP socket — if the
    // user navigates away, we keep capturing bytes for them to replay on
    // return. The agent itself keeps generating via consumeStream regardless.
    const reader = sseResponse.body!.getReader();
    let httpAlive = !res.writableEnded && !res.destroyed;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        sink.append(value);
        if (httpAlive) {
          const canContinue = res.write(value);
          if (!canContinue) {
            await new Promise<void>((resolve) => res.once('drain', () => resolve()));
          }
          if (res.writableEnded || res.destroyed) httpAlive = false;
        }
      }
    } finally {
      // Sentinel + mapping cleanup happen regardless of how the loop exits.
      // Replay readers see __END__ and close out cleanly; the thread mapping
      // is dropped so a re-resume after completion returns 204 immediately.
      await sink.end();
      await clearActiveStream(resolvedThreadId);
      if (!res.writableEnded) res.end();
    }
  } catch (err: any) {
    // Real cause stays in server logs; the user only ever sees the generic
    // "something went wrong" message. Leaking DB column names or supabase
    // error text into the chat is a UX failure and a small infosec leak.
    console.error('[aegis] Stream setup error:', err);
    if (resolvedThreadId) {
      await writeAegisChatError(resolvedThreadId, classifyChatError(err));
    }
    if (!res.headersSent) {
      res.status(500).json({ error: 'Something went wrong. Please try again.' });
    } else if (!res.writableEnded) {
      res.end();
    }
  }
});

// Resume an in-flight stream. The AI SDK's HttpChatTransport.reconnectToStream
// hits this endpoint by default when useChat.resumeStream() is called — its
// canonical URL shape is `${api}/${chatId}/stream`. We look up the active
// streamId for the thread, replay every SSE byte already captured, then
// tail the Redis chunk list for new bytes until __END__. If there's no
// active stream (already finished, or never started), we 204 — the SDK
// treats that as "nothing to resume" and proceeds with whatever messages
// are already in state.
router.get('/stream/:threadId/stream', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { threadId } = req.params;
  if (!threadId) return res.status(400).end();

  const thread = await getThreadForParticipant(threadId, userId);
  if (!thread) return res.status(404).end();
  if (!(await hasAegisPermission(thread.organization_id, userId))) {
    return res.status(403).end();
  }

  const streamId = await getActiveStreamId(threadId);
  if (!streamId) {
    // No live stream to resume. SDK reads this as null and is a no-op.
    return res.status(204).end();
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Vercel-AI-UI-Message-Stream': 'v1',
    'X-Accel-Buffering': 'no',
  });

  try {
    await replayStream(streamId, res);
  } catch (err) {
    console.error('[aegis] resume replay error', err);
  } finally {
    if (!res.writableEnded) res.end();
  }
});

// Regenerate trims the thread back to the last user message so a fresh
// /stream call (driven by useChat.regenerate on the client) re-runs against
// the same prompt. The actual streaming is the client's job — this route
// just owns the server-side cleanup.
router.post('/regenerate', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { threadId } = req.body ?? {};
  if (!threadId || typeof threadId !== 'string') {
    return res.status(400).json({ error: 'threadId is required' });
  }

  const thread = await getThreadForParticipant(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  if (!(await hasAegisPermission(thread.organization_id, userId))) {
    return res.status(403).json({ error: 'You do not have permission to use Aegis' });
  }

  const { data: lastUser } = await supabase
    .from('aegis_chat_messages')
    .select('id, created_at')
    .eq('thread_id', threadId)
    .eq('role', 'user')
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  if (!lastUser) return res.status(400).json({ error: 'No user message to regenerate from' });

  const { error: deleteErr } = await supabase
    .from('aegis_chat_messages')
    .delete()
    .eq('thread_id', threadId)
    .gt('created_at', lastUser.created_at);
  if (deleteErr) {
    console.error('[aegis] regenerate delete failed', deleteErr);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }

  res.json({ threadId });
});

export default router;
