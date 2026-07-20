// @ts-nocheck
import { Router, Response } from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { userHasOrgPermission } from '../lib/permissions';
import { rowToMessage, rowToThread, mapFixStatusToBadge, type ThreadRow, type UserStateRow, type FixStatusForBadge } from '../lib/aegis/types';
import { generateThreadTitle } from '../lib/aegis-v3/title';
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


export default router;
