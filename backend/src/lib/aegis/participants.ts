import { supabase } from '../supabase';

export interface ParticipantRow {
  user_id: string;
  joined_at: string;
  is_creator: boolean;
  display_name: string | null;
  email: string | null;
  avatar_url: string | null;
}

export async function isParticipant(threadId: string, userId: string): Promise<boolean> {
  const { data } = await supabase
    .from('aegis_chat_participants')
    .select('user_id')
    .eq('thread_id', threadId)
    .eq('user_id', userId)
    .maybeSingle();
  return !!data;
}

export async function isCreator(threadId: string, userId: string): Promise<boolean> {
  const { data } = await supabase
    .from('aegis_chat_threads')
    .select('user_id')
    .eq('id', threadId)
    .maybeSingle();
  return !!data && data.user_id === userId;
}

export async function getThreadForParticipant(
  threadId: string,
  userId: string,
): Promise<{ id: string; organization_id: string; user_id: string; created_by: string; title: string } | null> {
  const member = await isParticipant(threadId, userId);
  if (!member) return null;
  const { data } = await supabase
    .from('aegis_chat_threads')
    .select('id, organization_id, user_id, created_by, title')
    .eq('id', threadId)
    .maybeSingle();
  return data ?? null;
}

export async function listParticipants(threadId: string): Promise<ParticipantRow[]> {
  const { data: thread } = await supabase
    .from('aegis_chat_threads')
    .select('user_id')
    .eq('id', threadId)
    .maybeSingle();
  const creatorId = thread?.user_id ?? null;

  const { data: rows } = await supabase
    .from('aegis_chat_participants')
    .select('user_id, joined_at')
    .eq('thread_id', threadId)
    .order('joined_at', { ascending: true });
  const participants = rows ?? [];
  if (participants.length === 0) return [];

  const userIds = participants.map((p) => p.user_id);
  const { data: profiles } = await supabase
    .from('user_profiles')
    .select('user_id, full_name, avatar_url')
    .in('user_id', userIds);
  const profileByUser = new Map((profiles ?? []).map((p: any) => [p.user_id, p]));

  const emailByUser = new Map<string, string | null>();
  await Promise.all(
    userIds.map(async (uid) => {
      try {
        const { data } = await supabase.auth.admin.getUserById(uid);
        emailByUser.set(uid, data?.user?.email ?? null);
      } catch {
        emailByUser.set(uid, null);
      }
    }),
  );

  return participants.map((p) => {
    const profile: any = profileByUser.get(p.user_id) ?? {};
    return {
      user_id: p.user_id,
      joined_at: p.joined_at,
      is_creator: p.user_id === creatorId,
      display_name: profile.full_name ?? null,
      email: emailByUser.get(p.user_id) ?? null,
      avatar_url: profile.avatar_url ?? null,
    };
  });
}

export async function addParticipant(threadId: string, userId: string): Promise<void> {
  await supabase
    .from('aegis_chat_participants')
    .upsert({ thread_id: threadId, user_id: userId }, { onConflict: 'thread_id,user_id' });
}

export async function removeParticipant(threadId: string, userId: string): Promise<void> {
  await supabase
    .from('aegis_chat_participants')
    .delete()
    .eq('thread_id', threadId)
    .eq('user_id', userId);
  await supabase
    .from('aegis_chat_user_state')
    .delete()
    .eq('thread_id', threadId)
    .eq('user_id', userId);
}

/**
 * Transfers ownership to the oldest remaining participant. Returns the new
 * owner user id, or null if there are no remaining participants (caller is
 * expected to delete the thread in that case).
 */
export async function transferOwnership(threadId: string): Promise<string | null> {
  const { data } = await supabase
    .from('aegis_chat_participants')
    .select('user_id, joined_at')
    .eq('thread_id', threadId)
    .order('joined_at', { ascending: true })
    .limit(1)
    .maybeSingle();
  if (!data) return null;
  await supabase
    .from('aegis_chat_threads')
    .update({ user_id: data.user_id })
    .eq('id', threadId);
  return data.user_id;
}
