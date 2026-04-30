import { fetchWithAuth } from './api';

export type FixStatusForBadge =
  | 'awaiting_approval'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'refused'
  | 'rejected';

export interface AegisThread {
  id: string;
  organizationId: string;
  userId: string;
  createdBy: string;
  isCreator: boolean;
  participantCount: number;
  title: string;
  createdAt: string;
  updatedAt: string;
  pinnedAt: string | null;
  archivedAt: string | null;
  fixStatus: FixStatusForBadge | null;
}

export interface AegisParticipant {
  userId: string;
  joinedAt: string;
  isCreator: boolean;
  displayName: string | null;
  email: string | null;
  avatarUrl: string | null;
}

export interface InvitableUser {
  userId: string;
  displayName: string | null;
  avatarUrl: string | null;
  email: string | null;
  role: string | null;
}

export type TextPart = { type: 'text'; text: string };
export type ToolCallPart = {
  type: 'tool-call';
  toolCallId: string;
  toolName: string;
  args: Record<string, unknown>;
};
export type ToolResultPart = {
  type: 'tool-result';
  toolCallId: string;
  toolName: string;
  result: unknown;
  isError?: boolean;
};
export type MessagePart = TextPart | ToolCallPart | ToolResultPart;

export type AegisChatErrorType = 'rate_limit' | 'transient' | 'cost_cap';

export interface AegisChatError {
  type: AegisChatErrorType;
  statusCode: number | null;
  message: string | null;
}

export interface AegisMessage {
  id: string;
  threadId: string;
  role: 'user' | 'assistant';
  userId: string | null;
  content: string;
  metadata: { parts: MessagePart[]; error?: AegisChatError };
  createdAt: string;
}

export const aegisApi = {
  async listThreads(organizationId: string): Promise<AegisThread[]> {
    const { threads } = await fetchWithAuth(
      `/api/aegis/threads?organizationId=${encodeURIComponent(organizationId)}`,
    );
    return threads;
  },

  async createThread(organizationId: string, title?: string): Promise<AegisThread> {
    const { thread } = await fetchWithAuth('/api/aegis/threads', {
      method: 'POST',
      body: JSON.stringify({ organizationId, title }),
    });
    return thread;
  },

  async renameThread(threadId: string, title: string): Promise<AegisThread> {
    const { thread } = await fetchWithAuth(`/api/aegis/threads/${threadId}`, {
      method: 'PATCH',
      body: JSON.stringify({ title }),
    });
    return thread;
  },

  async setThreadPinned(threadId: string, pinned: boolean): Promise<AegisThread> {
    const { thread } = await fetchWithAuth(`/api/aegis/threads/${threadId}`, {
      method: 'PATCH',
      body: JSON.stringify({ pinned }),
    });
    return thread;
  },

  async setThreadArchived(threadId: string, archived: boolean): Promise<AegisThread> {
    const { thread } = await fetchWithAuth(`/api/aegis/threads/${threadId}`, {
      method: 'PATCH',
      body: JSON.stringify({ archived }),
    });
    return thread;
  },

  async deleteThread(threadId: string): Promise<void> {
    await fetchWithAuth(`/api/aegis/threads/${threadId}`, { method: 'DELETE' });
  },

  async getMessages(threadId: string): Promise<AegisMessage[]> {
    const { messages } = await fetchWithAuth(`/api/aegis/threads/${threadId}/messages`);
    return messages;
  },

  async truncateBelow(messageId: string): Promise<void> {
    await fetchWithAuth(`/api/aegis/messages/${messageId}/below`, { method: 'DELETE' });
  },

  async regenerate(threadId: string): Promise<{ threadId: string }> {
    return fetchWithAuth('/api/aegis/chat/regenerate', {
      method: 'POST',
      body: JSON.stringify({ threadId }),
    });
  },

  async autoTitle(threadId: string): Promise<AegisThread> {
    const { thread } = await fetchWithAuth(`/api/aegis/threads/${threadId}/auto-title`, {
      method: 'POST',
    });
    return thread;
  },

  async listParticipants(threadId: string): Promise<AegisParticipant[]> {
    const { participants } = await fetchWithAuth(`/api/aegis/threads/${threadId}/participants`);
    return (participants ?? []).map((p: any) => ({
      userId: p.user_id,
      joinedAt: p.joined_at,
      isCreator: p.is_creator,
      displayName: p.display_name,
      email: p.email,
      avatarUrl: p.avatar_url,
    }));
  },

  async addParticipant(threadId: string, userId: string): Promise<void> {
    await fetchWithAuth(`/api/aegis/threads/${threadId}/participants`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
  },

  async removeParticipant(threadId: string, userId: string): Promise<void> {
    await fetchWithAuth(`/api/aegis/threads/${threadId}/participants/${userId}`, { method: 'DELETE' });
  },

  async getInviteCode(threadId: string): Promise<{ code: string | null }> {
    return fetchWithAuth(`/api/aegis/threads/${threadId}/invite-code`);
  },

  async createInviteCode(threadId: string): Promise<{ code: string }> {
    return fetchWithAuth(`/api/aegis/threads/${threadId}/invite-code`, { method: 'POST' });
  },

  async revokeInviteCode(threadId: string): Promise<void> {
    await fetchWithAuth(`/api/aegis/threads/${threadId}/invite-code`, { method: 'DELETE' });
  },

  async redeemInviteCode(code: string): Promise<{ threadId: string }> {
    return fetchWithAuth('/api/aegis/invite/redeem', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
  },

  async listInvitableUsers(organizationId: string, threadId?: string): Promise<InvitableUser[]> {
    const qs = threadId ? `?threadId=${encodeURIComponent(threadId)}` : '';
    const { users } = await fetchWithAuth(
      `/api/aegis/organizations/${organizationId}/invitable-users${qs}`,
    );
    return users;
  },
};
