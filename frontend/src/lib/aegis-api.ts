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

// --- Aegis Tasks (a task is a chat with one goal) ---

export type AegisTaskStatus =
  | 'proposed'
  | 'working'
  | 'completed'
  | 'completed_with_failures'
  | 'failed'
  | 'declined'
  | 'cancelled'
  | 'needs_input';

export interface AegisTaskTarget {
  findingType: 'vulnerability' | 'semgrep' | 'secret';
  findingKey: string;
  osvId?: string;
  findingHandle?: string;
  projectId: string;
  label: string;
}

export interface AegisTask {
  id: string;
  organizationId: string;
  projectId: string | null;
  threadId: string | null;
  kind: 'fix';
  title: string;
  description: string | null;
  status: AegisTaskStatus;
  source: 'chat' | 'finding';
  targets: AegisTaskTarget[];
  totalFixes: number;
  completedFixes: number;
  failedFixes: number;
  summary: string | null;
  createdAt: string;
  updatedAt: string;
  acceptedAt: string | null;
  completedAt: string | null;
}

export interface TaskRunStatus {
  taskStatus: string;
  run: {
    fixStatus: string;
    step: number | null;
    contextTokens: number | null;
    contextWindow: number | null;
    contextPct: number | null;
    startedAt: string | null;
    prNumber: number | null;
  } | null;
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
    return fetchWithAuth('/api/aegis/v3/regenerate', {
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

  // --- Tasks ---

  async listTasks(organizationId: string): Promise<AegisTask[]> {
    const { tasks } = await fetchWithAuth(
      `/api/aegis/tasks?organizationId=${encodeURIComponent(organizationId)}`,
    );
    return tasks;
  },

  async getTask(taskId: string, organizationId: string): Promise<AegisTask> {
    const { task } = await fetchWithAuth(
      `/api/aegis/tasks/${taskId}?organizationId=${encodeURIComponent(organizationId)}`,
    );
    return task;
  },

  /** Live run telemetry for the task chat's context meter + /status. */
  async getTaskRunStatus(taskId: string, organizationId: string): Promise<TaskRunStatus> {
    return fetchWithAuth(
      `/api/aegis/tasks/${taskId}/run-status?organizationId=${encodeURIComponent(organizationId)}`,
    );
  },

  async acceptTask(taskId: string, organizationId: string): Promise<{ threadId: string }> {
    return fetchWithAuth(`/api/aegis/tasks/${taskId}/accept`, {
      method: 'PATCH',
      body: JSON.stringify({ organizationId }),
    });
  },

  async declineTask(taskId: string, organizationId: string): Promise<{ success: boolean }> {
    return fetchWithAuth(`/api/aegis/tasks/${taskId}/decline`, {
      method: 'PATCH',
      body: JSON.stringify({ organizationId }),
    });
  },

  /** Stop a running task — rejects its in-flight agent fixes so the worker aborts. */
  async cancelTask(taskId: string, organizationId: string): Promise<{ success: boolean; cancelled: number }> {
    return fetchWithAuth(`/api/aegis/tasks/${taskId}/cancel`, {
      method: 'POST',
      body: JSON.stringify({ organizationId }),
    });
  },

  /** Follow-up message on a task thread — persists it and wakes the task's own agent (never the chat agent). */
  async sendTaskMessage(taskId: string, organizationId: string, message: string):
    Promise<{ woke: boolean; queued: boolean; threadId: string }> {
    return fetchWithAuth(`/api/aegis/tasks/${taskId}/message`, {
      method: 'POST',
      body: JSON.stringify({ organizationId, message }),
    });
  },

  /** Send-to-Aegis: create a task from a finding. Returns the proposed task + its chat. */
  async createTaskFromFinding(body: {
    organizationId: string;
    projectId: string;
    findingType: 'vulnerability' | 'semgrep' | 'secret';
    findingKey: string;
    osvId?: string;
    findingHandle?: string;
    label?: string;
  }): Promise<{ taskId: string; threadId: string; deduped?: boolean }> {
    return fetchWithAuth('/api/aegis/tasks', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  },
};
