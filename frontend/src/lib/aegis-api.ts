import { fetchWithAuth } from './api';

export interface AegisThread {
  id: string;
  organizationId: string;
  userId: string;
  title: string;
  createdAt: string;
  updatedAt: string;
  pinnedAt: string | null;
  archivedAt: string | null;
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

export interface AegisMessage {
  id: string;
  threadId: string;
  role: 'user' | 'assistant';
  content: string;
  metadata: { parts: MessagePart[] };
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

  async autoTitle(threadId: string): Promise<AegisThread> {
    const { thread } = await fetchWithAuth(`/api/aegis/threads/${threadId}/auto-title`, {
      method: 'POST',
    });
    return thread;
  },
};
