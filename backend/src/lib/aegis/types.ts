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
  userId: string | null;
  content: string;
  metadata: { parts: MessagePart[] };
  createdAt: string;
}

export interface ChatRequestBody {
  organizationId: string;
  threadId?: string;
  messages: Array<{
    role: 'user' | 'assistant';
    content: string;
    parts?: MessagePart[];
  }>;
}

export interface ThreadRow {
  id: string;
  organization_id: string;
  user_id: string;
  created_by: string;
  title: string;
  created_at: string;
  updated_at: string;
}

export interface UserStateRow {
  pinned_at: string | null;
  archived_at: string | null;
}

export function rowToThread(
  row: ThreadRow,
  viewerId: string,
  userState: UserStateRow | null,
  participantCount: number,
): AegisThread {
  return {
    id: row.id,
    organizationId: row.organization_id,
    userId: row.user_id,
    createdBy: row.created_by,
    isCreator: row.user_id === viewerId,
    participantCount,
    title: row.title,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    pinnedAt: userState?.pinned_at ?? null,
    archivedAt: userState?.archived_at ?? null,
  };
}

export function rowToMessage(row: {
  id: string;
  thread_id: string;
  role: 'user' | 'assistant';
  user_id: string | null;
  content: string;
  metadata: unknown;
  created_at: string;
}): AegisMessage {
  const metadata = (row.metadata && typeof row.metadata === 'object'
    ? (row.metadata as Record<string, unknown>)
    : {}) as { parts?: MessagePart[] };
  return {
    id: row.id,
    threadId: row.thread_id,
    role: row.role,
    userId: row.user_id ?? null,
    content: row.content,
    metadata: { parts: metadata.parts ?? [] },
    createdAt: row.created_at,
  };
}
