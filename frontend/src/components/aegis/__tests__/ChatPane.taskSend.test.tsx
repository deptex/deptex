import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '../../../test/utils';
import type { AegisTask } from '../../../lib/aegis-api';
// Static import (not a per-test dynamic import): ChatPane's module graph is
// heavy (react-markdown, syntax highlighter), so loading it inside a test can
// blow the 5s test timeout on a cold transform — and the abandoned test body
// then mounts a zombie ChatPane during the NEXT test. vi.mock hoists above
// static imports, so all module mocks still apply.
import { ChatPane } from '../ChatPane';

// The split-brain backstop. A task thread's send must go to the task's own
// agent (POST /api/aegis/tasks/:id/message via aegisApi.sendTaskMessage) and
// NEVER through useChat's sendMessage (the chat agent's SSE path). These pin:
// (a) task threads → sendTaskMessage(task.id, orgId, text) + an optimistic
//     user bubble, and useChat.sendMessage is never called;
// (b) a queued response ({queued:true}) surfaces the subtle "Queued" hint;
// (c) normal chat threads are untouched → sendMessage fires, sendTaskMessage
//     never does;
// (d) while the parent's task list is unresolved (tasksLoading), a send in an
//     existing thread with no resolved task FAILS CLOSED — neither agent is
//     called — because an unresolved thread might be a task thread and
//     misrouting it to the chat agent is the exact split-brain (a) forbids.

const mocks = vi.hoisted(() => ({
  sendMessage: vi.fn(),
  clearError: vi.fn(),
  resumeStream: vi.fn(async () => undefined),
  stop: vi.fn(),
  sendTaskMessage: vi.fn(),
  getMessages: vi.fn(async () => []),
}));

// Stateful useChat mock: setMessages must actually re-render so the optimistic
// user bubble is assertable in the DOM. Everything else is inert — the whole
// point of the task path is that useChat's machinery never runs.
vi.mock('@ai-sdk/react', async () => {
  const React = await import('react');
  return {
    useChat: () => {
      const [messages, setMessages] = React.useState<any[]>([]);
      return {
        messages,
        setMessages,
        sendMessage: mocks.sendMessage,
        regenerate: vi.fn(),
        stop: mocks.stop,
        status: 'ready',
        error: undefined,
        clearError: mocks.clearError,
        resumeStream: mocks.resumeStream,
      };
    },
  };
});

// ChatPane only constructs the transport; keep the real `ai` package out.
vi.mock('ai', () => ({
  DefaultChatTransport: class {
    constructor(_opts: unknown) {}
  },
}));

vi.mock('../../../lib/aegis-api', () => ({
  aegisApi: {
    sendTaskMessage: mocks.sendTaskMessage,
    getMessages: mocks.getMessages,
    regenerate: vi.fn(),
  },
}));

vi.mock('../../../lib/api', () => ({
  api: {
    peekAIModels: vi.fn(() => null),
    getAIModels: vi.fn(async () => ({ models: [], enabledModels: [], defaultModel: '' })),
    subscribeAIModels: vi.fn(() => () => {}),
  },
  getAuthToken: vi.fn(async () => 'test-token'),
}));

vi.mock('../../../lib/supabase', () => {
  const makeChannel = () => {
    const ch: any = {};
    ch.on = vi.fn(() => ch);
    ch.subscribe = vi.fn(() => ch);
    return ch;
  };
  return {
    supabase: {
      from: vi.fn(() => ({
        select: vi.fn(() => ({
          eq: vi.fn(async () => ({ data: [] })),
        })),
      })),
      channel: vi.fn(() => makeChannel()),
      removeChannel: vi.fn(),
    },
  };
});

const task: AegisTask = {
  id: 'task-1',
  organizationId: 'org-1',
  projectId: 'proj-1',
  threadId: 'thread-1',
  kind: 'fix',
  title: 'Fix simple-git CVE',
  description: null,
  status: 'completed',
  source: 'finding',
  targets: [],
  totalFixes: 1,
  completedFixes: 1,
  failedFixes: 0,
  summary: null,
  createdAt: '2026-07-01T00:00:00Z',
  updatedAt: '2026-07-01T00:00:00Z',
  acceptedAt: '2026-07-01T00:00:00Z',
  completedAt: '2026-07-01T01:00:00Z',
};

async function renderChatPane(props: {
  liveReload: boolean;
  task: AegisTask | null;
  tasksLoading?: boolean;
}) {
  const utils = render(
    <ChatPane
      organizationId="org-1"
      threadId="thread-1"
      currentUserId="user-1"
      displayName="Henry"
      onThreadCreated={vi.fn()}
      liveReload={props.liveReload}
      task={props.task}
      tasksLoading={props.tasksLoading}
    />,
  );
  // Let the seed-load (getMessages + resumeStream) settle before interacting.
  await waitFor(() => expect(mocks.getMessages).toHaveBeenCalled());
  return utils;
}

function submitText(text: string) {
  const textarea = screen.getByPlaceholderText('Ask anything');
  fireEvent.change(textarea, { target: { value: text } });
  fireEvent.keyDown(textarea, { key: 'Enter' });
}

describe('ChatPane — task-thread sends wake the task agent (never the chat agent)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getMessages.mockImplementation(async () => []);
    mocks.sendTaskMessage.mockResolvedValue({ woke: true, queued: false, threadId: 'thread-1' });
    // jsdom has no scrollIntoView (ChatPane auto-scrolls on new messages).
    window.HTMLElement.prototype.scrollIntoView = vi.fn();
  });

  // Explicit unmount: each test renders its own ChatPane and queries by
  // placeholder, so a leaked mount from a prior test = duplicate matches.
  afterEach(() => cleanup());

  it('routes a task-thread send to sendTaskMessage with an optimistic bubble; useChat.sendMessage never fires', async () => {
    await renderChatPane({ liveReload: true, task });

    submitText('bump it to 3.36.0 instead');

    // Optimistic user bubble appears immediately (before the POST resolves).
    expect(screen.getByText('bump it to 3.36.0 instead')).toBeInTheDocument();

    await waitFor(() =>
      expect(mocks.sendTaskMessage).toHaveBeenCalledWith('task-1', 'org-1', 'bump it to 3.36.0 instead'),
    );
    expect(mocks.sendTaskMessage).toHaveBeenCalledTimes(1);
    // The split-brain assertion: the chat agent's SSE path must never run.
    expect(mocks.sendMessage).not.toHaveBeenCalled();
  });

  it('shows the "Queued" hint when the agent is mid-run ({queued: true})', async () => {
    mocks.sendTaskMessage.mockResolvedValue({ woke: false, queued: false, threadId: 'thread-1' });
    await renderChatPane({ liveReload: true, task });

    submitText('first follow-up');
    await waitFor(() => expect(mocks.sendTaskMessage).toHaveBeenCalledTimes(1));
    // A woke (non-queued) send shows no hint.
    expect(screen.queryByText(/Queued — I'll pick this up/)).toBeNull();

    mocks.sendTaskMessage.mockResolvedValue({ woke: false, queued: true, threadId: 'thread-1' });
    submitText('second follow-up while running');
    expect(await screen.findByText(/Queued — I'll pick this up when the current run finishes/)).toBeInTheDocument();
  });

  it('normal chat threads still send through useChat.sendMessage, never sendTaskMessage', async () => {
    await renderChatPane({ liveReload: false, task: null, tasksLoading: false });

    submitText('hello aegis');

    await waitFor(() => expect(mocks.sendMessage).toHaveBeenCalledWith({ text: 'hello aegis' }));
    expect(mocks.sendTaskMessage).not.toHaveBeenCalled();
  });

  it('fails closed while the task list is unresolved: an existing thread with no task calls NEITHER agent', async () => {
    await renderChatPane({ liveReload: false, task: null, tasksLoading: true });

    submitText('is this a task thread?');

    // Neither brain may run: this thread could be a task thread whose
    // listTasks() hasn't resolved — falling through to the chat agent is the
    // split-brain this feature forbids.
    expect(mocks.sendTaskMessage).not.toHaveBeenCalled();
    expect(mocks.sendMessage).not.toHaveBeenCalled();
    expect(
      screen.getByText('Still loading this conversation — try again in a moment.'),
    ).toBeInTheDocument();
  });

  it('a resolved task thread still routes to the task agent even while tasksLoading is true elsewhere', async () => {
    // Belt-and-braces: the fail-closed guard requires !task — a thread whose
    // task HAS resolved must not be blocked by an in-flight list refresh.
    await renderChatPane({ liveReload: true, task, tasksLoading: true });

    submitText('carry on');

    await waitFor(() => expect(mocks.sendTaskMessage).toHaveBeenCalledWith('task-1', 'org-1', 'carry on'));
    expect(mocks.sendMessage).not.toHaveBeenCalled();
  });
});
