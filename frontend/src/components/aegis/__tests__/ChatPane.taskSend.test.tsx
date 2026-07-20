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
  cancelTask: vi.fn(async () => ({ success: true, cancelled: 1 })),
  getMessages: vi.fn(async () => []),
  getTaskRunStatus: vi.fn(async () => ({ taskStatus: 'completed', run: null })),
  // What useChat reports (set per-test to simulate a chat SSE stream).
  chatStatus: 'ready' as string,
  // Rows the project_security_fixes query resolves with — a queued/executing
  // row flips ChatPane's `taskWorking` on (the worker-run signal driving the
  // in-input Stop + thinking dot).
  fixRows: [] as Array<{ status: string }>,
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
        status: mocks.chatStatus,
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
    cancelTask: mocks.cancelTask,
    getMessages: mocks.getMessages,
    getTaskRunStatus: mocks.getTaskRunStatus,
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
          eq: vi.fn(async () => ({ data: mocks.fixRows })),
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
  // Target the textbox by role, not placeholder — the placeholder flips to
  // "Add a follow-up" once a task run is active (taskWorking), so a
  // placeholder-keyed query would miss it on a second, mid-run send.
  const textarea = screen.getByRole('textbox');
  fireEvent.change(textarea, { target: { value: text } });
  fireEvent.keyDown(textarea, { key: 'Enter' });
}

describe('ChatPane — task-thread sends wake the task agent (never the chat agent)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getMessages.mockImplementation(async () => []);
    mocks.sendTaskMessage.mockResolvedValue({ woke: true, queued: false, threadId: 'thread-1' });
    mocks.chatStatus = 'ready';
    mocks.fixRows = [];
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

  it('/status runs client-side — reads run telemetry, sends NOTHING to either agent', async () => {
    mocks.getTaskRunStatus.mockResolvedValue({
      taskStatus: 'working',
      run: { fixStatus: 'executing', step: 12, contextTokens: 90000, contextWindow: 200000, contextPct: 0.45, startedAt: null, prNumber: 7 },
    } as any);
    await renderChatPane({ liveReload: true, task: { ...task, status: 'working' } });

    submitText('/status');

    await waitFor(() => expect(mocks.getTaskRunStatus).toHaveBeenCalledWith('task-1', 'org-1'));
    // The formatted status line renders in the ephemeral output banner.
    await waitFor(() => expect(screen.getByText(/context 45%/)).toBeInTheDocument());
    // A command is NEVER a message to the agent (or the chat agent).
    expect(mocks.sendTaskMessage).not.toHaveBeenCalled();
    expect(mocks.sendMessage).not.toHaveBeenCalled();
  });

  it('renders the context-window ring in the composer when the run has telemetry', async () => {
    mocks.getTaskRunStatus.mockResolvedValue({
      taskStatus: 'working',
      run: { fixStatus: 'executing', step: 8, contextTokens: 142000, contextWindow: 200000, contextPct: 0.71, startedAt: null, prNumber: null },
    } as any);
    await renderChatPane({ liveReload: true, task: { ...task, status: 'working' } });
    // The ring shows the rounded percent in the toolbar.
    await waitFor(() => expect(screen.getByText('71%')).toBeInTheDocument());
  });

  it('/retry wakes the agent with a retry message — never sends the raw "/retry"', async () => {
    // task.status is 'completed' (terminal), so a retry is allowed.
    await renderChatPane({ liveReload: true, task });

    submitText('/retry');

    await waitFor(() =>
      expect(mocks.sendTaskMessage).toHaveBeenCalledWith('task-1', 'org-1', 'Please try this again.'),
    );
    // The literal command string must not be sent as a message.
    expect(mocks.sendTaskMessage).not.toHaveBeenCalledWith('task-1', 'org-1', '/retry');
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

  it('shows Stop in the input during a worker-side task run; clicking cancels the task, not useChat', async () => {
    // A queued/executing fix row = the task agent is running server-side.
    // useChat is idle ('ready'), so the Stop must come from taskWorking.
    mocks.fixRows = [{ status: 'executing' }];
    await renderChatPane({ liveReload: true, task });

    // taskWorking resolves async (supabase query) → the input flips to its
    // streaming form and the mic slot becomes the Stop square.
    const stopBtn = await screen.findByRole('button', { name: 'Stop generating' });
    fireEvent.click(stopBtn);

    // Same call TaskDetailPanel's Stop makes — the worker aborts at its next
    // step boundary. useChat.stop() must NOT fire (there's no SSE stream).
    await waitFor(() => expect(mocks.cancelTask).toHaveBeenCalledWith('task-1', 'org-1'));
    expect(mocks.cancelTask).toHaveBeenCalledTimes(1);
    expect(mocks.stop).not.toHaveBeenCalled();
  });

  it('shows a chat skeleton while the thread loads, revealing the "Started task" header only once loaded', async () => {
    // Hold getMessages pending so we can observe the loading window: the
    // skeleton is up and the task header ("Started task") must NOT have popped
    // in yet (the reported jump). Then it resolves and both flip.
    let resolveMsgs: (v: any[]) => void = () => {};
    mocks.getMessages.mockImplementation(
      (() => new Promise((res) => { resolveMsgs = res as (v: any[]) => void; })) as any,
    );

    render(
      <ChatPane
        organizationId="org-1"
        threadId="thread-1"
        currentUserId="user-1"
        displayName="Henry"
        onThreadCreated={vi.fn()}
        liveReload
        task={task}
      />,
    );

    await waitFor(() => expect(mocks.getMessages).toHaveBeenCalled());
    expect(document.querySelector('[aria-label="Loading conversation"]')).not.toBeNull();
    expect(screen.queryByText('Started task')).toBeNull();

    // History arrives → skeleton gone, task header revealed as one.
    resolveMsgs([]);
    await waitFor(() =>
      expect(document.querySelector('[aria-label="Loading conversation"]')).toBeNull(),
    );
    expect(screen.getByText('Started task')).toBeInTheDocument();
  });

  it('fires onFirstLoad after the thread history loads (so the parent can slide the panel in)', async () => {
    // The panel is held closed over the skeleton until this fires. Hold
    // getMessages pending: onFirstLoad must NOT fire yet; then resolve → fires.
    let resolveMsgs: (v: any[]) => void = () => {};
    mocks.getMessages.mockImplementation(
      (() => new Promise((res) => { resolveMsgs = res as (v: any[]) => void; })) as any,
    );
    const onFirstLoad = vi.fn();

    render(
      <ChatPane
        organizationId="org-1"
        threadId="thread-1"
        currentUserId="user-1"
        displayName="Henry"
        onThreadCreated={vi.fn()}
        liveReload
        task={task}
        onFirstLoad={onFirstLoad}
      />,
    );

    await waitFor(() => expect(mocks.getMessages).toHaveBeenCalled());
    expect(onFirstLoad).not.toHaveBeenCalled();

    resolveMsgs([]);
    await waitFor(() => expect(onFirstLoad).toHaveBeenCalledTimes(1));
  });

  it('shows the in-input Stop the instant a task follow-up is sent (before any fix row goes running)', async () => {
    // The lag bug: the thinking dot + Stop are driven by taskWorking, which used
    // to flip only once a poll/realtime read saw the fix row running — so for a
    // few seconds after send the mic still showed. No running row exists yet
    // here; the Stop must appear from the optimistic flip on send alone.
    mocks.fixRows = []; // no running fix row
    await renderChatPane({ liveReload: true, task });

    // Idle before sending: the input shows the mic, not Stop.
    expect(screen.queryByRole('button', { name: 'Stop generating' })).toBeNull();

    submitText('bump it once more');

    // Immediately after send (no await for any poll/realtime read) the input is
    // in its streaming form with Stop.
    expect(screen.getByRole('button', { name: 'Stop generating' })).toBeInTheDocument();
    await waitFor(() => expect(mocks.sendTaskMessage).toHaveBeenCalledTimes(1));
  });

  it('poll fallback surfaces a late reply when realtime never delivers (the "nothing until refresh" fix)', async () => {
    // The supabase channel mock never invokes its subscription callback, so this
    // harness models a DEAD realtime socket — the exact "I asked and nothing came
    // back until I refreshed" case. Only the send-armed poll can surface the reply.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      mocks.getMessages.mockResolvedValue([]);
      mocks.fixRows = []; // idle input at submit time; the poll reloads regardless
      mocks.sendTaskMessage.mockResolvedValue({ woke: true, queued: false, threadId: 'thread-1' });

      render(
        <ChatPane
          organizationId="org-1"
          threadId="thread-1"
          currentUserId="user-1"
          displayName="Henry"
          onThreadCreated={vi.fn()}
          liveReload
          task={task}
        />,
      );
      await vi.advanceTimersByTimeAsync(50);

      submitText('does the override resolve to 4.1.0?');
      await waitFor(() => expect(mocks.sendTaskMessage).toHaveBeenCalledTimes(1));

      // The worker (eventually) persists its answer; realtime stays silent.
      mocks.getMessages.mockResolvedValue([
        {
          id: 'm-answer',
          role: 'assistant',
          content: 'Yes — the override forces set-value to 4.1.0.',
          metadata: { parts: [{ type: 'text', text: 'Yes — the override forces set-value to 4.1.0.' }] },
        },
      ] as any);

      // Advance past one poll cadence — the fallback reloads and renders the reply
      // without any realtime event.
      await vi.advanceTimersByTimeAsync(4000);
      expect(screen.getByText('Yes — the override forces set-value to 4.1.0.')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('a streaming NON-task chat still stops via useChat.stop, never cancelTask', async () => {
    mocks.chatStatus = 'streaming';
    await renderChatPane({ liveReload: false, task: null, tasksLoading: false });

    const stopBtn = await screen.findByRole('button', { name: 'Stop generating' });
    fireEvent.click(stopBtn);

    expect(mocks.stop).toHaveBeenCalledTimes(1);
    expect(mocks.cancelTask).not.toHaveBeenCalled();
  });
});
