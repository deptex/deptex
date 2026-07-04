import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, render, screen, fireEvent, cleanup } from '../../../test/utils';
import type { AegisTask } from '../../../lib/aegis-api';
import { TaskDetailPanel } from '../TaskDetailPanel';

// The Changes tab must live-update: an amend/resume run lands new edit-step
// messages on the SAME thread, and the loader used to key on threadId alone —
// it could never re-run. These pin: (a) the initial load renders the edit-step
// diffs; (b) a realtime INSERT on the thread refetches and the NEW diff renders
// (after the 300ms trailing debounce), without flashing the empty state; and
// (c) the PanelRight toggle is persistent — visible when the panel is closed
// (aria-label "Open task details" → onOpen) and open (aria-label "Close panel"
// → onClose).

const mocks = vi.hoisted(() => ({
  getMessages: vi.fn(async () => [] as any[]),
  getFix: vi.fn(async () => ({ fix: null })),
  // Callbacks the component registered on the realtime channel; fire to
  // simulate an aegis_chat_messages INSERT landing.
  realtimeCallbacks: [] as Array<() => void>,
}));

vi.mock('../../../lib/aegis-api', () => ({
  aegisApi: {
    getMessages: mocks.getMessages,
    cancelTask: vi.fn(),
  },
}));

vi.mock('../../../lib/api', () => ({
  api: {
    getVulnerabilityDetail: vi.fn(),
    getFix: mocks.getFix,
  },
}));

// Keep the vulnerability-card module graph out — these tests use zero targets.
vi.mock('../../security/VulnerabilityExpandedCard', () => ({
  VulnerabilityExpandedCard: () => null,
}));

vi.mock('../../../lib/supabase', () => ({
  supabase: {
    channel: vi.fn(() => {
      const ch: any = {};
      ch.on = vi.fn((_evt: unknown, _filter: unknown, cb: () => void) => {
        mocks.realtimeCallbacks.push(cb);
        return ch;
      });
      ch.subscribe = vi.fn(() => ch);
      return ch;
    }),
    removeChannel: vi.fn(),
  },
}));

const task: AegisTask = {
  id: 'task-1',
  organizationId: 'org-1',
  projectId: 'proj-1',
  threadId: 'thread-1',
  kind: 'fix',
  title: 'Fix simple-git CVE',
  description: null,
  status: 'working',
  source: 'finding',
  targets: [],
  totalFixes: 1,
  completedFixes: 0,
  failedFixes: 0,
  summary: null,
  createdAt: '2026-07-01T00:00:00Z',
  updatedAt: '2026-07-01T00:00:00Z',
  acceptedAt: '2026-07-01T00:00:00Z',
  completedAt: null,
};

// Flush the panel's async change-set load inside act so its setState doesn't
// land outside React's test lifecycle (the source of act(...) warnings).
async function flushAsync(ms = 0) {
  await act(async () => {
    await new Promise((r) => setTimeout(r, ms));
  });
}

function editStepMessage(file: string): any {
  return {
    id: `m-${file}`,
    role: 'assistant',
    content: `Edited ${file}`,
    metadata: {
      parts: [
        {
          type: 'step',
          icon: 'edit',
          label: `Edited ${file}`,
          diff: `--- a/${file}\n+++ b/${file}\n@@ -1,2 +1,2 @@\n-const old = 1;\n+const updated = 2;\n`,
        },
      ],
    },
  };
}

describe('TaskDetailPanel — Changes tab live refresh + persistent toggle', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.realtimeCallbacks.length = 0;
    mocks.getMessages.mockImplementation(async () => [editStepMessage('src/one.ts')]);
    mocks.getFix.mockImplementation(async () => ({ fix: null }));
  });

  afterEach(() => cleanup());

  it('renders the edit-step diffs, then re-fetches on a realtime insert and shows the amend diff', async () => {
    render(<TaskDetailPanel task={task} open onClose={vi.fn()} onOpen={vi.fn()} />);
    await flushAsync();

    // Changes is the second tab.
    fireEvent.click(screen.getByRole('button', { name: 'Changes' }));
    expect(await screen.findByText('src/one.ts')).toBeInTheDocument();

    // The panel subscribed to the thread's message inserts.
    expect(mocks.realtimeCallbacks.length).toBeGreaterThan(0);

    // An amend lands a second edit step on the same thread → INSERT fires.
    mocks.getMessages.mockImplementation(async () => [
      editStepMessage('src/one.ts'),
      editStepMessage('src/two.ts'),
    ]);
    mocks.realtimeCallbacks.forEach((cb) => cb());

    // After the 300ms trailing debounce the refetch lands the new diff —
    // updating in place (the first diff never leaves the screen). The act
    // window covers the debounce timer + refetch.
    await flushAsync(350);
    expect(await screen.findByText('src/two.ts', {}, { timeout: 3000 })).toBeInTheDocument();
    expect(screen.getByText('src/one.ts')).toBeInTheDocument();
    expect(screen.queryByText(/No changes yet/)).toBeNull();
  });

  it('keeps the PanelRight toggle visible when closed: "Open task details" → onOpen', async () => {
    const onOpen = vi.fn();
    const onClose = vi.fn();
    render(<TaskDetailPanel task={task} open={false} onClose={onClose} onOpen={onOpen} />);
    await flushAsync();

    const openBtn = screen.getByRole('button', { name: 'Open task details' });
    fireEvent.click(openBtn);
    expect(onOpen).toHaveBeenCalledTimes(1);
    expect(onClose).not.toHaveBeenCalled();
  });

  it('the same toggle closes an open panel: "Close panel" → onClose', async () => {
    const onOpen = vi.fn();
    const onClose = vi.fn();
    render(<TaskDetailPanel task={task} open onClose={onClose} onOpen={onOpen} />);
    await flushAsync();

    fireEvent.click(screen.getByRole('button', { name: 'Close panel' }));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onOpen).not.toHaveBeenCalled();
  });
});
