import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, render, screen, fireEvent, cleanup } from '../../../test/utils';
import type { AegisTask } from '../../../lib/aegis-api';
import { TaskDetailPanel } from '../TaskDetailPanel';

// The Changes tab is the PR's cumulative "Files changed" view. These pin:
// (a) with a PR (`prNumber != null`), the NET change renders — exactly ONE
//     card per file from GET /api/aegis/fix/:fixId/changes, message-derived
//     stage diffs suppressed, and `lockfile: true` files (machine-regenerated
//     fallout, not authored changes) hidden outright — UNLESS the PR is
//     lockfile-only, in which case they're the change and render as
//     name + counts + "diff not shown";
// (b) before a PR exists (`prNumber: null`), the tab falls back to the
//     chronological edit-step stage diffs from the chat;
// (c) a realtime INSERT on the thread refetches (300ms trailing debounce) and
//     a file's updated patch replaces the old one IN PLACE — still one card;
// (d) the PanelRight toggle is persistent — visible closed ("Open task
//     details" → onOpen) and open ("Close panel" → onClose).

const mocks = vi.hoisted(() => ({
  getMessages: vi.fn(async () => [] as any[]),
  getFixChanges: vi.fn(async () => ({
    prNumber: null as number | null,
    prUrl: null as string | null,
    files: [] as any[],
  })),
  // Callbacks the component registered on the realtime channel; fire to
  // simulate an aegis_chat_messages INSERT landing.
  realtimeCallbacks: [] as Array<() => void>,
}));

vi.mock('../../../lib/aegis-api', () => ({
  aegisApi: {
    getMessages: mocks.getMessages,
    cancelTask: vi.fn(),
    // run-status feeds the context meter; run: null keeps the meter hidden in
    // these change-set tests.
    getTaskRunStatus: vi.fn(async () => ({ taskStatus: 'working', run: null })),
  },
}));

vi.mock('../../../lib/api', () => ({
  api: {
    getVulnerabilityDetail: vi.fn(),
    getFixChanges: mocks.getFixChanges,
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

// The PR card message — where the loader discovers the fixId it feeds to
// getFixChanges.
function prResultMessage(fixId: string): any {
  return {
    id: 'm-pr',
    role: 'assistant',
    content: 'Opened a pull request',
    metadata: {
      parts: [
        {
          type: 'tool-result',
          toolCallId: 'call-1',
          toolName: 'open_pull_request',
          result: { fixId },
        },
      ],
    },
  };
}

function packageJsonPatch(version: string): string {
  return `@@ -1,5 +1,5 @@\n {\n   "dependencies": {\n-    "simple-git": "3.16.0"\n+    "simple-git": "${version}"\n   }\n }`;
}

function netChanges(version: string) {
  return {
    prNumber: 7,
    prUrl: 'https://github.com/o/r/pull/7',
    files: [
      // The lockfile rides along on every manifest edit — the tab must hide it.
      { path: 'package-lock.json', status: 'modified', additions: 120, deletions: 118, patch: null, lockfile: true },
      { path: 'package.json', status: 'modified', additions: 1, deletions: 1, patch: packageJsonPatch(version), lockfile: false },
    ],
  };
}

async function openChangesTab() {
  render(<TaskDetailPanel task={task} open onClose={vi.fn()} onOpen={vi.fn()} />);
  await flushAsync();
  fireEvent.click(screen.getByRole('button', { name: 'Changes' }));
}

describe('TaskDetailPanel — Changes tab net view + live refresh + persistent toggle', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.realtimeCallbacks.length = 0;
    mocks.getMessages.mockImplementation(async () => [
      editStepMessage('src/one.ts'),
      prResultMessage('fix-1'),
    ]);
    mocks.getFixChanges.mockImplementation(async () => ({ prNumber: null, prUrl: null, files: [] }));
  });

  afterEach(() => cleanup());

  it('renders the NET view once a PR exists: one card per authored file, lockfile hidden, stage diffs suppressed', async () => {
    mocks.getFixChanges.mockImplementation(async () => netChanges('3.30.0'));
    await openChangesTab();

    // One card per file — the whole point: no per-stage duplicates.
    expect(await screen.findByText('package.json')).toBeInTheDocument();
    expect(screen.getAllByText('package.json')).toHaveLength(1);
    expect(mocks.getFixChanges).toHaveBeenCalledWith('fix-1');

    // The manifest's diff body renders (syntax highlighting splits tokens
    // across spans, so assert on concatenated text).
    expect(document.body.textContent).toContain('3.30.0');

    // The regenerated lockfile is machine fallout, not a change Aegis
    // authored — no card, no counts.
    expect(screen.queryByText('package-lock.json')).toBeNull();
    expect(screen.queryByText('+120')).toBeNull();
    expect(screen.queryByText('diff not shown')).toBeNull();

    // The message-derived stage diff must NOT render alongside the net view.
    expect(screen.queryByText('src/one.ts')).toBeNull();
  });

  it('a lockfile-ONLY PR (pure transitive bump) still shows the lockfile summary row', async () => {
    mocks.getFixChanges.mockImplementation(async () => ({
      prNumber: 7,
      prUrl: 'https://github.com/o/r/pull/7',
      files: [
        { path: 'package-lock.json', status: 'modified', additions: 12, deletions: 9, patch: null, lockfile: true },
      ],
    }));
    await openChangesTab();

    // Hiding it here would leave the tab empty while the PR has real content.
    expect(await screen.findByText('package-lock.json')).toBeInTheDocument();
    expect(screen.getByText('+12')).toBeInTheDocument();
    expect(screen.getByText('−9')).toBeInTheDocument();
    expect(screen.getByText('diff not shown')).toBeInTheDocument();
    expect(screen.queryByText(/No changes yet/)).toBeNull();
  });

  it('falls back to the chronological stage diffs while no PR exists (prNumber: null)', async () => {
    await openChangesTab();

    expect(await screen.findByText('src/one.ts')).toBeInTheDocument();
    expect(mocks.getFixChanges).toHaveBeenCalledWith('fix-1');
    expect(screen.queryByText('diff not shown')).toBeNull();
    expect(screen.queryByText(/No changes yet/)).toBeNull();
  });

  it('refetches on a realtime insert: an amended file replaces its patch in place — still one card', async () => {
    mocks.getFixChanges.mockImplementation(async () => netChanges('3.30.0'));
    await openChangesTab();
    expect(await screen.findByText('package.json')).toBeInTheDocument();
    expect(document.body.textContent).toContain('3.30.0');
    expect(mocks.realtimeCallbacks.length).toBeGreaterThan(0);

    // The amend pushes a new commit → the PR's net patch for package.json
    // changes; a message INSERT lands on the thread.
    mocks.getFixChanges.mockImplementation(async () => netChanges('3.36.0'));
    mocks.realtimeCallbacks.forEach((cb) => cb());

    // After the 300ms trailing debounce the refetch replaces the patch in
    // place — the updated diff, still exactly one package.json card, and no
    // empty-state flash.
    await flushAsync(350);
    expect(document.body.textContent).toContain('3.36.0');
    expect(document.body.textContent).not.toContain('3.30.0');
    expect(screen.getAllByText('package.json')).toHaveLength(1);
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
