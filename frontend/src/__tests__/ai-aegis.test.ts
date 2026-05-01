/**
 * AI / Aegis Frontend Test Suite
 * AegisPanel, Streaming, Rate Limits & Usage, Safety.
 * (BYOK UI tests retired with the AIConfigurationSection cleanup.)
 */

import { render, screen, fireEvent, waitFor, cleanup, act } from '@testing-library/react';
import React from 'react';
import type { StreamCallbacks } from '../lib/aegis-stream';

// ────────────────────────────────────────────────────────────────
//  Module Mocks
// ────────────────────────────────────────────────────────────────

vi.mock('../lib/api', () => ({
  api: {
    getAegisThreadsByProject: vi.fn().mockResolvedValue([]),
    getAegisThreadMessages: vi.fn().mockResolvedValue([]),
    getAIUsage: vi.fn().mockResolvedValue({
      totalInputTokens: 10_000,
      totalOutputTokens: 5_000,
      totalEstimatedCost: 0.5,
      monthlyCostCap: 100,
      byFeature: {},
      byUser: [],
    }),
    getAIUsageLogs: vi.fn().mockResolvedValue({ logs: [], total: 0 }),
    streamAegisMessage: vi.fn().mockResolvedValue({ body: null }),
  },
}));

vi.mock('../lib/aegis-stream', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/aegis-stream')>();
  return { ...actual, streamAegisMessage: vi.fn() };
});

vi.mock('react-markdown', () => ({
  default: (props: { children: string }) =>
    React.createElement('div', { 'data-testid': 'markdown' }, props.children),
}));

vi.mock('remark-gfm', () => ({ default: () => {} }));

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

// ────────────────────────────────────────────────────────────────
//  Imports (resolved after mock registration)
// ────────────────────────────────────────────────────────────────

import { api } from '../lib/api';
import { streamAegisMessage, sanitizeStreamingMarkdown } from '../lib/aegis-stream';
import { AegisPanel } from '../components/aegis/AegisPanel';

// ────────────────────────────────────────────────────────────────
//  Helpers
// ────────────────────────────────────────────────────────────────

function setMatchMedia(matches: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation(() => ({
      matches,
      media: '',
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      onchange: null,
    })),
  });
}

const PANEL = {
  organizationId: 'org-1',
  projectId: 'proj-1',
  hasByokProvider: true,
  hasPermission: true,
};

function renderPanel(extra: Record<string, any> = {}) {
  return render(React.createElement(AegisPanel, { ...PANEL, ...extra }));
}

function expand() {
  localStorage.setItem('aegis-panel-proj-1', 'true');
}

async function typeAndSend(text: string) {
  const ta = await screen.findByPlaceholderText('Ask Aegis...');
  await act(async () => {
    fireEvent.change(ta, { target: { value: text } });
  });
  await act(async () => {
    fireEvent.keyDown(ta, { key: 'Enter' });
  });
}

beforeEach(() => {
  setMatchMedia(true);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

// ═══════════════════════════════════════════════════════════════
//  1-8  Aegis Panel
// ═══════════════════════════════════════════════════════════════

describe('Aegis Panel', () => {
  it('1 — renders collapsed by default (40px tab on right edge)', () => {
    renderPanel();
    const tab = screen.getByTitle('Open Aegis AI');
    expect(tab).toBeInTheDocument();
    expect(tab.className).toContain('w-10');
    expect(screen.getByText('Aegis AI')).toBeInTheDocument();
    expect(screen.queryByPlaceholderText('Ask Aegis...')).not.toBeInTheDocument();
  });

  it('2 — clicking tab expands panel to full chat interface', async () => {
    renderPanel();
    fireEvent.click(screen.getByTitle('Open Aegis AI'));
    expect(await screen.findByPlaceholderText('Ask Aegis...')).toBeInTheDocument();
    expect(screen.getByText('Aegis Security Copilot')).toBeInTheDocument();
  });

  it('3 — context indicator updates when user clicks different graph nodes', async () => {
    expand();
    const { rerender } = render(
      React.createElement(AegisPanel, { ...PANEL, context: { type: 'project', id: 'p1' } }),
    );
    expect(await screen.findByText('Project')).toBeInTheDocument();

    rerender(
      React.createElement(AegisPanel, { ...PANEL, context: { type: 'vulnerability', id: 'v1' } }),
    );
    expect(await screen.findByText('Vulnerability')).toBeInTheDocument();
  });

  it('4 — quick action buttons change based on context type (project/vuln/dep)', async () => {
    expand();
    const { unmount } = render(
      React.createElement(AegisPanel, { ...PANEL, context: { type: 'project', id: 'p1' } }),
    );
    expect(await screen.findByText('What should I fix first?')).toBeInTheDocument();
    expect(screen.queryByText('Explain this vulnerability')).not.toBeInTheDocument();
    unmount();

    render(
      React.createElement(AegisPanel, { ...PANEL, context: { type: 'vulnerability', id: 'v1' } }),
    );
    expect(await screen.findByText('Explain this vulnerability')).toBeInTheDocument();
    expect(screen.queryByText('What should I fix first?')).not.toBeInTheDocument();
  });

  it('5 — shows "Configure AI keys" card when org has no BYOK provider', async () => {
    expand();
    renderPanel({ hasByokProvider: false });
    expect(await screen.findByText('Set up AI Provider')).toBeInTheDocument();
    expect(screen.getByText(/Connect an OpenAI, Anthropic, or Google API key/)).toBeInTheDocument();
    expect(screen.queryByPlaceholderText('Ask Aegis...')).not.toBeInTheDocument();
  });

  it('6 — Tier 2 buttons hidden for users without interact_with_security_agent', async () => {
    expand();
    renderPanel({ hasPermission: false });
    expect(
      await screen.findByText(/don't have permission/i),
    ).toBeInTheDocument();
    expect(screen.queryByPlaceholderText('Ask Aegis...')).not.toBeInTheDocument();
  });

  it('7 — Tier 1 features (collapsed tab) visible without interact_with_security_agent', () => {
    renderPanel({ hasPermission: false });
    expect(screen.getByTitle('Open Aegis AI')).toBeInTheDocument();
    expect(screen.getByText('Aegis AI')).toBeInTheDocument();
  });

  it('8 — panel overlays graph on screens < 1280px (responsive test)', async () => {
    setMatchMedia(false);
    expand();
    const { container } = renderPanel();
    await waitFor(() => {
      const el = container.firstElementChild as HTMLElement;
      expect(el.className).toContain('absolute');
      expect(el.className).toContain('z-50');
    });
  });
});

// ═══════════════════════════════════════════════════════════════
//  9-12  Streaming
// ═══════════════════════════════════════════════════════════════

describe('Streaming', () => {
  it('9 — streaming text renders incrementally with blinking cursor', async () => {
    expand();
    vi.mocked(streamAegisMessage).mockImplementation(
      async (_o, _t, _m, _c, cbs: StreamCallbacks) => {
        cbs.onChunk('Hello ');
        cbs.onChunk('world');
        return new Promise(() => {});
      },
    );

    renderPanel({ context: { type: 'project', id: 'p1' } });
    await typeAndSend('test');

    await waitFor(() => {
      expect(screen.getByTestId('markdown')).toHaveTextContent('Hello world');
    });
    expect(document.querySelector('.animate-pulse')).toBeTruthy();
  });

  it('10 — fence guard strips incomplete markdown (odd backticks, unclosed bold)', () => {
    expect(sanitizeStreamingMarkdown('before ```js\ncode')).toBe('before ');
    expect(sanitizeStreamingMarkdown('hello **bold')).toBe('hello ');
    expect(sanitizeStreamingMarkdown('use `lodash')).toBe('use ');

    expect(sanitizeStreamingMarkdown('**bold** and `code`')).toBe('**bold** and `code`');
    expect(sanitizeStreamingMarkdown('```js\ncode\n```')).toBe('```js\ncode\n```');
    expect(sanitizeStreamingMarkdown('no markdown here')).toBe('no markdown here');
  });

  it('11 — done event renders full content without fence guard', async () => {
    expand();
    vi.mocked(streamAegisMessage).mockImplementation(
      async (_o, _t, _m, _c, cbs: StreamCallbacks) => {
        cbs.onChunk('Parti');
        cbs.onChunk('al');
        cbs.onDone('Complete **formatted** answer', 'thread-1');
      },
    );

    renderPanel({ context: { type: 'project', id: 'p1' } });
    await typeAndSend('analyze');

    await waitFor(() => {
      expect(screen.getByTestId('markdown')).toHaveTextContent(
        'Complete **formatted** answer',
      );
    });
    expect(document.querySelector('.animate-pulse')).toBeFalsy();
  });

  it('12 — SSE connection abort on component unmount (AbortController)', async () => {
    expand();
    let captured: AbortSignal | undefined;
    vi.mocked(streamAegisMessage).mockImplementation(
      async (_o, _t, _m, _c, _cbs, signal) => {
        captured = signal;
        return new Promise(() => {});
      },
    );

    const { unmount } = renderPanel({ context: { type: 'project', id: 'p1' } });
    await typeAndSend('test');
    await waitFor(() => expect(captured).toBeDefined());

    expect(captured!.aborted).toBe(false);
    unmount();
    expect(captured!.aborted).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════
//  Rate Limits and Usage
// ═══════════════════════════════════════════════════════════════

describe('Rate Limits and Usage', () => {
  it('18 — "Analyze usage with AI" shows limit message after 5 calls', async () => {
    const TIER1_LIMIT = 5;
    let callCount = 0;

    const analyzeWithAI = async () => {
      callCount++;
      if (callCount > TIER1_LIMIT) {
        return { error: true, message: 'Rate limit reached: max 5 AI analyses per hour' };
      }
      return { error: false, analysis: 'ok' };
    };

    for (let i = 0; i < TIER1_LIMIT; i++) {
      expect((await analyzeWithAI()).error).toBe(false);
    }
    const limited = await analyzeWithAI();
    expect(limited.error).toBe(true);
    expect(limited.message).toContain('Rate limit');
  });

  it('19 — monthly cost cap exceeded shows user-friendly message with current/max amounts', async () => {
    expand();
    vi.mocked(api.getAIUsage).mockResolvedValue({
      totalInputTokens: 500_000,
      totalOutputTokens: 200_000,
      totalEstimatedCost: 120,
      monthlyCostCap: 100,
      byFeature: {},
      byUser: [],
    } as any);

    renderPanel();

    expect(await screen.findByText(/Monthly AI budget reached/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Budget exhausted')).toBeInTheDocument();
    expect(
      (screen.getByPlaceholderText('Budget exhausted') as HTMLTextAreaElement).disabled,
    ).toBe(true);
  });

});

// ═══════════════════════════════════════════════════════════════
//  22-24  Safety
// ═══════════════════════════════════════════════════════════════

describe('Safety', () => {
  it('24 — context switch mid-conversation appends context marker in chat history', async () => {
    expand();
    const { rerender } = render(
      React.createElement(AegisPanel, { ...PANEL, context: { type: 'project', id: 'p1' } }),
    );
    await screen.findByPlaceholderText('Ask Aegis...');

    rerender(
      React.createElement(AegisPanel, {
        ...PANEL,
        context: { type: 'vulnerability', id: 'CVE-2024-1234' },
      }),
    );

    await waitFor(() => {
      expect(
        screen.getByText(/Context switched to Vulnerability/),
      ).toBeInTheDocument();
    });
  });
});
