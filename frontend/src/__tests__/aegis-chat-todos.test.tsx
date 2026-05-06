/**
 * ChatTodos — visibility matrix coverage. The strip's state machine is the
 * load-bearing UX of the chat-todos feature, so all four cells of the
 * (streaming × any-non-terminal) matrix get a test.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import type { UIMessage } from 'ai';
import { ChatTodos } from '../components/aegis/ChatTodos';

afterEach(() => {
  vi.useRealTimers();
});

function assistantMsg(id: string, todos: Array<{ title: string; status?: string }>): UIMessage {
  return {
    id,
    role: 'assistant',
    parts: [
      { type: 'tool-call', toolName: 'set_todos', args: { todos } },
    ],
  } as unknown as UIMessage;
}

describe('ChatTodos', () => {
  it('streaming + non-terminal → renders Loader2 on in_progress row', () => {
    render(
      <ChatTodos
        streaming
        messages={[
          assistantMsg('a1', [
            { title: 'Revise plan A', status: 'in_progress' },
            { title: 'Revise plan B', status: 'pending' },
          ]),
        ]}
      />,
    );
    expect(screen.getByText('Revise plan A')).toBeInTheDocument();
    expect(screen.getByText('Revise plan B')).toBeInTheDocument();
    expect(screen.getByText('Plan 0/2')).toBeInTheDocument();
    expect(screen.getByLabelText('In progress')).toBeInTheDocument();
    expect(screen.getByLabelText('Pending')).toBeInTheDocument();
  });

  it('streaming + all terminal → shows Done pill, then fades + unmounts after the hold', () => {
    vi.useFakeTimers();
    const message = assistantMsg('a2', [
      { title: 'Revise plan A', status: 'done' },
      { title: 'Revise plan B', status: 'done' },
    ]);
    render(<ChatTodos streaming messages={[message]} />);

    expect(screen.getByText('Done — 2/2')).toBeInTheDocument();
    expect(screen.queryByLabelText('Dismiss plan')).toBeNull();

    // 1500ms hold → fade phase begins (still in DOM, opacity-0)
    act(() => {
      vi.advanceTimersByTime(1500);
    });
    const wrapper = screen.getByRole('status');
    expect(wrapper.className).toMatch(/opacity-0/);

    // +300ms transition → unmount
    act(() => {
      vi.advanceTimersByTime(300);
    });
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('not streaming + non-terminal → stalled: Pause icon + Dismiss-X + "Stream ended"', () => {
    render(
      <ChatTodos
        streaming={false}
        messages={[
          assistantMsg('a3', [
            { title: 'Revise plan A', status: 'in_progress' },
            { title: 'Revise plan B', status: 'pending' },
          ]),
        ]}
      />,
    );
    expect(screen.getByText('Plan 0/2')).toBeInTheDocument();
    expect(screen.getByText(/Stream ended/)).toBeInTheDocument();
    expect(screen.getByLabelText('Dismiss plan')).toBeInTheDocument();
    // In stalled mode, in_progress and pending both render the Pause icon.
    expect(screen.getAllByLabelText('Paused').length).toBe(2);
    expect(screen.queryByLabelText('In progress')).toBeNull();
  });

  it('not streaming + all terminal → Done pill, no Dismiss-X, fades after 1.5s', () => {
    vi.useFakeTimers();
    render(
      <ChatTodos
        streaming={false}
        messages={[
          assistantMsg('a4', [
            { title: 'A', status: 'done' },
            { title: 'B', status: 'done' },
          ]),
        ]}
      />,
    );
    expect(screen.getByText('Done — 2/2')).toBeInTheDocument();
    expect(screen.queryByLabelText('Dismiss plan')).toBeNull();
    act(() => {
      vi.advanceTimersByTime(1800);
    });
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('renders nothing when there is no assistant message', () => {
    const { container } = render(<ChatTodos streaming messages={[]} />);
    expect(container.firstChild).toBeNull();
  });

  it('renders nothing when the latest assistant message has no set_todos parts', () => {
    const { container } = render(
      <ChatTodos
        streaming
        messages={[
          {
            id: 'a5',
            role: 'assistant',
            parts: [{ type: 'text', text: 'Hello.' }],
          } as unknown as UIMessage,
        ]}
      />,
    );
    expect(container.firstChild).toBeNull();
  });
});
