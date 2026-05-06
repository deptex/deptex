/**
 * MessageBubble — regression coverage around the request_fix /
 * approve_fix special-cases plus the new set_todos suppression and
 * empty-bubble guard introduced for the chat-todos strip.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { UIMessage } from 'ai';
import React from 'react';

vi.mock('../components/aegis/MarkdownRenderer', () => ({
  MarkdownRenderer: ({ content }: { content: string }) =>
    React.createElement('div', { 'data-testid': 'md' }, content),
}));

vi.mock('../components/aegis/PlanCard', () => ({
  PlanCard: ({ fixId }: { fixId: string }) =>
    React.createElement('div', { 'data-testid': 'plan-card' }, fixId),
  PlanCardSkeleton: () => React.createElement('div', { 'data-testid': 'plan-skel' }),
}));

vi.mock('../components/aegis/FixStatusCard', () => ({
  FixStatusCard: ({ fixId }: { fixId: string }) =>
    React.createElement('div', { 'data-testid': 'fix-status' }, fixId),
}));

vi.mock('../components/aegis/ToolCallCard', () => ({
  ToolCallGroup: ({ tools }: { tools: Array<{ toolName: string }> }) =>
    React.createElement(
      'div',
      { 'data-testid': 'tool-group' },
      tools.map((t) => t.toolName).join(','),
    ),
}));

import { MessageBubble } from '../components/aegis/MessageBubble';

function asMessage(parts: any[]): UIMessage {
  return { id: 'm', role: 'assistant', parts } as unknown as UIMessage;
}

describe('MessageBubble', () => {
  it('renders PlanCardSkeleton while request_fix is in flight', () => {
    render(
      <MessageBubble
        message={asMessage([
          {
            type: 'tool-call',
            toolName: 'request_fix',
            state: 'input-streaming',
          },
        ])}
      />,
    );
    expect(screen.getByTestId('plan-skel')).toBeInTheDocument();
    expect(screen.queryByTestId('plan-card')).toBeNull();
  });

  it('renders PlanCard once request_fix resolves with a fixId', () => {
    render(
      <MessageBubble
        message={asMessage([
          {
            type: 'tool-call',
            toolName: 'request_fix',
            state: 'output-available',
            output: { fixId: 'fix-1' },
          },
        ])}
      />,
    );
    expect(screen.getByTestId('plan-card')).toHaveTextContent('fix-1');
    expect(screen.queryByTestId('plan-skel')).toBeNull();
  });

  it('falls through to ToolCallGroup when request_fix returns output.error', () => {
    render(
      <MessageBubble
        message={asMessage([
          {
            type: 'tool-call',
            toolName: 'request_fix',
            state: 'output-available',
            output: { error: 'no github installation' },
          },
        ])}
      />,
    );
    expect(screen.queryByTestId('plan-skel')).toBeNull();
    expect(screen.queryByTestId('plan-card')).toBeNull();
    expect(screen.getByTestId('tool-group')).toHaveTextContent('request_fix');
  });

  it('renders FixStatusCard when approve_fix resolves', () => {
    render(
      <MessageBubble
        message={asMessage([
          {
            type: 'tool-call',
            toolName: 'approve_fix',
            state: 'output-available',
            output: { fixId: 'fix-2' },
          },
        ])}
      />,
    );
    expect(screen.getByTestId('fix-status')).toHaveTextContent('fix-2');
  });

  it('returns null when only set_todos parts exist (empty-bubble guard)', () => {
    const { container } = render(
      <MessageBubble
        message={asMessage([
          {
            type: 'tool-call',
            toolName: 'set_todos',
            args: { todos: [{ title: 'A' }, { title: 'B' }] },
          },
          {
            type: 'tool-call',
            toolName: 'set_todos',
            args: { todos: [{ title: 'A', status: 'done' }, { title: 'B' }] },
          },
        ])}
      />,
    );
    // Empty-bubble guard: no padded wrapper, no markdown, no tool group.
    expect(container.firstChild).toBeNull();
  });

  it('text + set_todos + request_fix(error) renders text + error pill, no set_todos chrome', () => {
    render(
      <MessageBubble
        message={asMessage([
          { type: 'text', text: 'Looking into it.' },
          {
            type: 'tool-call',
            toolName: 'set_todos',
            args: { todos: [{ title: 'A' }, { title: 'B' }] },
          },
          {
            type: 'tool-call',
            toolName: 'request_fix',
            state: 'output-available',
            output: { error: 'missing handle' },
          },
        ])}
      />,
    );
    expect(screen.getByTestId('md')).toHaveTextContent('Looking into it.');
    const group = screen.getByTestId('tool-group');
    expect(group).toHaveTextContent('request_fix');
    expect(group.textContent).not.toContain('set_todos');
  });
});
