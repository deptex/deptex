import { describe, it, expect } from 'vitest';
import type { UIMessage } from 'ai';
import { deriveTodos } from '../lib/aegis-todos';

// The same set_todos call surfaces in three real shapes depending on where
// in its lifecycle we read it from. The derivation MUST yield the same
// Todo[] in all three or the strip will silently render nothing on one
// of the paths. This is the regression that the previous draft missed.

const expectedTodos = [
  { title: 'Revise plan A', status: 'in_progress' as const },
  { title: 'Revise plan B', status: 'pending' as const },
];

const args = {
  todos: [
    { title: 'Revise plan A', status: 'in_progress' },
    { title: 'Revise plan B', status: 'pending' },
  ],
};

function msg(parts: any[]): UIMessage {
  return { id: 'm1', role: 'assistant', parts } as unknown as UIMessage;
}

describe('deriveTodos — three-shape round-trip', () => {
  it('handles the live AI SDK stream shape (tool-set_todos / input)', () => {
    expect(
      deriveTodos(
        msg([
          { type: 'tool-set_todos', state: 'input-available', input: args, toolCallId: 'c1' },
        ]),
      ),
    ).toEqual(expectedTodos);
  });

  it('handles the persisted shape (tool-call / args)', () => {
    expect(
      deriveTodos(
        msg([{ type: 'tool-call', toolName: 'set_todos', args, toolCallId: 'c1' }]),
      ),
    ).toEqual(expectedTodos);
  });

  it('handles the rehydrated shape (dynamic-tool / input)', () => {
    expect(
      deriveTodos(
        msg([
          {
            type: 'dynamic-tool',
            toolName: 'set_todos',
            state: 'output-available',
            input: args,
            output: { ok: true },
            toolCallId: 'c1',
          },
        ]),
      ),
    ).toEqual(expectedTodos);
  });
});
