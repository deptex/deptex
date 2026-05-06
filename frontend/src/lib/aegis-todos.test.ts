import { describe, it, expect } from 'vitest';
import type { UIMessage } from 'ai';
import { deriveTodos } from './aegis-todos';

function msg(parts: any[]): UIMessage {
  return { id: 'm1', role: 'assistant', parts } as unknown as UIMessage;
}

describe('deriveTodos', () => {
  it('returns [] when message has no parts', () => {
    expect(deriveTodos(msg([]))).toEqual([]);
  });

  it('returns the todos from a single set_todos part', () => {
    const todos = deriveTodos(
      msg([
        { type: 'text', text: 'Working on it.' },
        {
          type: 'tool-call',
          toolName: 'set_todos',
          args: {
            todos: [
              { title: 'Revise plan A', status: 'in_progress' },
              { title: 'Revise plan B' },
            ],
          },
        },
      ]),
    );
    expect(todos).toEqual([
      { title: 'Revise plan A', status: 'in_progress' },
      { title: 'Revise plan B', status: 'pending' },
    ]);
  });

  it('returns the LATEST set_todos when two consecutive calls exist', () => {
    const todos = deriveTodos(
      msg([
        {
          type: 'tool-call',
          toolName: 'set_todos',
          args: {
            todos: [
              { title: 'A', status: 'in_progress' },
              { title: 'B', status: 'pending' },
            ],
          },
        },
        {
          type: 'tool-call',
          toolName: 'set_todos',
          args: {
            todos: [
              { title: 'A', status: 'done' },
              { title: 'B', status: 'in_progress' },
            ],
          },
        },
      ]),
    );
    expect(todos).toEqual([
      { title: 'A', status: 'done' },
      { title: 'B', status: 'in_progress' },
    ]);
  });

  it('returns [] when args.todos is missing or malformed', () => {
    expect(
      deriveTodos(
        msg([{ type: 'tool-call', toolName: 'set_todos', args: { todos: undefined } }]),
      ),
    ).toEqual([]);
    expect(
      deriveTodos(
        msg([{ type: 'tool-call', toolName: 'set_todos', args: {} }]),
      ),
    ).toEqual([]);
    // Items missing `title` are filtered out, not crash-rendered.
    const filtered = deriveTodos(
      msg([
        {
          type: 'tool-call',
          toolName: 'set_todos',
          args: {
            todos: [
              { title: 'kept' },
              { status: 'pending' }, // no title — filtered
              { title: '', status: 'pending' }, // empty title — filtered
            ],
          },
        },
      ]),
    );
    expect(filtered).toEqual([{ title: 'kept', status: 'pending' }]);
  });
});
