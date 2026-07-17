import { describe, it, expect } from 'vitest';
import { derivePlanTodoRows } from '../FixPanel';

// The fix-detail "To-dos" section derives its rows from the plan. Regression
// guard: an agent-strategy plan has no `fileChanges` (and often no `todos`),
// and the unguarded `plan.fileChanges.map` black-screened the whole app via the
// route error boundary. These pin that BOTH fields are optional at runtime.

describe('derivePlanTodoRows', () => {
  it('uses AI todos when present (mono: false)', () => {
    const rows = derivePlanTodoRows({
      todos: [{ title: 'Bump set-value', detail: 'to 4.1.0' }, { title: 'Verify' }],
    });
    expect(rows).toEqual([
      { primary: 'Bump set-value', secondary: 'to 4.1.0', mono: false },
      { primary: 'Verify', secondary: undefined, mono: false },
    ]);
  });

  it('falls back to fileChanges when there are no todos (mono: true)', () => {
    const rows = derivePlanTodoRows({
      todos: [],
      fileChanges: [{ path: 'package.json', action: 'modify', description: 'add override' }],
    });
    expect(rows).toEqual([{ primary: 'package.json', secondary: 'add override', mono: true }]);
  });

  it('returns an empty list — never throws — when fileChanges is undefined (agent plan)', () => {
    // The exact crash shape: no todos, no fileChanges.
    expect(() => derivePlanTodoRows({} as any)).not.toThrow();
    expect(derivePlanTodoRows({} as any)).toEqual([]);
    expect(derivePlanTodoRows({ todos: [] } as any)).toEqual([]);
  });
});
