import type { UIMessage } from 'ai';
import { isToolPart, toolNameFor, toolArgs } from './aegis-parts';

export type TodoStatus = 'pending' | 'in_progress' | 'done';
export type Todo = { title: string; status: TodoStatus };

// Single-tool full-replace semantics: each set_todos call replaces the active
// list. To mark progress the agent re-emits set_todos with the same titles
// plus updated status values. So derivation is just "walk parts backward,
// take the most recent set_todos, return its todos".
export function deriveTodos(message: UIMessage): Todo[] {
  const parts = (message as any).parts ?? [];
  for (let i = parts.length - 1; i >= 0; i--) {
    const part = parts[i];
    if (isToolPart(part) && toolNameFor(part) === 'set_todos') {
      const args = toolArgs(part);
      const todos = args?.todos;
      if (!Array.isArray(todos)) return [];
      return todos
        .filter((t: any) => typeof t?.title === 'string' && t.title.length > 0)
        .map((t: any) => ({
          title: t.title,
          status: (t.status as TodoStatus) ?? 'pending',
        }));
    }
  }
  return [];
}
