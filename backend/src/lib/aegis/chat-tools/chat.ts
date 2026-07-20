import { jsonSchema } from 'ai';
import type { AegisToolEntry } from '../tool-types';

type Todo = {
  title: string;
  status?: 'pending' | 'in_progress' | 'done';
};

// Single tool, full-replace semantics. Each call replaces the active list
// entirely; to declare progress the agent re-calls set_todos with the same
// titles plus updated status values. No ids — array order is identity within
// a turn. The frontend derivation reads the most-recent set_todos part and
// renders the strip; UI suppression in MessageBubble keeps the call out of
// the chat scroll. audit:false skips the aegis_tool_executions write so this
// pure-UI bookkeeping doesn't pollute telemetry dashboards.
const setTodos: AegisToolEntry<{ todos: Todo[] }, { ok: true }> = {
  name: 'set_todos',
  description:
    "Declare or update the user-visible plan for THIS turn when it spans 2-6 discrete workstreams. Pass the FULL current list every call; the most recent call replaces the previous one. To mark progress, re-call set_todos with the same titles plus updated status values ('pending' -> 'in_progress' -> 'done'). Use this only when the user requested ≥2 user-visible workstreams of ≥30s each (e.g. 'revise both plans', 'fix all 3 secrets'); do NOT use it to break a single deliverable into tool-call subroutines. The strip is canonical progress UI — do NOT also narrate 'now I'll do step 1' in prose.",
  danger: 'safe',
  audit: false,
  inputSchema: jsonSchema({
    type: 'object',
    required: ['todos'],
    additionalProperties: false,
    properties: {
      todos: {
        type: 'array',
        minItems: 2,
        maxItems: 6,
        items: {
          type: 'object',
          required: ['title'],
          additionalProperties: false,
          properties: {
            title: {
              type: 'string',
              minLength: 4,
              maxLength: 120,
              description: 'One-line user-visible title for this workstream.',
            },
            status: {
              type: 'string',
              enum: ['pending', 'in_progress', 'done'],
              default: 'pending',
              description:
                'Current state. Omit on initial call (defaults to pending). Re-call set_todos with updated status values to declare progress.',
            },
          },
        },
      },
    },
  }),
  execute: async (_input, ctx) => {
    // Flag is read by request_fix / revise_fix to enforce "must call set_todos
    // before fanning out to ≥2 user-visible workstreams in a single turn."
    // Setting unconditionally is fine — the schema's minItems:2 already gates
    // out trivial single-step lists.
    ctx.turnState.setTodosCalled = true;
    return { ok: true };
  },
};

export const chatTools: AegisToolEntry[] = [setTodos];
