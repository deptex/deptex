import { createMockSupabase, TableRegistry } from './supabase';

const registry: TableRegistry = {};
export const { supabase, queryBuilder } = createMockSupabase(registry);

/** Replace (overwrite) the response for a given table+method. */
export function setTableResponse(
  table: string,
  method: 'single' | 'then' | 'maybeSingle',
  value: { data: any; error: any }
) {
  if (!registry[table]) registry[table] = {};
  registry[table][method] = value;
}

/**
 * Queue an additional response for `single` on a table.
 * Responses are consumed in FIFO order; the last one is reused for any
 * subsequent calls once the queue is exhausted.
 */
export function pushTableResponse(
  table: string,
  value: { data: any; error: any }
) {
  if (!registry[table]) registry[table] = {};
  const existing = registry[table].single;
  if (existing === undefined) {
    registry[table].single = value;
  } else {
    const arr = Array.isArray(existing) ? existing : [existing];
    registry[table].single = [...arr, value];
  }
}

export function clearTableRegistry() {
  for (const k of Object.keys(registry)) delete registry[k];
}
