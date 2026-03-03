import { createMockSupabase, TableRegistry } from './supabase';

const registry: TableRegistry = {};
export const { supabase, queryBuilder } = createMockSupabase(registry);

export function setTableResponse(
  table: string,
  method: 'single' | 'then' | 'maybeSingle',
  value: { data: any; error: any }
) {
  if (!registry[table]) registry[table] = {};
  registry[table][method] = value;
}

export function clearTableRegistry() {
  for (const k of Object.keys(registry)) delete registry[k];
}
