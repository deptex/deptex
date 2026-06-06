import { createMockSupabase, TableRegistry, RpcRegistry } from './supabase-builder';

const registry: TableRegistry = {};
const rpcRegistry: RpcRegistry = {};
export const { supabase, queryBuilder } = createMockSupabase(registry, rpcRegistry);

/** Set the response for a Supabase RPC call by function name. */
export function setRpcResponse(name: string, value: { data: any; error: any }) {
  rpcRegistry[name] = value;
}

/**
 * Queue an additional response for an RPC by name. Responses are consumed in FIFO
 * order; the last one is reused once the queue is exhausted. Mirrors pushTableResponse,
 * for tests that need successive RPC calls to return different values (e.g. retry paths).
 */
export function pushRpcResponse(name: string, value: { data: any; error: any }) {
  const existing = rpcRegistry[name];
  if (existing === undefined) {
    rpcRegistry[name] = value;
  } else {
    const arr = Array.isArray(existing) ? existing : [existing];
    rpcRegistry[name] = [...arr, value];
  }
}

export function clearRpcRegistry() {
  for (const k of Object.keys(rpcRegistry)) delete rpcRegistry[k];
}

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
