/**
 * Thin wrapper over `executePolicyFunction` (the isolated-vm engine in
 * `policy-engine.ts`) that adds:
 *   - per-contract return-shape validation
 *   - error normalization to a 4-stage taxonomy (parse/run/returnShape/returnSize)
 *   - a structured one-line log per call for diagnostics
 *
 * NOT a fresh isolate harness — all sandboxing happens inside `executePolicyFunction`.
 */

import { executePolicyFunction } from '../policy-engine';
import type { FlowCodeContract } from './contracts';

export type FlowCodeErrorStage = 'parse' | 'run' | 'returnShape' | 'returnSize';

export interface FlowCodeError {
  stage: FlowCodeErrorStage;
  message: string;
  /** 1-indexed source line if extractable from the underlying error. */
  line?: number;
}

export type FlowCodeResult =
  | { ok: true; value: unknown; durationMs: number }
  | { ok: false; error: FlowCodeError; durationMs: number };

export interface RunFlowCodeOpts {
  contract: FlowCodeContract;
  /** The user's body (without the `function name() { ... }` wrapper). */
  code: string;
  context: Record<string, unknown>;
  organizationId?: string;
  /** Defaults to the engine's 30s. Validation calls may pass 5s. */
  timeoutMs?: number;
  source?: 'editor_test' | 'save_validation' | 'runtime' | 'other';
}

export async function runFlowCode(opts: RunFlowCodeOpts): Promise<FlowCodeResult> {
  const { contract, code, context, organizationId, timeoutMs, source = 'other' } = opts;
  const wrapped = wrapBodyAsFunction(code, contract);
  const start = Date.now();

  let value: unknown;
  try {
    value = await executePolicyFunction({
      code: wrapped,
      functionName: contract.functionName,
      context,
      organizationId,
      codeType: `flow_${contract.functionName}`,
      timeoutMs,
    });
  } catch (err) {
    const durationMs = Date.now() - start;
    const error = normalizeError(err);
    logRun({ contract: contract.functionName, organizationId, durationMs, ok: false, errorStage: error.stage, source });
    return { ok: false, error, durationMs };
  }

  const check = contract.returnTypeCheck(value);
  if (check !== true) {
    const durationMs = Date.now() - start;
    logRun({ contract: contract.functionName, organizationId, durationMs, ok: false, errorStage: 'returnShape', source });
    return { ok: false, error: { stage: 'returnShape', message: check }, durationMs };
  }

  const durationMs = Date.now() - start;
  logRun({ contract: contract.functionName, organizationId, durationMs, ok: true, source });
  return { ok: true, value, durationMs };
}

/**
 * Wrap a raw body string as `function <name>(<param>) { <body> }`. Bodies that
 * already contain a `function <name>(` declaration are passed through unchanged
 * — keeps backward compat with flows saved before the body-only convention.
 */
export function wrapBodyAsFunction(code: string, contract: FlowCodeContract): string {
  const trimmed = code.trim();
  if (looksLikeFunctionDeclaration(trimmed, contract.functionName)) {
    return trimmed;
  }
  return `function ${contract.functionName}(${contract.paramName}) {\n${code}\n}`;
}

function looksLikeFunctionDeclaration(code: string, functionName: string): boolean {
  // Cheap lexical check — the validator will catch parse errors regardless.
  // Matches `function name(`, `async function name(`, or `function name (`.
  const pattern = new RegExp(`^(async\\s+)?function\\s+${escapeRegex(functionName)}\\s*\\(`, 'm');
  return pattern.test(code);
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizeError(err: unknown): FlowCodeError {
  const message = err instanceof Error ? err.message : String(err);
  const lineMatch = /\bline\s+(\d+)|:(\d+):\d+/i.exec(message);
  const line = lineMatch ? Number(lineMatch[1] ?? lineMatch[2]) : undefined;

  if (/256KB cap|return value exceeds/i.test(message)) {
    return { stage: 'returnSize', message, line };
  }
  if (/SyntaxError|Unexpected (token|identifier|end)|Expected function/i.test(message)) {
    return { stage: 'parse', message, line };
  }
  return { stage: 'run', message, line };
}

function logRun(meta: {
  contract: string;
  organizationId?: string;
  durationMs: number;
  ok: boolean;
  errorStage?: FlowCodeErrorStage;
  source?: string;
}): void {
  // One JSON line per call. Picked up by Vercel/Fly logs and can be queried
  // for per-org P95s when we get around to it.
  const payload: Record<string, unknown> = {
    event: 'flow_code_run',
    ...meta,
    ts: new Date().toISOString(),
  };
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(payload));
}
