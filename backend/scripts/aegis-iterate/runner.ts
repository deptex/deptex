import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import type { ModelMessage } from 'ai';
import { createAegisAgent } from '../../src/lib/aegis-v3/agent';
import { getOrCreateThread, loadThreadHistory } from '../../src/lib/aegis-v3/thread';
import { saveUserMessage } from '../../src/lib/aegis-v3/persistence';
import { getProviderInfoForOrg } from '../../src/lib/aegis-v3/provider';
import { estimateCost } from '../../src/lib/ai/pricing';

export interface ScenarioTurn {
  user: string;
  expect?: {
    tools_called?: string[];
    tools_called_count?: Record<string, number>;
    tools_not_called?: string[];
    tools_with_error?: string[];
    text_includes?: string[];
    text_excludes?: string[];
  };
}

export interface ScenarioCase {
  id: string;
  description?: string;
  context?: { type?: string; id?: string; projectId?: string };
  modelId?: string;
  turns: ScenarioTurn[];
}

export interface Scenario {
  scenario: string;
  orgId: string;
  userId: string;
  defaultModelId?: string;
  cases: ScenarioCase[];
}

export interface CaseResult {
  caseId: string;
  threadId: string;
  turns: number;
  costUsd: number;
  expectations: { passed: number; failed: number };
  error?: string;
}

export function loadScenario(file: string): Scenario {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as Scenario;
  if (!raw.orgId || !raw.userId || !Array.isArray(raw.cases)) {
    throw new Error(`invalid scenario file: ${file}`);
  }
  return raw;
}

interface TraceEvent {
  t: number;
  turn: number;
  kind:
    | 'user_turn'
    | 'tool_call'
    | 'tool_result'
    | 'text'
    | 'step_finish'
    | 'turn_finish'
    | 'expectation_check'
    | 'error';
  [key: string]: unknown;
}

function appendEvent(file: string, evt: TraceEvent): void {
  fs.appendFileSync(file, JSON.stringify(evt) + '\n');
}

function summarizeArgs(input: unknown): string {
  if (input == null) return '';
  try {
    const json = JSON.stringify(input);
    return json.length > 240 ? json.slice(0, 237) + '...' : json;
  } catch {
    return String(input);
  }
}

function summarizeResult(output: unknown): string {
  if (output == null) return '';
  try {
    const json = JSON.stringify(output);
    return json.length > 240 ? json.slice(0, 237) + '...' : json;
  } catch {
    return String(output);
  }
}

function isErrorResult(output: unknown): boolean {
  if (!output || typeof output !== 'object') return false;
  const o = output as Record<string, unknown>;
  return typeof o.error === 'string' && o.error.length > 0;
}

interface RunOpts {
  scenario: Scenario;
  case: ScenarioCase;
  runDir: string;
  maxCostUsd: number;
}

export async function runScenarioCase(opts: RunOpts): Promise<CaseResult> {
  const { scenario, case: sc, runDir, maxCostUsd } = opts;
  const threadId = randomUUID();
  const transcriptPath = path.join(runDir, `${sc.id}.jsonl`);
  fs.writeFileSync(transcriptPath, '');

  const providerInfo = await getProviderInfoForOrg(scenario.orgId, sc.modelId ?? scenario.defaultModelId);
  console.log(`\n--- case ${sc.id} ---`);
  if (sc.description) console.log(`    ${sc.description}`);
  console.log(`    thread: ${threadId}`);
  console.log(`    model:  ${providerInfo.model}`);

  // Bootstrap thread row + participant entry. Same code path /v3/stream uses,
  // so the harness exercises the real persistence + RBAC surface (modulo the
  // permission middleware itself, which we skip here).
  await getOrCreateThread(scenario.orgId, scenario.userId, threadId, sc.turns[0]?.user ?? '', sc.context);

  let costUsd = 0;
  let passedCt = 0;
  let failedCt = 0;
  let turnIdx = 0;

  try {
    for (const turn of sc.turns) {
      turnIdx += 1;
      const turnStart = Date.now();
      console.log(`\n  turn ${turnIdx}: "${turn.user.slice(0, 90)}${turn.user.length > 90 ? '...' : ''}"`);
      appendEvent(transcriptPath, {
        t: turnStart,
        turn: turnIdx,
        kind: 'user_turn',
        text: turn.user,
      });

      // Persist user message + load history exactly like /v3/stream does, so the
      // model sees the same messages array on turn N+1 that production would.
      await saveUserMessage({ threadId, userId: scenario.userId, content: turn.user });
      const history = await loadThreadHistory(threadId);

      const agent = await createAegisAgent({
        orgId: scenario.orgId,
        userId: scenario.userId,
        threadId,
        userMessage: turn.user,
        priorMessageCount: history.length - 1, // -1 because saveUserMessage already inserted
        context: sc.context,
        modelId: sc.modelId ?? scenario.defaultModelId,
      });

      const messages: ModelMessage[] = history; // already includes the user turn we just saved

      const calledTools: string[] = [];
      const calledCounts: Record<string, number> = {};
      const erroredTools: string[] = [];
      let assistantText = '';

      const result = await agent.stream({ messages });

      for await (const part of result.fullStream) {
        const p = part as { type: string; [k: string]: unknown };
        switch (p.type) {
          case 'text-delta': {
            const delta = (p as { text?: string; delta?: string }).text ?? (p as { delta?: string }).delta ?? '';
            assistantText += delta;
            break;
          }
          case 'tool-call': {
            const toolName = String(p.toolName ?? p.tool_name ?? 'unknown');
            calledTools.push(toolName);
            calledCounts[toolName] = (calledCounts[toolName] ?? 0) + 1;
            const input = (p as { input?: unknown }).input ?? (p as { args?: unknown }).args;
            console.log(`    [tool] ${toolName}(${summarizeArgs(input)})`);
            appendEvent(transcriptPath, {
              t: Date.now(),
              turn: turnIdx,
              kind: 'tool_call',
              toolName,
              input,
            });
            break;
          }
          case 'tool-result': {
            const toolName = String(p.toolName ?? p.tool_name ?? 'unknown');
            const output = (p as { output?: unknown }).output ?? (p as { result?: unknown }).result;
            const isError = isErrorResult(output);
            if (isError) erroredTools.push(toolName);
            console.log(`    [tool→] ${toolName} ${isError ? '(ERROR) ' : ''}${summarizeResult(output)}`);
            appendEvent(transcriptPath, {
              t: Date.now(),
              turn: turnIdx,
              kind: 'tool_result',
              toolName,
              output,
              isError,
            });
            break;
          }
          case 'error': {
            const errMsg = String((p as { error?: unknown }).error ?? 'unknown');
            console.log(`    [error] ${errMsg}`);
            appendEvent(transcriptPath, {
              t: Date.now(),
              turn: turnIdx,
              kind: 'error',
              error: errMsg,
            });
            break;
          }
        }
      }

      // Wait for the agent's onFinish (saveAssistantMessage) to complete so
      // the next turn sees the assistant turn in history. consumeStream above
      // is implicit via fullStream iteration; awaiting the promise APIs
      // exposed by StreamTextResult is how we get aggregates.
      const totalUsage = await result.totalUsage;
      const turnCost = estimateCost(
        providerInfo.model,
        totalUsage?.inputTokens ?? 0,
        totalUsage?.outputTokens ?? 0,
      );
      costUsd += turnCost;
      const elapsed = Date.now() - turnStart;
      const trimmedText = assistantText.length > 200 ? assistantText.slice(0, 197) + '...' : assistantText;
      if (trimmedText.trim()) console.log(`    [text] ${trimmedText}`);
      console.log(
        `    [usage] ${totalUsage?.inputTokens ?? 0} in / ${totalUsage?.outputTokens ?? 0} out → $${turnCost.toFixed(4)} (${(elapsed / 1000).toFixed(1)}s; running $${costUsd.toFixed(4)})`,
      );
      appendEvent(transcriptPath, {
        t: Date.now(),
        turn: turnIdx,
        kind: 'turn_finish',
        text: assistantText,
        usage: totalUsage,
        costUsd: turnCost,
        elapsedMs: elapsed,
      });

      // Expectation check
      const expect = turn.expect;
      if (expect) {
        const missing: string[] = [];
        const unexpected: string[] = [];
        const wrongCount: string[] = [];
        const missingErrors: string[] = [];
        const missingText: string[] = [];
        const unwantedText: string[] = [];

        for (const t of expect.tools_called ?? []) {
          if (!calledTools.includes(t)) missing.push(t);
        }
        for (const t of expect.tools_not_called ?? []) {
          if (calledTools.includes(t)) unexpected.push(t);
        }
        for (const [t, ct] of Object.entries(expect.tools_called_count ?? {})) {
          if ((calledCounts[t] ?? 0) !== ct) {
            wrongCount.push(`${t} expected ${ct}, got ${calledCounts[t] ?? 0}`);
          }
        }
        for (const t of expect.tools_with_error ?? []) {
          if (!erroredTools.includes(t)) missingErrors.push(t);
        }
        for (const s of expect.text_includes ?? []) {
          if (!assistantText.includes(s)) missingText.push(s);
        }
        for (const s of expect.text_excludes ?? []) {
          if (assistantText.includes(s)) unwantedText.push(s);
        }

        const failures: string[] = [];
        if (missing.length) failures.push(`missing tools: ${missing.join(', ')}`);
        if (unexpected.length) failures.push(`unexpected tools: ${unexpected.join(', ')}`);
        if (wrongCount.length) failures.push(`wrong counts: ${wrongCount.join('; ')}`);
        if (missingErrors.length) failures.push(`expected error from: ${missingErrors.join(', ')}`);
        if (missingText.length) failures.push(`text missing: ${missingText.join(', ')}`);
        if (unwantedText.length) failures.push(`text included unwanted: ${unwantedText.join(', ')}`);

        if (failures.length === 0) {
          passedCt += 1;
          console.log(`    ✅ expectations met`);
        } else {
          failedCt += 1;
          console.log(`    ❌ expectations failed: ${failures.join(' | ')}`);
        }
        appendEvent(transcriptPath, {
          t: Date.now(),
          turn: turnIdx,
          kind: 'expectation_check',
          passed: failures.length === 0,
          failures,
          calledTools,
          calledCounts,
          erroredTools,
        });
      }

      if (costUsd > maxCostUsd) {
        console.log(`    🛑 cost cap hit ($${costUsd.toFixed(4)} > $${maxCostUsd.toFixed(2)}); aborting case`);
        return {
          caseId: sc.id,
          threadId,
          turns: turnIdx,
          costUsd,
          expectations: { passed: passedCt, failed: failedCt },
          error: 'cost cap exceeded',
        };
      }
    }

    return {
      caseId: sc.id,
      threadId,
      turns: turnIdx,
      costUsd,
      expectations: { passed: passedCt, failed: failedCt },
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(`    💥 case errored: ${msg}`);
    appendEvent(transcriptPath, { t: Date.now(), turn: turnIdx, kind: 'error', error: msg });
    return {
      caseId: sc.id,
      threadId,
      turns: turnIdx,
      costUsd,
      expectations: { passed: passedCt, failed: failedCt },
      error: msg,
    };
  }
}
