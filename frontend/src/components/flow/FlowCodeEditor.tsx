/**
 * Editor primitive for code-mode flow nodes.
 *
 * Hosts a Monaco JavaScript editor with TS-flavored autocomplete sourced from
 * `EVENT_SCHEMAS` + the contract registry. The Test button hits the backend's
 * `/api/flows/validate-code` (same engine the runtime uses) so the load-bearing
 * promise — "Save = passes Test = runs at runtime" — stays true.
 *
 * Visual chrome (theme, padding, wrapper) matches `<PolicyCodeEditor>` so the
 * code block reads identically across the policies page and the flow builder.
 */

import { useEffect, useRef, useState } from 'react';
import MonacoEditor, { type BeforeMount, type OnMount } from '@monaco-editor/react';
import type { editor, IDisposable } from 'monaco-editor';
import { Loader2, Play, ChevronDown, ChevronRight, AlertCircle, CheckCircle2 } from 'lucide-react';
import { api, type FlowCodeValidationResult } from '../../lib/api';
import { cn } from '../../lib/utils';
import { CODE_BLOCK_BG, beforeMountPolicyMonaco } from '../policy-monaco-setup';
import { JsLangBadge } from '../JsLangBadge';
import { buildFlowCodeDts, NODE_CODE_CONTRACTS } from './flow-code-typedefs';

const LINE_HEIGHT = 20;
const PADDING_TOP = 8;
const PADDING_BOTTOM = 2;
const MIN_LINES = 3;

interface FlowCodeEditorProps {
  flowId: string;
  nodeType: string;
  eventType: string | null;
  value: string;
  onChange: (value: string) => void;
  /** Notified after each validate-code response. Parent can store last result for save-gate UX. */
  onValidationChange?: (result: FlowCodeValidationResult | null) => void;
  /** Examples surfaced in the collapsible. */
  exampleBodies?: Array<{ label: string; body: string }>;
}

const CONDITION_EXAMPLES: Array<{ label: string; body: string }> = [
  {
    label: 'Critical or high severity only',
    body: `  const sev = context.vulnerability?.severity;
  return sev === 'critical' || sev === 'high';`,
  },
  {
    label: 'Reachable + score >= 70',
    body: `  const v = context.vulnerability;
  return Boolean(v?.isReachable) && (v?.depscore ?? 0) >= 70;`,
  },
  {
    label: 'Production tier projects',
    body: `  return context.project?.tier === 'Production';`,
  },
  {
    label: 'Direct dependencies only',
    body: `  return context.dependency?.isDirect === true;`,
  },
];

function fitHeight(value: string): number {
  const lineCount = Math.max(MIN_LINES, value.split('\n').length || 1);
  return (lineCount + 1) * LINE_HEIGHT + PADDING_TOP + PADDING_BOTTOM;
}

export function FlowCodeEditor({
  flowId,
  nodeType,
  eventType,
  value,
  onChange,
  onValidationChange,
  exampleBodies,
}: FlowCodeEditorProps) {
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);
  const disposablesRef = useRef<IDisposable[]>([]);
  const monacoRef = useRef<typeof import('monaco-editor') | null>(null);

  const [testing, setTesting] = useState(false);
  const [lastResult, setLastResult] = useState<FlowCodeValidationResult | null>(null);
  const [showExamples, setShowExamples] = useState(false);
  const [showCustomContext, setShowCustomContext] = useState(false);
  const [customContextJson, setCustomContextJson] = useState('');

  const examples = exampleBodies ?? (nodeType === 'condition' ? CONDITION_EXAMPLES : []);

  // Clear stale test result on edit. We surface "untested" via the absence of
  // lastResult and "passed" via its presence.
  useEffect(() => {
    if (lastResult !== null) {
      setLastResult(null);
      onValidationChange?.(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  // Refresh extra-lib when (nodeType, eventType) change. Removing the previous
  // disposable prevents the registry from growing unbounded across re-mounts.
  useEffect(() => {
    if (!monacoRef.current || !eventType) return;
    while (disposablesRef.current.length) disposablesRef.current.pop()?.dispose();
    const dts = buildFlowCodeDts(nodeType, eventType);
    const lib = (monacoRef.current.languages as any).typescript.javascriptDefaults.addExtraLib(
      dts,
      `flow-code-${nodeType}-${eventType}.d.ts`,
    );
    disposablesRef.current.push(lib);
    return () => {
      while (disposablesRef.current.length) disposablesRef.current.pop()?.dispose();
    };
  }, [nodeType, eventType]);

  const handleBeforeMount: BeforeMount = (monaco) => {
    // Same theme + diagnostics setup the policies page uses.
    beforeMountPolicyMonaco(monaco);

    // Override semantic validation back ON so users see "field doesn't exist"
    // errors against the typed event context. (PolicyCodeEditor turns it off
    // because its custom monarch language doesn't drive the TS service.)
    (monaco.languages as any).typescript.javascriptDefaults.setDiagnosticsOptions({
      noSemanticValidation: false,
      noSyntaxValidation: false,
    });

    monacoRef.current = monaco;
    if (eventType) {
      const dts = buildFlowCodeDts(nodeType, eventType);
      const lib = (monaco.languages as any).typescript.javascriptDefaults.addExtraLib(
        dts,
        `flow-code-${nodeType}-${eventType}.d.ts`,
      );
      disposablesRef.current.push(lib);
    }
  };

  const handleMount: OnMount = (editor) => {
    editorRef.current = editor;
  };

  const runTest = async () => {
    if (!eventType) return;
    setTesting(true);
    let parsedCustom: unknown = undefined;
    if (showCustomContext && customContextJson.trim()) {
      try {
        parsedCustom = JSON.parse(customContextJson);
      } catch (err: unknown) {
        const result: FlowCodeValidationResult = {
          syntaxOk: true,
          runOk: false,
          error: { stage: 'run', message: `Invalid custom context JSON: ${(err as Error).message}` },
          durationMs: 0,
        };
        setLastResult(result);
        onValidationChange?.(result);
        setTesting(false);
        return;
      }
    }
    try {
      const result = await api.validateFlowCode({
        flowId,
        nodeType,
        eventType,
        code: value,
        customContext: parsedCustom,
      });
      setLastResult(result);
      onValidationChange?.(result);
    } catch (err: unknown) {
      const result: FlowCodeValidationResult = {
        syntaxOk: true,
        runOk: false,
        error: { stage: 'run', message: (err as Error).message ?? 'Test request failed' },
        durationMs: 0,
      };
      setLastResult(result);
      onValidationChange?.(result);
    } finally {
      setTesting(false);
    }
  };

  const insertExample = (body: string) => {
    onChange(body);
    setShowExamples(false);
  };

  const editorHeight = fitHeight(value);
  const functionLabel = NODE_CODE_CONTRACTS[nodeType]?.functionName ?? 'function';

  return (
    <div className="flex flex-col gap-2">
      {/* Code block — matches the org-settings policies page chrome exactly:
          bordered card with a function-name header and the editor below. */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center gap-2">
          <JsLangBadge className="text-xs" />
          <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
            {functionLabel}
          </span>
          <div className="ml-auto flex items-center gap-1.5">
            <button
              type="button"
              onClick={runTest}
              disabled={testing || !eventType}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background-card px-2 py-1 text-[11px] font-medium text-foreground transition-colors hover:bg-background-subtle disabled:cursor-not-allowed disabled:opacity-50"
            >
              {testing ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <Play className="h-3 w-3" strokeWidth={2.5} />
              )}
              {testing ? 'Testing…' : 'Test'}
            </button>
          </div>
        </div>
        <div
          className="policy-code-editor w-full overscroll-auto"
          style={{ backgroundColor: CODE_BLOCK_BG, fontSize: 16 }}
        >
          <MonacoEditor
            width="100%"
            height={`${editorHeight}px`}
            language="javascript"
            theme="deptex"
            value={value}
            onChange={(v) => onChange(v ?? '')}
            beforeMount={handleBeforeMount}
            onMount={handleMount}
            options={{
              theme: 'deptex',
              minimap: { enabled: false },
              fontSize: 13,
              lineHeight: LINE_HEIGHT,
              fontFamily: "Consolas, 'Courier New', monospace",
              lineNumbers: 'on',
              lineNumbersMinChars: 2,
              scrollBeyondLastLine: false,
              automaticLayout: true,
              tabSize: 2,
              wordWrap: 'off',
              padding: { top: PADDING_TOP, bottom: PADDING_BOTTOM },
            }}
          />
        </div>
      </div>

      {/* Status panel */}
      {lastResult && (
        <div
          className={cn(
            'flex items-start gap-2 rounded-lg border px-3 py-2 text-[12px]',
            lastResult.runOk
              ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-400'
              : 'border-red-500/30 bg-red-500/5 text-red-400',
          )}
        >
          {lastResult.runOk ? (
            <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
          ) : (
            <AlertCircle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
          )}
          <div className="flex-1 min-w-0">
            {lastResult.runOk ? (
              <>
                <div className="font-medium">Valid (last test passed)</div>
                <div className="mt-0.5 font-mono text-[11px] text-foreground-secondary">
                  Returned: {JSON.stringify(lastResult.returnValue)} · {lastResult.durationMs}ms
                  {lastResult.cached && ' · cached'}
                </div>
              </>
            ) : (
              <>
                <div className="font-medium">
                  {lastResult.error?.stage === 'parse'
                    ? 'Syntax error'
                    : lastResult.error?.stage === 'returnShape'
                      ? 'Wrong return type'
                      : lastResult.error?.stage === 'returnSize'
                        ? 'Return value too large'
                        : 'Runtime error'}
                </div>
                <div className="mt-0.5 break-words font-mono text-[11px] text-foreground-secondary">
                  {lastResult.error?.message}
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Examples collapsible */}
      {examples.length > 0 && (
        <div className="rounded-lg border border-border bg-background-card-header">
          <button
            type="button"
            onClick={() => setShowExamples((v) => !v)}
            className="flex w-full items-center gap-2 px-3 py-2 text-[12px] font-medium text-foreground-secondary hover:text-foreground"
          >
            {showExamples ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            Examples
          </button>
          {showExamples && (
            <div className="border-t border-border">
              {examples.map((ex, i) => (
                <button
                  key={i}
                  type="button"
                  onClick={() => insertExample(ex.body)}
                  className="flex w-full flex-col items-start gap-0.5 border-b border-border px-3 py-2 text-left last:border-b-0 hover:bg-background-subtle"
                >
                  <span className="text-[12px] font-medium text-foreground">{ex.label}</span>
                  <code className="line-clamp-2 font-mono text-[11px] text-foreground-secondary">{ex.body.trim()}</code>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Custom context collapsible */}
      <div className="rounded-lg border border-border bg-background-card-header">
        <button
          type="button"
          onClick={() => setShowCustomContext((v) => !v)}
          className="flex w-full items-center gap-2 px-3 py-2 text-[12px] font-medium text-foreground-secondary hover:text-foreground"
        >
          {showCustomContext ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          Run with my own sample
        </button>
        {showCustomContext && (
          <div className="border-t border-border p-3">
            <textarea
              value={customContextJson}
              onChange={(e) => setCustomContextJson(e.target.value)}
              placeholder='{"vulnerability": {"severity": "critical", ...}}'
              rows={4}
              className="w-full rounded-md border border-border bg-background-card px-2 py-1.5 font-mono text-[11px] text-foreground placeholder:text-foreground-secondary/60 focus:border-foreground/40 focus:outline-none"
            />
            <p className="mt-1 text-[11px] text-foreground-secondary">
              JSON shape of an event payload — bypasses the cache.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
