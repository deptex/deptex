import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { usePlanGate, TIER_DISPLAY } from '../../contexts/PlanContext';
import {
  Sparkles,
  Send,
  X,
  ChevronRight,
  Bot,
  AlertTriangle,
  Settings,
  MessageSquare,
  Loader2,
} from 'lucide-react';
import { api, type AegisMessage } from '../../lib/api';
import {
  streamAegisMessage,
  sanitizeStreamingMarkdown,
  type AegisContext,
} from '../../lib/aegis-stream';

interface AegisPanelProps {
  organizationId: string;
  projectId: string;
  context?: { type: string; id: string };
  hasByokProvider: boolean;
  hasPermission: boolean;
  onContextChange?: (context: { type: string; id: string } | null) => void;
}

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  toolCalls?: { name: string; summary?: string }[];
}

const CONTEXT_LABELS: Record<string, string> = {
  project: 'Project',
  vulnerability: 'Vulnerability',
  dependency: 'Dependency',
  semgrep: 'Code Finding',
  secret: 'Secret Finding',
};

const QUICK_ACTIONS: Record<string, string[]> = {
  project: ['What should I fix first?', 'Generate security report', 'Summarize risks'],
  vulnerability: ['Explain this vulnerability', 'Is this exploitable?', 'How do I fix this?'],
  dependency: ['Assess this dependency', 'Suggest upgrade', 'Show forensics'],
  semgrep: ['Explain this finding', 'Is this a real risk?', 'Suggest a fix'],
  secret: ['Assess exposure risk', 'How to rotate this?', 'Show affected code'],
};

const STORAGE_KEY_PREFIX = 'aegis-panel-';

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const mql = window.matchMedia(query);
    const handler = (e: MediaQueryListEvent) => setMatches(e.matches);
    mql.addEventListener('change', handler);
    return () => mql.removeEventListener('change', handler);
  }, [query]);
  return matches;
}

export function AegisPanel({
  organizationId,
  projectId,
  context,
  hasByokProvider,
  hasPermission,
  onContextChange,
}: AegisPanelProps) {
  const planGateAegis = usePlanGate('aegis_chat');
  const isDesktop = useMediaQuery('(min-width: 1280px)');
  const storageKey = `${STORAGE_KEY_PREFIX}${projectId}`;

  const [expanded, setExpanded] = useState(() => {
    try { return localStorage.getItem(storageKey) === 'true'; } catch { return false; }
  });
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [threadId, setThreadId] = useState<string | null>(null);
  const [isStreaming, setIsStreaming] = useState(false);
  const [streamingContent, setStreamingContent] = useState('');
  const [activeTools, setActiveTools] = useState<string[]>([]);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [usage, setUsage] = useState<{ spent: number; cap: number } | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const prevContextRef = useRef<typeof context>(undefined);

  useEffect(() => {
    try { localStorage.setItem(storageKey, String(expanded)); } catch {}
  }, [expanded, storageKey]);

  useEffect(() => {
    if (!expanded || historyLoaded || !hasByokProvider) return;

    let cancelled = false;
    setHistoryLoading(true);

    (async () => {
      try {
        const threads = await api.getAegisThreadsByProject(organizationId, projectId);
        if (cancelled) return;

        if (threads.length > 0) {
          const latest = threads[0];
          setThreadId(latest.id);
          const msgs = await api.getAegisThreadMessages(latest.id);
          if (cancelled) return;

          setMessages(
            msgs.map((m: AegisMessage) => ({
              id: m.id,
              role: m.role,
              content: m.content,
              timestamp: new Date(m.created_at),
            })),
          );
        }
      } catch {
        // Silently handle — user can still type
      } finally {
        if (!cancelled) {
          setHistoryLoaded(true);
          setHistoryLoading(false);
        }
      }
    })();

    return () => { cancelled = true; };
  }, [expanded, historyLoaded, organizationId, projectId, hasByokProvider]);

  useEffect(() => {
    if (!expanded || !hasByokProvider) return;
    let cancelled = false;

    (async () => {
      try {
        const data = await api.getAIUsage(organizationId);
        if (!cancelled) {
          setUsage({ spent: data.totalEstimatedCost, cap: data.monthlyCostCap });
        }
      } catch {}
    })();

    return () => { cancelled = true; };
  }, [expanded, organizationId, hasByokProvider]);

  useEffect(() => {
    const prev = prevContextRef.current;
    prevContextRef.current = context;

    if (!prev || !context) return;
    if (prev.type === context.type && prev.id === context.id) return;

    const label = CONTEXT_LABELS[context.type] || context.type;
    setMessages((msgs) => [
      ...msgs,
      {
        id: `sys-${Date.now()}`,
        role: 'system',
        content: `Context switched to ${label}: \`${context.id}\``,
        timestamp: new Date(),
      },
    ]);
  }, [context]);

  useEffect(() => {
    const el = messagesEndRef.current;
    if (el && typeof (el as HTMLElement).scrollIntoView === 'function') {
      (el as HTMLElement).scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, streamingContent]);

  useEffect(() => {
    return () => { abortRef.current?.abort(); };
  }, []);

  const budgetRatio = useMemo(() => {
    if (!usage || usage.cap <= 0) return 0;
    return usage.spent / usage.cap;
  }, [usage]);

  const isBudgetExhausted = budgetRatio >= 1;
  const isBudgetWarning = budgetRatio >= 0.9 && budgetRatio < 1;

  const sendMessage = useCallback(async (text: string) => {
    if (!text.trim() || isStreaming || isBudgetExhausted) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: text.trim(),
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsStreaming(true);
    setStreamingContent('');
    setActiveTools([]);

    const abort = new AbortController();
    abortRef.current = abort;

    const aegisContext: AegisContext | null = context
      ? { type: context.type as AegisContext['type'], id: context.id, projectId }
      : { type: 'project', id: projectId, projectId };

    const toolResults: { name: string; summary?: string }[] = [];

    try {
      await streamAegisMessage(
        organizationId,
        threadId,
        text.trim(),
        aegisContext,
        {
          onChunk(chunk) {
            setStreamingContent((prev) => prev + chunk);
          },
          onToolStart(name) {
            setActiveTools((prev) => [...prev, name]);
          },
          onToolResult(name, summary) {
            toolResults.push({ name, summary });
            setActiveTools((prev) => prev.filter((t) => t !== name));
          },
          onDone(fullContent, newThreadId, tokenUsage) {
            setThreadId(newThreadId || threadId);
            setMessages((prev) => [
              ...prev,
              {
                id: `assistant-${Date.now()}`,
                role: 'assistant',
                content: fullContent,
                timestamp: new Date(),
                toolCalls: toolResults.length > 0 ? toolResults : undefined,
              },
            ]);
            setStreamingContent('');
            setIsStreaming(false);
            setActiveTools([]);

            if (tokenUsage && usage) {
              const addedCost = (tokenUsage.inputTokens * 0.000003) + (tokenUsage.outputTokens * 0.000015);
              setUsage((prev) => prev ? { ...prev, spent: prev.spent + addedCost } : prev);
            }
          },
          onError(message, code) {
            setMessages((prev) => [
              ...prev,
              {
                id: `error-${Date.now()}`,
                role: 'system',
                content: code === 'BUDGET_EXCEEDED'
                  ? 'Monthly AI budget has been reached. Please contact your admin to increase the limit.'
                  : `Error: ${message}`,
                timestamp: new Date(),
              },
            ]);
            setStreamingContent('');
            setIsStreaming(false);
            setActiveTools([]);
          },
        },
        abort.signal,
      );
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        setMessages((prev) => [
          ...prev,
          {
            id: `error-${Date.now()}`,
            role: 'system',
            content: `Error: ${err.message || 'Failed to send message'}`,
            timestamp: new Date(),
          },
        ]);
      }
      setStreamingContent('');
      setIsStreaming(false);
      setActiveTools([]);
    }
  }, [isStreaming, isBudgetExhausted, context, projectId, organizationId, threadId, usage]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  const handleToggle = () => {
    setExpanded((prev) => !prev);
  };

  // ── Collapsed tab ──────────────────────────────────────
  if (!expanded) {
    return (
      <button
        onClick={handleToggle}
        className="group flex-shrink-0 w-10 flex flex-col items-center justify-center gap-2 border-l border-border bg-background-card hover:bg-background-subtle transition-colors cursor-pointer"
        style={{ writingMode: 'vertical-rl' }}
        title="Open Aegis AI"
      >
        <Sparkles className="h-4 w-4 text-green-500 rotate-0" style={{ writingMode: 'horizontal-tb' }} />
        <span className="text-xs font-medium text-foreground-secondary group-hover:text-foreground tracking-wider">
          Aegis AI
        </span>
      </button>
    );
  }

  // ── Expanded panel wrapper ─────────────────────────────
  const panelClasses = isDesktop
    ? 'flex-shrink-0 w-[380px] border-l border-border bg-background h-full'
    : 'absolute right-0 top-0 bottom-0 w-[380px] max-w-full border-l border-border bg-background z-50 shadow-xl';

  return (
    <div className={panelClasses}>
      <div className="flex flex-col h-full">
        {/* Header */}
        <div className="flex items-center justify-between px-4 h-12 border-b border-border flex-shrink-0">
          <div className="flex items-center gap-2 min-w-0">
            <Sparkles className="h-4 w-4 text-green-500 flex-shrink-0" />
            <span className="text-sm font-semibold text-foreground truncate">Aegis AI</span>
            {context && (
              <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-green-500/10 text-green-500 border border-green-500/20 truncate max-w-[140px]">
                {CONTEXT_LABELS[context.type] || context.type}
              </span>
            )}
          </div>
          <button
            onClick={handleToggle}
            className="h-7 w-7 flex items-center justify-center rounded-md text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Budget warnings */}
        {isBudgetWarning && (
          <div className="px-4 py-2 bg-yellow-500/10 border-b border-yellow-500/20 flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5 text-yellow-500 flex-shrink-0" />
            <span className="text-xs text-yellow-500">
              {Math.round(budgetRatio * 100)}% of monthly AI budget used
            </span>
          </div>
        )}
        {isBudgetExhausted && (
          <div className="px-4 py-2 bg-destructive/10 border-b border-destructive/20 flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5 text-destructive flex-shrink-0" />
            <span className="text-xs text-destructive">
              Monthly AI budget reached. Messages blocked until next cycle.
            </span>
          </div>
        )}

        {/* Body */}
        {!planGateAegis.allowed ? (
          <div className="flex-1 flex items-center justify-center p-6">
            <div className="text-center space-y-2">
              <Bot className="h-8 w-8 text-foreground-muted mx-auto" />
              <p className="text-sm text-foreground-secondary">
                Aegis AI requires the {TIER_DISPLAY[planGateAegis.requiredTier]} plan.
              </p>
              <a href={planGateAegis.upgradeUrl} className="text-xs text-primary hover:underline">Upgrade</a>
            </div>
          </div>
        ) : !hasByokProvider ? (
          <NoProviderCard organizationId={organizationId} />
        ) : !hasPermission ? (
          <div className="flex-1 flex items-center justify-center p-6">
            <div className="text-center space-y-2">
              <Bot className="h-8 w-8 text-foreground-muted mx-auto" />
              <p className="text-sm text-foreground-secondary">
                You don't have permission to use Aegis AI in this organization.
              </p>
            </div>
          </div>
        ) : (
          <>
            {/* Messages area */}
            <div className="flex-1 overflow-y-auto custom-scrollbar p-4 space-y-4">
              {historyLoading && (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-5 w-5 text-foreground-muted animate-spin" />
                </div>
              )}

              {!historyLoading && messages.length === 0 && !streamingContent && (
                <EmptyState
                  context={context}
                  onQuickAction={sendMessage}
                />
              )}

              {messages.map((msg) => (
                <MessageBubble key={msg.id} message={msg} />
              ))}

              {/* Streaming assistant response */}
              {isStreaming && (
                <div className="space-y-2">
                  {activeTools.length > 0 && (
                    <div className="flex items-center gap-2 px-3 py-2 rounded-md bg-green-500/5 border border-green-500/10">
                      <Loader2 className="h-3 w-3 text-green-500 animate-spin flex-shrink-0" />
                      <span className="text-xs text-green-400">
                        Running: {activeTools.join(', ')}
                      </span>
                    </div>
                  )}
                  {streamingContent && (
                    <div className="rounded-lg px-3 py-2.5 bg-background-card border border-border">
                      <div className="prose-aegis text-sm text-foreground">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>
                          {sanitizeStreamingMarkdown(streamingContent)}
                        </ReactMarkdown>
                        <span className="inline-block w-2 h-4 bg-green-500 animate-pulse rounded-sm ml-0.5 align-text-bottom" />
                      </div>
                    </div>
                  )}
                  {!streamingContent && activeTools.length === 0 && (
                    <div className="rounded-lg px-3 py-2.5 bg-background-card border border-border">
                      <span className="inline-block w-2 h-4 bg-green-500 animate-pulse rounded-sm" />
                    </div>
                  )}
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Quick actions */}
            {messages.length === 0 && !isStreaming && context && (
              <QuickActions
                contextType={context.type}
                onAction={sendMessage}
              />
            )}

            {/* Input */}
            <div className="flex-shrink-0 border-t border-border p-3">
              <div className="flex items-end gap-2">
                <textarea
                  ref={inputRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder={isBudgetExhausted ? 'Budget exhausted' : 'Ask Aegis...'}
                  disabled={isStreaming || isBudgetExhausted}
                  rows={1}
                  className="flex-1 resize-none bg-background-card border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:ring-1 focus:ring-green-500/40 focus:border-green-500/40 disabled:opacity-50 min-h-[38px] max-h-[120px]"
                  style={{ fieldSizing: 'content' } as React.CSSProperties}
                />
                <button
                  onClick={() => sendMessage(input)}
                  disabled={!input.trim() || isStreaming || isBudgetExhausted}
                  className="h-[38px] w-[38px] flex items-center justify-center rounded-lg bg-green-600 hover:bg-green-500 text-white disabled:opacity-30 disabled:hover:bg-green-600 transition-colors flex-shrink-0"
                >
                  {isStreaming ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Send className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────

function NoProviderCard({ organizationId }: { organizationId: string }) {
  return (
    <div className="flex-1 flex items-center justify-center p-6">
      <div className="w-full max-w-[280px] rounded-lg border border-border bg-background-card p-5 space-y-4 text-center">
        <div className="h-10 w-10 rounded-full bg-green-500/10 flex items-center justify-center mx-auto">
          <Bot className="h-5 w-5 text-green-500" />
        </div>
        <div className="space-y-1.5">
          <h3 className="text-sm font-semibold text-foreground">Set up AI Provider</h3>
          <p className="text-xs text-foreground-secondary leading-relaxed">
            Connect an OpenAI, Anthropic, or Google API key to enable Aegis AI security assistant.
          </p>
        </div>
        <a
          href={`/organizations/${organizationId}/settings`}
          className="inline-flex items-center gap-1.5 text-xs font-medium text-green-500 hover:text-green-400 transition-colors"
        >
          <Settings className="h-3.5 w-3.5" />
          Organization Settings
          <ChevronRight className="h-3 w-3" />
        </a>
      </div>
    </div>
  );
}

function EmptyState({
  context,
  onQuickAction,
}: {
  context?: { type: string; id: string };
  onQuickAction: (text: string) => void;
}) {
  const contextType = context?.type || 'project';
  const actions = QUICK_ACTIONS[contextType] || QUICK_ACTIONS.project;

  return (
    <div className="flex flex-col items-center justify-center py-12 space-y-5">
      <div className="h-12 w-12 rounded-full bg-green-500/10 flex items-center justify-center">
        <Sparkles className="h-6 w-6 text-green-500" />
      </div>
      <div className="text-center space-y-1.5">
        <h3 className="text-sm font-semibold text-foreground">Aegis Security Copilot</h3>
        <p className="text-xs text-foreground-secondary max-w-[240px]">
          Ask about vulnerabilities, dependencies, or security posture.
        </p>
      </div>
      <div className="w-full space-y-1.5 px-2">
        {actions.map((action) => (
          <button
            key={action}
            onClick={() => onQuickAction(action)}
            className="w-full text-left px-3 py-2 rounded-md border border-border bg-background-card hover:bg-background-subtle text-xs text-foreground-secondary hover:text-foreground transition-colors flex items-center gap-2"
          >
            <MessageSquare className="h-3 w-3 flex-shrink-0 text-green-500/60" />
            {action}
          </button>
        ))}
      </div>
    </div>
  );
}

function QuickActions({
  contextType,
  onAction,
}: {
  contextType: string;
  onAction: (text: string) => void;
}) {
  const actions = QUICK_ACTIONS[contextType];
  if (!actions) return null;

  return (
    <div className="flex-shrink-0 border-t border-border px-3 py-2">
      <div className="flex gap-1.5 overflow-x-auto custom-scrollbar pb-0.5">
        {actions.map((action) => (
          <button
            key={action}
            onClick={() => onAction(action)}
            className="flex-shrink-0 px-2.5 py-1 rounded-full border border-border bg-background-card hover:bg-background-subtle text-[11px] text-foreground-secondary hover:text-foreground transition-colors whitespace-nowrap"
          >
            {action}
          </button>
        ))}
      </div>
    </div>
  );
}

function MessageBubble({ message }: { message: ChatMessage }) {
  if (message.role === 'system') {
    return (
      <div className="flex justify-center">
        <span className="text-[11px] text-foreground-muted bg-background-subtle px-2.5 py-1 rounded-full">
          {message.content}
        </span>
      </div>
    );
  }

  const isUser = message.role === 'user';

  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
      <div
        className={`max-w-[90%] rounded-lg px-3 py-2.5 text-sm ${
          isUser
            ? 'bg-green-600/20 border border-green-500/20 text-foreground'
            : 'bg-background-card border border-border text-foreground'
        }`}
      >
        {!isUser && message.toolCalls && message.toolCalls.length > 0 && (
          <div className="mb-2 space-y-1">
            {message.toolCalls.map((tc, i) => (
              <div key={i} className="flex items-center gap-1.5 text-[11px] text-foreground-muted">
                <span className="h-1 w-1 rounded-full bg-green-500 flex-shrink-0" />
                <span>Used <span className="text-foreground-secondary font-medium">{tc.name}</span></span>
              </div>
            ))}
          </div>
        )}
        {isUser ? (
          <p className="whitespace-pre-wrap break-words">{message.content}</p>
        ) : (
          <div className="prose-aegis">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {message.content}
            </ReactMarkdown>
          </div>
        )}
      </div>
    </div>
  );
}
