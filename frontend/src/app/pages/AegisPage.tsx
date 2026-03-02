import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useChat } from '@ai-sdk/react';
import { DefaultChatTransport } from 'ai';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  Plus,
  Sparkles,
  Send,
  ChevronDown,
  ChevronRight,
  Loader2,
  Zap,
  MessageSquare,
  FolderOpen,
  Shield,
  Search,
  Megaphone,
  Wrench,
  CheckCircle,
  FileText,
  Circle,
  Clock,
  AlertCircle,
  X,
  StickyNote,
} from 'lucide-react';
import { supabase } from '../../lib/supabase';
import { api, type AegisThread, type AegisAutomation } from '../../lib/api';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

interface AegisTask {
  id: string;
  title: string;
  status: string;
  completed_steps?: number;
  total_steps?: number;
}

interface SecurityIncident {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium';
  status: string;
  current_phase: string;
  incident_type: string;
  escalation_level: number;
  declared_at: string;
  resolved_at?: string;
  contained_at?: string;
  affected_projects?: string[];
  affected_packages?: string[];
  affected_cves?: string[];
  task_id?: string;
  time_to_contain_ms?: number;
  time_to_remediate_ms?: number;
  total_duration_ms?: number;
  fixes_created?: number;
  prs_merged?: number;
  post_mortem?: string;
}

interface TimelineEvent {
  id: string;
  phase: string;
  event_type: string;
  description: string;
  actor?: string;
  metadata?: any;
  created_at: string;
}

const PHASE_ORDER = ['contain', 'assess', 'communicate', 'remediate', 'verify', 'report'] as const;

const PHASE_ICONS: Record<string, React.ReactNode> = {
  contain: <Shield className="w-4 h-4" />,
  assess: <Search className="w-4 h-4" />,
  communicate: <Megaphone className="w-4 h-4" />,
  remediate: <Wrench className="w-4 h-4" />,
  verify: <CheckCircle className="w-4 h-4" />,
  report: <FileText className="w-4 h-4" />,
};

function timeAgo(dateStr: string): string {
  const ms = Date.now() - new Date(dateStr).getTime();
  const min = Math.floor(ms / 60000);
  if (min < 1) return 'just now';
  if (min < 60) return `${min}m ago`;
  const hrs = Math.floor(min / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function formatDuration(ms?: number | null): string {
  if (!ms || ms <= 0) return 'N/A';
  const min = Math.floor(ms / 60000);
  if (min < 60) return `${min}m`;
  const hrs = Math.floor(min / 60);
  return `${hrs}h ${min % 60}m`;
}

function getMessageText(msg: { parts?: Array<{ type?: string; text?: string }> }): string {
  if (!msg.parts?.length) return '';
  return msg.parts
    .filter((p): p is { type: 'text'; text: string } => p.type === 'text' && typeof p.text === 'string')
    .map((p) => p.text)
    .join('');
}

export default function AegisPage() {
  const { id: organizationId, threadId: threadIdParam } = useParams<{ id: string; threadId?: string }>();
  const navigate = useNavigate();
  const [threads, setThreads] = useState<AegisThread[]>([]);
  const [tasks, setTasks] = useState<AegisTask[]>([]);
  const [automations, setAutomations] = useState<AegisAutomation[]>([]);
  const [loading, setLoading] = useState(true);
  const [contextEntity, setContextEntity] = useState<{ type: string; id: string } | null>(null);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(null);
  const [incidentTimeline, setIncidentTimeline] = useState<TimelineEvent[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [initialMessagesLoaded, setInitialMessagesLoaded] = useState(false);
  const [isWideViewport, setIsWideViewport] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(min-width: 1440px)').matches
  );
  const onNewThreadIdRef = useRef<((id: string) => void) | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const currentThreadId = threadIdParam || undefined;

  const loadThreads = useCallback(async () => {
    if (!organizationId) return;
    try {
      const list = await api.getAegisThreads(organizationId);
      setThreads(list);
    } catch {
      setThreads([]);
    }
  }, [organizationId]);

  const loadTasks = useCallback(async () => {
    if (!organizationId) return;
    try {
      const token = (await supabase.auth.getSession()).data.session?.access_token;
      if (!token) return;
      const res = await fetch(`${API_BASE_URL}/api/aegis/tasks/${organizationId}?status=running`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setTasks(Array.isArray(data) ? data : []);
      } else {
        setTasks([]);
      }
    } catch {
      setTasks([]);
    }
  }, [organizationId]);

  const loadAutomations = useCallback(async () => {
    if (!organizationId) return;
    try {
      const list = await api.getAegisAutomations(organizationId);
      setAutomations(list);
    } catch {
      setAutomations([]);
    }
  }, [organizationId]);

  const loadIncidents = useCallback(async () => {
    if (!organizationId) return;
    try {
      const token = (await supabase.auth.getSession()).data.session?.access_token;
      if (!token) return;
      const res = await fetch(
        `${API_BASE_URL}/api/organizations/${organizationId}/incidents?status=active,contained,assessing,communicating,remediating,verifying`,
        { headers: { Authorization: `Bearer ${token}` } },
      );
      if (res.ok) {
        const data = await res.json();
        setIncidents(data.incidents || []);
      }
    } catch {
      setIncidents([]);
    }
  }, [organizationId]);

  const loadIncidentDetail = useCallback(async (incidentId: string) => {
    try {
      const token = (await supabase.auth.getSession()).data.session?.access_token;
      if (!token || !organizationId) return;
      const res = await fetch(
        `${API_BASE_URL}/api/organizations/${organizationId}/incidents/${incidentId}`,
        { headers: { Authorization: `Bearer ${token}` } },
      );
      if (res.ok) {
        const data = await res.json();
        setSelectedIncident(data);
        setIncidentTimeline(data.timeline || []);
      }
    } catch {}
  }, [organizationId]);

  const loadInitialMessages = useCallback(async (threadId: string) => {
    try {
      const msgs = await api.getAegisThreadMessages(threadId);
      return msgs.map((m) => ({
        id: m.id,
        role: m.role as 'user' | 'assistant' | 'system',
        parts: [{ type: 'text' as const, text: m.content }],
      }));
    } catch {
      return [];
    }
  }, []);

  useEffect(() => {
    if (!organizationId) return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      await Promise.all([loadThreads(), loadTasks(), loadAutomations(), loadIncidents()]);
      if (!cancelled) setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [organizationId, loadThreads, loadTasks, loadAutomations, loadIncidents]);

  useEffect(() => {
    if (!organizationId) return;
    const channel = supabase
      .channel('incidents-realtime')
      .on(
        'postgres_changes' as any,
        { event: '*', schema: 'public', table: 'security_incidents', filter: `organization_id=eq.${organizationId}` },
        () => { loadIncidents(); if (selectedIncident) loadIncidentDetail(selectedIncident.id); },
      )
      .subscribe();
    return () => { supabase.removeChannel(channel); };
  }, [organizationId, loadIncidents, loadIncidentDetail, selectedIncident]);

  onNewThreadIdRef.current = (newId: string) => {
    if (organizationId) {
      navigate(`/organizations/${organizationId}/aegis/${newId}`, { replace: true });
    }
  };

  const transport = useMemo(() => {
    if (!organizationId) return undefined;
    return new DefaultChatTransport({
      api: `${API_BASE_URL}/api/aegis/v2/stream`,
      headers: async () => {
        const { data: { session } } = await supabase.auth.getSession();
        return { Authorization: `Bearer ${session?.access_token}` };
      },
      body: { organizationId, threadId: currentThreadId || undefined, context: contextEntity || undefined },
      prepareSendMessagesRequest: (opts) => {
        const lastMsg = opts.messages[opts.messages.length - 1];
        const text = lastMsg ? getMessageText(lastMsg) : '';
        return {
          body: {
            organizationId,
            threadId: opts.trigger === 'submit-message' ? (currentThreadId || null) : undefined,
            message: text,
            context: contextEntity || undefined,
          },
        };
      },
      fetch: async (url, init) => {
        const res = await fetch(url, init);
        const newThreadId = res.headers.get('X-Thread-Id');
        if (newThreadId && res.ok) {
          onNewThreadIdRef.current?.(newThreadId);
        }
        return res;
      },
    });
  }, [organizationId, currentThreadId, contextEntity]);

  const initialMessagesState = useRef<Array<{ id: string; role: 'user' | 'assistant' | 'system'; parts: { type: 'text'; text: string }[] }> | null>(null);

  useEffect(() => {
    setInitialMessagesLoaded(false);
    initialMessagesState.current = null;
  }, [currentThreadId]);

  useEffect(() => {
    if (!currentThreadId || initialMessagesLoaded || !organizationId) return;
    let cancelled = false;
    loadInitialMessages(currentThreadId).then((msgs) => {
      if (!cancelled && msgs.length > 0) {
        initialMessagesState.current = msgs;
        setInitialMessagesLoaded(true);
      }
    });
    return () => { cancelled = true; };
  }, [currentThreadId, organizationId, loadInitialMessages, initialMessagesLoaded]);

  const { messages, sendMessage, status, error, setMessages, stop } = useChat({
    id: currentThreadId || `new-${organizationId}`,
    transport,
  });

  useEffect(() => {
    if (initialMessagesState.current && initialMessagesState.current.length > 0 && messages.length === 0) {
      setMessages(initialMessagesState.current);
      initialMessagesState.current = null;
    }
  }, [messages.length, setMessages]);

  useEffect(() => {
    const el = messagesEndRef.current;
    if (el && typeof el.scrollIntoView === 'function') {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  const isLoading = status === 'streaming' || status === 'submitted';

  const handleNewChat = () => {
    if (organizationId) {
      navigate(`/organizations/${organizationId}/aegis`);
      setContextEntity(null);
    }
  };

  const handleSelectThread = (threadId: string) => {
    if (organizationId) {
      navigate(`/organizations/${organizationId}/aegis/${threadId}`);
    }
  };

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      const text = inputValue.trim();
      if (!text) return;
      sendMessage({ text });
      setInputValue('');
    },
    [sendMessage, inputValue]
  );

  useEffect(() => {
    const mql = window.matchMedia('(min-width: 1440px)');
    const handler = () => setIsWideViewport(mql.matches);
    mql.addEventListener('change', handler);
    return () => mql.removeEventListener('change', handler);
  }, []);

  if (!organizationId) {
    return (
      <div className="min-h-screen bg-[#09090b] flex items-center justify-center">
        <p className="text-zinc-500">No organization selected</p>
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-3rem)] flex bg-[#09090b] text-zinc-100 font-sans">
      {/* Left panel */}
      <aside className="w-[280px] shrink-0 border-r border-[#27272a] flex flex-col bg-[#09090b]">
        <div className="p-3 border-b border-[#27272a]">
          <button
            onClick={handleNewChat}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-3 rounded-lg bg-green-500 hover:bg-green-600 text-white text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Chat
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-3 space-y-4">
          {/* Active incidents */}
          {incidents.length > 0 && (
            <section>
              <h3 className="text-[10px] font-semibold uppercase tracking-wider text-red-400 mb-2 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                Active incidents
              </h3>
              <div className="space-y-1">
                {incidents.slice(0, 5).map((inc) => {
                  const isSelected = selectedIncident?.id === inc.id;
                  return (
                    <button
                      key={inc.id}
                      onClick={() => { loadIncidentDetail(inc.id); }}
                      className={`w-full text-left p-3 rounded-r-md transition-colors ${
                        isSelected
                          ? 'bg-zinc-800 border-l-2 border-l-white'
                          : 'bg-[#18181b]/60 border-l-2 border-l-red-500/60 hover:bg-[#18181b]'
                      }`}
                    >
                      <div className="flex items-center gap-1.5 mb-1">
                        <span className={`px-1.5 py-0.5 rounded-full text-[10px] font-medium ${
                          inc.severity === 'critical'
                            ? 'bg-red-500 text-white'
                            : inc.severity === 'high'
                            ? 'bg-amber-500 text-white'
                            : 'bg-zinc-600 text-white'
                        }`}>
                          {inc.severity}
                        </span>
                        <span className="text-[13px] font-semibold text-white truncate flex-1">
                          {inc.title}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 rounded-sm text-[10px] bg-amber-500/15 text-amber-500">
                          {inc.current_phase}
                        </span>
                        <span className="text-[11px] text-zinc-500">{timeAgo(inc.declared_at)}</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </section>
          )}

          {/* Active tasks */}
          <section>
            <h3 className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500 mb-2">
              Active tasks
            </h3>
            {loading ? (
              <div className="flex items-center gap-2 text-zinc-500 text-sm">
                <Loader2 className="w-3 h-3 animate-spin" />
                Loading...
              </div>
            ) : tasks.length === 0 ? (
              <p className="text-xs text-zinc-600">No active tasks</p>
            ) : (
              <div className="space-y-2">
                {tasks.slice(0, 5).map((t) => (
                  <div
                    key={t.id}
                    className="p-2.5 rounded-lg bg-[#18181b] border border-[#27272a] text-xs"
                  >
                    <p className="truncate font-medium text-zinc-200">{t.title || 'Task'}</p>
                    <div className="mt-1 flex items-center gap-2">
                      <div className="flex-1 h-1 rounded-full bg-[#27272a] overflow-hidden">
                        <div
                          className="h-full bg-green-500 rounded-full"
                          style={{
                            width: `${
                              t.total_steps && t.total_steps > 0
                                ? ((t.completed_steps ?? 0) / t.total_steps) * 100
                                : 0
                            }%`,
                          }}
                        />
                      </div>
                      <span className="text-zinc-500 font-mono text-[10px]">
                        {t.completed_steps ?? 0}/{t.total_steps ?? 0}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Automations */}
          <section>
            <h3 className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500 mb-2">
              Automations
            </h3>
            {automations.length === 0 ? (
              <p className="text-xs text-zinc-600">No automations</p>
            ) : (
              <div className="space-y-1">
                {automations.map((a) => (
                  <div
                    key={a.id}
                    className="flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-[#18181b] text-xs"
                  >
                    <Zap className={`w-3 h-3 shrink-0 ${a.enabled ? 'text-green-500' : 'text-zinc-600'}`} />
                    <span className="truncate text-zinc-300">{a.name}</span>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Threads */}
          <section>
            <h3 className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500 mb-2">
              Threads
            </h3>
            <div className="space-y-0.5 max-h-64 overflow-y-auto">
              {threads.map((t) => {
                const isActive = t.id === currentThreadId;
                return (
                  <button
                    key={t.id}
                    onClick={() => handleSelectThread(t.id)}
                    className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-2 ${
                      isActive
                        ? 'bg-[#18181b] border-l-2 border-l-green-500 pl-2'
                        : 'hover:bg-[#18181b] border-l-2 border-l-transparent pl-3'
                    }`}
                  >
                    <MessageSquare className="w-3.5 h-3.5 shrink-0 text-zinc-500" />
                    <span className="truncate text-zinc-300">{t.title || 'New chat'}</span>
                  </button>
                );
              })}
            </div>
          </section>
        </div>
      </aside>

      {/* Main panel */}
      <main className="flex-1 flex flex-col min-w-0">
        {selectedIncident ? (
          <IncidentDetailView
            incident={selectedIncident}
            timeline={incidentTimeline}
            organizationId={organizationId}
            onClose={() => setSelectedIncident(null)}
            onResolve={async () => {
              try {
                const token = (await supabase.auth.getSession()).data.session?.access_token;
                if (!token) return;
                await fetch(
                  `${API_BASE_URL}/api/organizations/${organizationId}/incidents/${selectedIncident.id}/resolve`,
                  { method: 'PATCH', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } },
                );
                setSelectedIncident(null);
                loadIncidents();
              } catch {}
            }}
            onClose2={async () => {
              try {
                const token = (await supabase.auth.getSession()).data.session?.access_token;
                if (!token) return;
                await fetch(
                  `${API_BASE_URL}/api/organizations/${organizationId}/incidents/${selectedIncident.id}/close`,
                  { method: 'PATCH', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({}) },
                );
                setSelectedIncident(null);
                loadIncidents();
              } catch {}
            }}
            onAddNote={async (content: string) => {
              try {
                const token = (await supabase.auth.getSession()).data.session?.access_token;
                if (!token) return;
                await fetch(
                  `${API_BASE_URL}/api/organizations/${organizationId}/incidents/${selectedIncident.id}/notes`,
                  { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ content }) },
                );
                loadIncidentDetail(selectedIncident.id);
              } catch {}
            }}
          />
        ) : (
        <>
        <header className="shrink-0 h-12 border-b border-[#27272a] flex items-center gap-3 px-4">
          <h1 className="text-sm font-medium truncate">
            {threads.find((t) => t.id === currentThreadId)?.title || 'New chat'}
          </h1>
          {contextEntity && (
            <span className="px-2 py-0.5 rounded-full text-xs bg-[#18181b] border border-[#27272a] text-zinc-400">
              {contextEntity.type}:{contextEntity.id.slice(0, 8)}
            </span>
          )}
        </header>

        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((m) => {
            if (m.role === 'user') {
              const text = getMessageText(m);
              return (
                <div key={m.id} className="flex justify-end">
                  <div className="max-w-[80%] px-4 py-2.5 rounded-xl bg-zinc-800 text-zinc-100 text-sm">
                    {text}
                  </div>
                </div>
              );
            }
            if (m.role === 'assistant') {
              const textPart = m.parts?.find((p: { type?: string }) => p.type === 'text');
              const text = textPart && 'text' in textPart ? textPart.text : '';
              const toolParts =
                m.parts?.filter(
                  (p: { type?: string }) =>
                    (typeof p.type === 'string' && p.type.startsWith('tool-')) || p.type === 'dynamic-tool'
                ) ?? [];
              return (
                <div key={m.id} className="flex gap-3">
                  <div className="shrink-0 w-8 h-8 rounded-lg bg-[#18181b] border border-[#27272a] flex items-center justify-center">
                    <Sparkles className="w-4 h-4 text-green-500" />
                  </div>
                  <div className="flex-1 min-w-0 space-y-2">
                    {toolParts.length > 0 && (
                      <div className="space-y-1">
                        {toolParts.map((tp: { type?: string; state?: string; toolName?: string; toolCallId?: string }, i: number) => (
                          <ToolExecutionCard key={tp.toolCallId ?? `tool-${i}`} tool={tp} />
                        ))}
                      </div>
                    )}
                    {text && (
                      <div className="prose prose-invert prose-sm max-w-none [&_pre]:bg-[#18181b] [&_pre]:border [&_pre]:border-[#27272a] [&_code]:font-mono [&_code]:text-xs">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
                      </div>
                    )}
                  </div>
                </div>
              );
            }
            return null;
          })}

          {isLoading && (
            <div className="flex gap-3">
              <div className="shrink-0 w-8 h-8 rounded-lg bg-[#18181b] border border-[#27272a] flex items-center justify-center">
                <Loader2 className="w-4 h-4 text-green-500 animate-spin" />
              </div>
              <div className="flex items-center gap-1 text-zinc-500 text-sm">
                <span className="inline-block w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                <span>Thinking...</span>
              </div>
            </div>
          )}

          {error && (
            <div className="px-4 py-2 rounded-lg bg-red-950/50 border border-red-900/50 text-red-300 text-sm">
              {error.message}
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        <form
          onSubmit={handleSubmit}
          className="shrink-0 p-4 border-t border-[#27272a] bg-[#09090b]"
        >
          <div className="flex gap-3 items-end">
            <textarea
              placeholder="Message Aegis..."
              rows={1}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              className="flex-1 min-h-[44px] max-h-32 px-4 py-3 rounded-xl bg-[#18181b] border border-[#27272a] text-zinc-100 placeholder:text-zinc-500 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  (e.target as HTMLTextAreaElement).form?.requestSubmit();
                }
              }}
              disabled={isLoading}
            />
            <button
              type="submit"
              disabled={isLoading}
              className="shrink-0 w-11 h-11 rounded-xl bg-green-500 hover:bg-green-600 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center transition-colors"
            >
              {isLoading ? (
                <Loader2 className="w-5 h-5 text-white animate-spin" />
              ) : (
                <Send className="w-5 h-5 text-white" />
              )}
            </button>
          </div>
          {contextEntity && (
            <div className="mt-2 flex items-center gap-2">
              <span className="text-xs text-zinc-500">Context:</span>
              <span className="px-2 py-0.5 rounded text-xs bg-[#18181b] border border-[#27272a] font-mono text-zinc-400">
                {contextEntity.type}/{contextEntity.id}
              </span>
            </div>
          )}
        </form>
      </>
        )}
      </main>

      {/* Right panel - conditional */}
      {contextEntity && isWideViewport && (
        <aside className="w-[320px] shrink-0 border-l border-[#27272a] p-4 bg-[#09090b]">
          <div className="rounded-xl bg-[#18181b] border border-[#27272a] p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-500 mb-2">
              Context
            </h3>
            <div className="space-y-2">
              <p className="text-sm text-zinc-300">
                <span className="font-mono">{contextEntity.type}</span>
                <span className="text-zinc-500 mx-1">·</span>
                <span className="font-mono text-zinc-400">{contextEntity.id}</span>
              </p>
              <div className="flex gap-2 mt-3">
                <button
                  type="button"
                  className="flex-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#27272a] hover:bg-zinc-700 text-zinc-200 transition-colors flex items-center justify-center gap-1"
                >
                  <FolderOpen className="w-3 h-3" />
                  Open Full Detail
                </button>
                <button
                  type="button"
                  className="flex-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-green-500 hover:bg-green-600 text-white transition-colors flex items-center justify-center gap-1"
                  onClick={() => {
                    // Would append context to input
                  }}
                >
                  <ChevronRight className="w-3 h-3" />
                  Send to Chat
                </button>
              </div>
            </div>
          </div>
        </aside>
      )}
    </div>
  );
}

function IncidentDetailView({
  incident,
  timeline,
  organizationId,
  onClose,
  onResolve,
  onClose2,
  onAddNote,
}: {
  incident: SecurityIncident;
  timeline: TimelineEvent[];
  organizationId: string;
  onClose: () => void;
  onResolve: () => void;
  onClose2: () => void;
  onAddNote: (content: string) => void;
}) {
  const [noteInput, setNoteInput] = useState('');
  const isTerminal = ['resolved', 'closed', 'aborted'].includes(incident.status);

  const phaseIdx = PHASE_ORDER.indexOf(incident.current_phase as any);

  return (
    <div className="flex-1 flex flex-col min-w-0">
      {/* Header */}
      <div className="shrink-0 border-b border-[#27272a] px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3 min-w-0">
          <span className={`px-2 py-0.5 rounded-sm text-[12px] font-medium ${
            incident.severity === 'critical' ? 'bg-red-500 text-white' :
            incident.severity === 'high' ? 'bg-amber-500 text-white' : 'bg-zinc-600 text-white'
          }`}>{incident.severity}</span>
          <h2 className="text-lg font-semibold truncate">{incident.title}</h2>
          <span className={`px-2.5 py-0.5 rounded-full text-[12px] flex items-center gap-1 ${
            isTerminal ? 'bg-zinc-700 text-green-400' : 'bg-zinc-700 text-amber-400'
          }`}>
            {isTerminal ? <CheckCircle className="w-3 h-3" /> : <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />}
            {incident.status}
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-[13px] text-zinc-400">Declared {timeAgo(incident.declared_at)}</span>
          {!isTerminal && (
            <>
              <button onClick={onResolve} className="px-3 py-1.5 rounded-md text-[13px] font-medium bg-green-500 hover:bg-green-600 text-white flex items-center gap-1.5">
                <CheckCircle className="w-3.5 h-3.5" /> Resolve
              </button>
              <button onClick={onClose2} className="px-3 py-1.5 rounded-md text-[13px] font-medium bg-zinc-700 hover:bg-zinc-600 text-zinc-300 flex items-center gap-1.5">
                <X className="w-3.5 h-3.5" /> Close
              </button>
            </>
          )}
          <button onClick={onClose} className="p-1.5 rounded-md hover:bg-zinc-800 text-zinc-400">
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Phase progress bar */}
      <div className="shrink-0 px-6 py-4 border-b border-[#27272a] flex items-center gap-1">
        {PHASE_ORDER.map((phase, i) => {
          const isCompleted = i < phaseIdx;
          const isCurrent = i === phaseIdx && !isTerminal;
          const isUpcoming = i > phaseIdx;
          return (
            <React.Fragment key={phase}>
              {i > 0 && (
                <div className={`h-0.5 w-4 ${isCompleted || isCurrent ? 'bg-green-500' : 'bg-zinc-700'}`} />
              )}
              <div className={`flex flex-col items-center gap-1 px-3 py-2 rounded-md border min-w-[90px] ${
                isCompleted ? 'bg-green-500/15 border-green-500 text-green-500' :
                isCurrent ? 'bg-amber-500/15 border-amber-500 text-amber-500' :
                'bg-[#18181b] border-zinc-800 text-zinc-500'
              }`}>
                {isCompleted ? <CheckCircle className="w-4 h-4" /> :
                 isCurrent ? <Loader2 className="w-4 h-4 animate-spin" /> :
                 PHASE_ICONS[phase] || <Circle className="w-4 h-4" />}
                <span className="text-[11px] font-semibold uppercase">{phase}</span>
              </div>
            </React.Fragment>
          );
        })}
      </div>

      {/* Timeline + right panel */}
      <div className="flex-1 flex overflow-hidden">
        {/* Timeline */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-1">
          {PHASE_ORDER.map((phase) => {
            const phaseEvents = timeline.filter(e => e.phase === phase);
            if (phaseEvents.length === 0) return null;
            return (
              <div key={phase} className="mb-4">
                <div className="text-[11px] uppercase text-zinc-600 font-semibold tracking-wider border-b border-zinc-800/50 pb-1 mb-2">
                  {phase}
                </div>
                {phaseEvents.map((event) => {
                  const time = new Date(event.created_at);
                  const timeStr = time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
                  const dotColor = event.event_type.includes('fail') || event.event_type.includes('abort')
                    ? 'bg-red-500'
                    : event.event_type.includes('escalation')
                    ? 'bg-amber-500'
                    : 'bg-green-500';
                  return (
                    <div key={event.id} className="flex items-start gap-3 py-1.5">
                      <span className="text-[11px] font-mono text-zinc-500 w-[50px] shrink-0 text-right">{timeStr}</span>
                      <div className="flex flex-col items-center mt-1">
                        <div className={`w-2 h-2 rounded-full ${dotColor}`} />
                        <div className="w-0.5 flex-1 bg-zinc-800" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          {event.actor && (
                            <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                              event.actor === 'aegis' ? 'bg-green-500/15 text-green-500' : 'bg-zinc-700 text-zinc-300'
                            }`}>
                              {event.actor === 'aegis' ? '✦ Aegis' : event.actor}
                            </span>
                          )}
                          <span className="text-[13px] text-zinc-200">{event.description}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            );
          })}

          {/* Add note form */}
          <div className="pt-4 border-t border-zinc-800 mt-4">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Add a note..."
                value={noteInput}
                onChange={(e) => setNoteInput(e.target.value)}
                className="flex-1 px-3 py-2 rounded-lg bg-[#18181b] border border-[#27272a] text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:ring-1 focus:ring-green-500/50"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && noteInput.trim()) {
                    onAddNote(noteInput.trim());
                    setNoteInput('');
                  }
                }}
              />
              <button
                onClick={() => { if (noteInput.trim()) { onAddNote(noteInput.trim()); setNoteInput(''); } }}
                className="px-3 py-2 rounded-lg bg-zinc-700 hover:bg-zinc-600 text-zinc-200 text-sm flex items-center gap-1"
              >
                <StickyNote className="w-3.5 h-3.5" /> Note
              </button>
            </div>
          </div>
        </div>

        {/* Right panel - affected scope */}
        <aside className="w-[300px] shrink-0 border-l border-[#27272a] p-4 overflow-y-auto">
          <h3 className="text-[14px] font-semibold text-zinc-300 mb-4">Affected Scope</h3>

          <div className="space-y-4">
            <div>
              <h4 className="text-[12px] text-zinc-500 mb-2">
                Projects <span className="text-zinc-600">({incident.affected_projects?.length || 0})</span>
              </h4>
              {(incident.affected_projects || []).length === 0 ? (
                <p className="text-[12px] text-zinc-600">None</p>
              ) : (
                <div className="space-y-1">
                  {incident.affected_projects!.map((pId) => (
                    <div key={pId} className="flex items-center gap-2 text-[12px]">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                      <span className="font-mono text-zinc-400 truncate">{pId.slice(0, 8)}...</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div>
              <h4 className="text-[12px] text-zinc-500 mb-2">
                Packages <span className="text-zinc-600">({incident.affected_packages?.length || 0})</span>
              </h4>
              {(incident.affected_packages || []).map((pkg) => (
                <div key={pkg} className="text-[12px] font-mono text-zinc-400 py-0.5">{pkg}</div>
              ))}
            </div>

            <div>
              <h4 className="text-[12px] text-zinc-500 mb-2">
                Vulnerabilities <span className="text-zinc-600">({incident.affected_cves?.length || 0})</span>
              </h4>
              {(incident.affected_cves || []).map((cve) => (
                <div key={cve} className="text-[12px] font-mono text-green-500 py-0.5">{cve}</div>
              ))}
            </div>

            <div className="pt-3 border-t border-zinc-800">
              <h4 className="text-[12px] text-zinc-500 mb-2">Metrics</h4>
              <div className="space-y-1 text-[12px]">
                <div className="flex justify-between">
                  <span className="text-zinc-500">Time to Contain</span>
                  <span className="font-mono text-zinc-300">{formatDuration(incident.time_to_contain_ms)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Time to Remediate</span>
                  <span className="font-mono text-zinc-300">{formatDuration(incident.time_to_remediate_ms)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Total Duration</span>
                  <span className="font-mono text-zinc-300">{formatDuration(incident.total_duration_ms)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Fixes Created</span>
                  <span className="font-mono text-zinc-300">{incident.fixes_created || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">PRs Merged</span>
                  <span className="font-mono text-zinc-300">{incident.prs_merged || 0}</span>
                </div>
              </div>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}

function ToolExecutionCard({ tool }: { tool: { type?: string; state?: string; toolName?: string } }) {
  const [collapsed, setCollapsed] = useState(true);
  const name = tool.toolName ?? (tool.type?.startsWith('tool-') ? tool.type.replace('tool-', '') : 'tool');
  const state = tool.state ?? 'pending';

  return (
    <div className="rounded-lg border border-[#27272a] overflow-hidden">
      <button
        type="button"
        onClick={() => setCollapsed(!collapsed)}
        className="w-full flex items-center justify-between px-3 py-2 bg-[#18181b] hover:bg-zinc-800/80 text-left"
      >
        <span className="text-xs font-mono text-zinc-400">{name}</span>
        <span className="text-[10px] text-zinc-500 uppercase">{state}</span>
        {collapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
      </button>
      {!collapsed && (
        <div className="px-3 py-2 text-xs text-zinc-500 border-t border-[#27272a]">
          Tool execution details
        </div>
      )}
    </div>
  );
}
