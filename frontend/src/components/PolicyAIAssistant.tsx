import { useState, useRef, useEffect, useLayoutEffect, useCallback, memo } from 'react';
import { createPortal } from 'react-dom';
import { ArrowUp, X, User, ChevronDown, Brain, Eraser } from 'lucide-react';
import { api } from '../lib/api';
import { useUserProfile } from '../hooks/useUserProfile';
import { Avatar, AvatarImage, AvatarFallback } from './ui/avatar';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';
import { cn } from '../lib/utils';
import { getDiffLineCounts } from './PolicyDiffViewer';
import { PolicyDiffCodeEditor } from './PolicyDiffCodeEditor';
import { JsLangBadge } from './JsLangBadge';

const CONTEXT_WINDOW = 1_000_000; // Gemini 2.5 Flash

const SLASH_COMMANDS: Array<{ id: string; label: string; description: string; icon: React.ReactNode }> = [
  { id: 'clear', label: 'Clear conversation', description: 'Remove all messages', icon: <Eraser className="h-3.5 w-3.5" /> },
];

type TargetEditor = 'compliance' | 'pullRequest' | 'projectStatus';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  suggestedCode?: string | null;
  targetEditor?: TargetEditor;
  baseCodeAtSuggestion?: string;
  accepted?: boolean;
}

interface PolicyAIAssistantProps {
  organizationId: string;
  /** Package policy body (packagePolicy). Optional when statusCodeOnly. */
  complianceBody?: string;
  /** PR check body (pullRequestCheck). Optional when statusCodeOnly. */
  pullRequestBody?: string;
  onUpdateCompliance?: (code: string) => void;
  onUpdatePullRequest?: (code: string) => void;
  /** Status code body (projectStatus) only — when set with onUpdateStatusCode, assistant is status-code only (no target dropdown). */
  statusCodeBody?: string;
  onUpdateStatusCode?: (code: string) => void;
  onClose: () => void;
  /** When 'edge', renders flush to container with dark theme, no X button. Use when fixed overlay sidebar. */
  variant?: 'inline' | 'edge';
  /** Optional ref to receive the panel's close handler (cleanup + onClose). Parent should call this when closing via backdrop so slash menu is cleared. */
  innerCloseRef?: React.MutableRefObject<(() => void) | null>;
}

const TARGET_LABELS: Record<TargetEditor, string> = {
  compliance: 'Package policy',
  pullRequest: 'Pull Request Check',
  projectStatus: 'Status Code',
};

/** Textarea grows with content up to this height, then scrolls inside */
const INPUT_MAX_HEIGHT_PX = 280;
const INPUT_MIN_HEIGHT_PX = 88;

/**
 * Module-level component so React keeps a stable type — inline DiffBlock inside
 * PolicyAIAssistant was recreated every render, remounting Monaco and causing flash.
 */
function PolicyAssistantDiffBlock({
  targetEditor,
  baseCode,
  requestedCode,
}: {
  targetEditor: TargetEditor;
  baseCode: string;
  requestedCode: string;
}) {
  const { added, removed } = getDiffLineCounts(baseCode, requestedCode);
  return (
    <div className="rounded-lg overflow-hidden border border-border bg-background-card">
      <div className="px-3 py-2 border-b border-border flex items-center justify-between gap-2 bg-background-card">
        <div className="flex items-center gap-2 min-w-0">
          <JsLangBadge className="text-xs" />
          <span className="text-xs font-medium text-foreground">
            {TARGET_LABELS[targetEditor]}
          </span>
          {added > 0 && <span className="text-xs text-green-500">+{added}</span>}
          {removed > 0 && <span className="text-xs text-red-500">-{removed}</span>}
        </div>
      </div>
      <MemoPolicyDiffCodeEditor original={baseCode} modified={requestedCode} />
    </div>
  );
}

/** Memoized so typing in the chat input doesn't re-run Monaco layout when code strings are unchanged */
const MemoPolicyDiffCodeEditor = memo(PolicyDiffCodeEditor, (prev, next) => {
  return prev.original === next.original && prev.modified === next.modified;
});

const SUGGESTIONS: Array<{ label: string; target: TargetEditor; prompt: string }> = [
  { label: 'Non-Compliant if any dependency blocked by package policy', target: 'projectStatus', prompt: 'Set project status to Non-Compliant with violation messages when any dependency has policyResult.allowed === false; otherwise Compliant.' },
  { label: 'Compliant only when no reachable critical vulns', target: 'projectStatus', prompt: 'Return Non-Compliant if any dependency has a critical severity vulnerability with isReachable true; otherwise Compliant.' },
  { label: 'Use Action Required when deps blocked (if that status exists)', target: 'projectStatus', prompt: 'If any dependency is disallowed by package policy, return status Action Required with violations listing package names and reasons; otherwise Compliant.' },
  { label: 'Only allow MIT and Apache-2.0 licenses (package policy)', target: 'compliance', prompt: 'Only allow MIT and Apache-2.0 licenses in the package policy — block any dependency whose license is not in that allowlist.' },
  { label: 'Require all deps to have known maintenance status', target: 'compliance', prompt: 'Make compliance fail if any dependency has unknown or unmaintained status.' },
  { label: 'Block projects with critical vulnerabilities', target: 'compliance', prompt: 'Make compliance fail when the project has any critical severity vulnerability that is reachable.' },
  { label: 'Block critical reachable vulns in PRs', target: 'pullRequest', prompt: 'Block PRs that add or update a dependency with any critical severity vulnerability that is reachable.' },
  { label: 'Require OpenSSF score >= 3 for new deps', target: 'pullRequest', prompt: 'Block PRs that add a new direct production dependency with an OpenSSF score below 3.' },
  { label: 'Block suspicious supply chain signals', target: 'pullRequest', prompt: 'Block PRs if any added or updated dependency has a failing registry integrity, install scripts, or entropy analysis status.' },
];

/** Render AI response Supabase-style: titles, paragraphs, numbered lists, bold */
function renderAISupabaseStyle(text: string) {
  const lines = text.split('\n');
  const elements: React.ReactNode[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    // Numbered list (1. 2. 3. or 1) 2) etc)
    if (/^\d+[.)]\s/.test(trimmed)) {
      const listItems: string[] = [];
      while (i < lines.length && /^\d+[.)]\s/.test(lines[i].trim())) {
        listItems.push(lines[i].trim().replace(/^\d+[.)]\s*/, ''));
        i++;
      }
      elements.push(
        <ol key={key++} className="list-decimal list-inside space-y-1.5 my-3 text-foreground">
          {listItems.map((item, j) => (
            <li key={j} className="pl-1">
              {renderInlineBold(item)}
            </li>
          ))}
        </ol>
      );
      continue;
    }

    // Bullet list
    if (/^[-*]\s/.test(trimmed)) {
      const listItems: string[] = [];
      while (i < lines.length && /^[-*]\s/.test(lines[i].trim())) {
        listItems.push(lines[i].trim().slice(2));
        i++;
      }
      elements.push(
        <ul key={key++} className="list-disc list-inside space-y-1 my-3 text-foreground">
          {listItems.map((item, j) => (
            <li key={j} className="pl-1">
              {renderInlineBold(item)}
            </li>
          ))}
        </ul>
      );
      continue;
    }

    // Empty line
    if (!trimmed) {
      i++;
      continue;
    }

    // Title (## or starts with ** and ends with **, or first line of a block)
    const isTitle = trimmed.startsWith('## ') || (trimmed.startsWith('**') && trimmed.endsWith('**'));
    if (isTitle) {
      const content = trimmed.replace(/^##\s*/, '').replace(/\*\*/g, '');
      elements.push(
        <p key={key++} className="font-bold text-foreground text-sm mt-4 mb-1 first:mt-0">
          {content}
        </p>
      );
    } else {
      elements.push(
        <p key={key++} className="text-sm text-foreground leading-relaxed my-2">
          {renderInlineBold(trimmed)}
        </p>
      );
    }
    i++;
  }

  return <div className="space-y-1">{elements}</div>;
}

function renderInlineBold(text: string) {
  const parts = text.split(/(\*\*.+?\*\*)/g);
  return parts.map((part, i) => {
    const match = part.match(/^\*\*(.+)\*\*$/);
    if (match) {
      return <span key={i} className="font-bold text-foreground">{match[1]}</span>;
    }
    return <span key={i}>{part}</span>;
  });
}

function parseAIResponse(raw: string): { message: string; code: string | null } {
  try {
    const trimmed = raw.trim();
    const jsonStart = trimmed.indexOf('{');
    const jsonEnd = trimmed.lastIndexOf('}');
    if (jsonStart === -1 || jsonEnd === -1) return { message: trimmed, code: null };
    const parsed = JSON.parse(trimmed.slice(jsonStart, jsonEnd + 1));
    return {
      message: parsed.message || '',
      code: parsed.code ?? null,
    };
  } catch {
    return { message: raw, code: null };
  }
}

export function PolicyAIAssistant({
  organizationId,
  complianceBody = '',
  pullRequestBody = '',
  onUpdateCompliance,
  onUpdatePullRequest,
  statusCodeBody,
  onUpdateStatusCode,
  onClose,
  variant = 'inline',
  innerCloseRef,
}: PolicyAIAssistantProps) {
  const statusCodeOnly = typeof statusCodeBody === 'string' && typeof onUpdateStatusCode === 'function';
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [targetEditor, setTargetEditor] = useState<TargetEditor>(statusCodeOnly ? 'projectStatus' : 'compliance');
  const [isStreaming, setIsStreaming] = useState(false);
  const [showTargetDropdown, setShowTargetDropdown] = useState(false);
  const [contextUsage, setContextUsage] = useState<{ inputTokens: number; outputTokens: number } | null>(null);
  const { avatarUrl, fullName } = useUserProfile();
  const chatEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Grow textarea with content so multi-line prompts stay visible without squishing
  useLayoutEffect(() => {
    const ta = inputRef.current;
    if (!ta || isStreaming) return;
    ta.style.height = 'auto';
    const next = Math.min(Math.max(ta.scrollHeight, INPUT_MIN_HEIGHT_PX), INPUT_MAX_HEIGHT_PX);
    ta.style.height = `${next}px`;
    ta.style.overflowY = ta.scrollHeight > INPUT_MAX_HEIGHT_PX ? 'auto' : 'hidden';
  }, [input, isStreaming]);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const targetDropdownMenuRef = useRef<HTMLDivElement>(null);
  const [targetDropdownRect, setTargetDropdownRect] = useState<{ left: number; top: number; width: number } | null>(null);
  const inputContainerRef = useRef<HTMLDivElement>(null);
  const [slashPopOpen, setSlashPopOpen] = useState(false);
  const [slashMenuRect, setSlashMenuRect] = useState<{ top: number; left: number; width: number } | null>(null);

  const handleClose = useCallback(() => {
    setSlashPopOpen(false);
    setSlashMenuRect(null);
    setInput((prev) => prev.replace(/\/[^/]*$/, ''));
    onClose();
  }, [onClose]);

  useEffect(() => {
    if (innerCloseRef) {
      innerCloseRef.current = handleClose;
      return () => {
        innerCloseRef.current = null;
      };
    }
  }, [handleClose, innerCloseRef]);

  const scrollToBottom = useCallback(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const t = e.target as Node;
      if (dropdownRef.current?.contains(t)) return;
      if (targetDropdownMenuRef.current?.contains(t)) return;
      setShowTargetDropdown(false);
    };
    if (showTargetDropdown) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [showTargetDropdown]);

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isStreaming) handleClose();
    };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [isStreaming, handleClose]);

  const handleSend = async (overrideMessage?: string, overrideTarget?: TargetEditor) => {
    const msg = overrideMessage ?? input.trim();
    const target = statusCodeOnly ? 'projectStatus' : (overrideTarget ?? targetEditor);
    if (!msg || isStreaming) return;

    setInput('');
    const userMsg: ChatMessage = { role: 'user', content: msg };
    const placeholderAssistant: ChatMessage = { role: 'assistant', content: '' };
    setMessages(prev => [...prev, userMsg, placeholderAssistant]);
    setIsStreaming(true);

    const conversationHistory = messages
      .filter(m => m.role === 'user' || m.role === 'assistant')
      .map(m => ({ role: m.role, content: m.content }));

    const baseCompliance = workingProposalCompliance ?? complianceBody;
    const basePullRequest = workingProposalPullRequest ?? pullRequestBody;
    const baseProjectStatus = workingProposalProjectStatus ?? (statusCodeBody ?? '');

    try {
      const response = await api.policyAIAssistStream(organizationId, {
        message: msg,
        targetEditor: statusCodeOnly ? 'projectStatus' : target,
        currentComplianceCode: baseCompliance,
        currentPullRequestCode: basePullRequest,
        currentProjectStatusCode: baseProjectStatus,
        conversationHistory,
      });

      const reader = response.body?.getReader();
      if (!reader) throw new Error('No response stream');

      const decoder = new TextDecoder();
      let accumulated = '';
      let buffer = '';

      // Placeholder assistant message already added above - "Thinking..." shows immediately
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const jsonStr = line.slice(6);

          try {
            const event = JSON.parse(jsonStr);
            if (event.type === 'chunk') {
              accumulated += event.content;
              // Don't update UI during stream - show "Thinking..." until done
            } else if (event.type === 'done') {
              const fullContent = event.fullContent ?? accumulated;
              const parsed = parseAIResponse(fullContent);
              const baseAtSuggestion = parsed.code
                ? (target === 'compliance' ? baseCompliance : target === 'pullRequest' ? basePullRequest : baseProjectStatus)
                : undefined;
              if (event.usage) setContextUsage(event.usage);
              setMessages(prev => {
                const updated = [...prev];
                updated[updated.length - 1] = {
                  role: 'assistant',
                  content: parsed.message,
                  suggestedCode: parsed.code,
                  targetEditor: parsed.code ? target : undefined,
                  baseCodeAtSuggestion: baseAtSuggestion,
                };
                return updated;
              });
            } else if (event.type === 'error') {
              setMessages(prev => {
                const updated = [...prev];
                updated[updated.length - 1] = {
                  role: 'assistant',
                  content: `Error: ${event.error}`,
                };
                return updated;
              });
            }
          } catch { /* skip malformed SSE lines */ }
        }
      }
    } catch (err: any) {
      setMessages(prev => [
        ...prev.filter(m => !(m.role === 'assistant' && m.content === '')),
        { role: 'assistant', content: `Error: ${err.message || 'Failed to get response'}` },
      ]);
    } finally {
      setIsStreaming(false);
      inputRef.current?.focus();
    }
  };

  const handleAccept = () => {
    if (!pendingSuggestion?.suggestedCode || !pendingSuggestion.targetEditor || pendingSuggestionIdx < 0) return;
    if (pendingSuggestion.targetEditor === 'compliance' && onUpdateCompliance) {
      onUpdateCompliance(pendingSuggestion.suggestedCode);
    } else if (pendingSuggestion.targetEditor === 'pullRequest' && onUpdatePullRequest) {
      onUpdatePullRequest(pendingSuggestion.suggestedCode);
    } else if (pendingSuggestion.targetEditor === 'projectStatus' && onUpdateStatusCode) {
      onUpdateStatusCode(pendingSuggestion.suggestedCode);
    }
    setMessages(prev =>
      prev.map(m =>
        m.suggestedCode ? { ...m, accepted: true } : m
      )
    );
  };

  const getCurrentCode = (target: TargetEditor) =>
    target === 'compliance' ? complianceBody : target === 'pullRequest' ? pullRequestBody : (statusCodeBody ?? '');

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const showSlashMenu = input.includes('/');
  const slashFilter = showSlashMenu ? input.slice(input.indexOf('/') + 1).toLowerCase() : '';
  const slashOptions = SLASH_COMMANDS.filter(
    (c) => !slashFilter || c.label.toLowerCase().includes(slashFilter) || c.id.toLowerCase().startsWith(slashFilter),
  );

  useEffect(() => {
    if (showSlashMenu && inputContainerRef.current) {
      const rect = inputContainerRef.current.getBoundingClientRect();
      setSlashMenuRect({ top: rect.top, left: rect.left, width: rect.width });
      setSlashPopOpen(false);
      const t = requestAnimationFrame(() => requestAnimationFrame(() => setSlashPopOpen(true)));
      return () => cancelAnimationFrame(t);
    } else {
      setSlashPopOpen(false);
      setSlashMenuRect(null);
    }
  }, [showSlashMenu]);

  const runSlashCommand = useCallback((id: string) => {
    setShowTargetDropdown(false);
    setInput((prev) => prev.replace(/\/[^/]*$/, ''));

    if (id === 'clear') {
      setMessages([]);
      setContextUsage(null);
    }
    inputRef.current?.focus();
  }, []);

  const contextUsed = contextUsage?.inputTokens ?? 0;
  const contextPercent = Math.min(100, (contextUsed / CONTEXT_WINDOW) * 100);

  const hasMessages = messages.length > 0;

  let pendingSuggestionIdx = -1;
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m.role === 'assistant' && m.suggestedCode && m.targetEditor && !m.accepted) {
      pendingSuggestionIdx = i;
      break;
    }
  }
  const pendingSuggestion = pendingSuggestionIdx >= 0 ? messages[pendingSuggestionIdx] : null;

  // Working proposal: use last suggested code as base for follow-ups (Cursor-style chaining)
  const workingProposalCompliance = (() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      const m = messages[i];
      if (m.role === 'assistant' && m.suggestedCode && m.targetEditor === 'compliance') return m.suggestedCode;
    }
    return null;
  })();
  const workingProposalPullRequest = (() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      const m = messages[i];
      if (m.role === 'assistant' && m.suggestedCode && m.targetEditor === 'pullRequest') return m.suggestedCode;
    }
    return null;
  })();
  const workingProposalProjectStatus = (() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      const m = messages[i];
      if (m.role === 'assistant' && m.suggestedCode && m.targetEditor === 'projectStatus') return m.suggestedCode;
    }
    return null;
  })();

  const isEdge = variant === 'edge';

  return (
    <div
      className={`flex flex-col min-h-0 flex-1 overflow-hidden ${
        isEdge
          ? 'bg-background'
          : 'w-[26rem] min-w-[26rem] flex-shrink-0 self-stretch ml-4 bg-background-card border border-border rounded-lg'
      }`}
    >
      {/* Header - minimal; no X when edge (close via backdrop) */}
      <div className={cn(
        'px-4 py-2 flex items-center flex-shrink-0 border-b border-border',
        'justify-between'
      )}>
        <span className="text-[13px] font-medium text-foreground">
          {statusCodeOnly ? 'Status code assistant' : 'Policy assistant'}
        </span>
        {!isEdge && (
          <button
            onClick={handleClose}
            className="h-6 w-6 rounded flex items-center justify-center text-foreground-muted hover:text-foreground hover:bg-background-subtle transition-colors"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>

      {/* Chat area */}
      <div className="flex-1 overflow-y-auto min-h-0 custom-scrollbar">
        {!hasMessages ? (
          <div className="px-5 pt-10 pb-6">
            <h3 className="text-lg font-semibold mb-1 text-foreground">
              {statusCodeOnly ? 'Status code assistant' : 'Policy assistant'}
            </h3>
            <p className="text-sm leading-relaxed mb-6 text-foreground-secondary">
              {statusCodeOnly
                ? 'Describe how projects should get their status. I generate projectStatus body code only — return { status, violations } using your org status names.'
                : `Describe your policy in plain English. I'll generate code for your ${TARGET_LABELS[targetEditor].toLowerCase()}.`}
            </p>
            <p className="text-xs font-medium uppercase tracking-wider mb-3 text-foreground-secondary">
              Suggestions
            </p>
            <div className="space-y-0.5">
              {SUGGESTIONS.filter((s) => s.target === targetEditor).map((s, i) => (
                <button
                  key={i}
                  onClick={() => handleSend(s.prompt, s.target)}
                  className="w-full text-left py-2 px-1 -mx-1 text-sm text-foreground-secondary hover:text-foreground/90 rounded transition-colors"
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="px-4 py-4 space-y-5">
            {messages.map((msg, idx) => (
              <div key={idx}>
                {msg.role === 'user' ? (
                  <div className="flex gap-3 items-start">
                    <Avatar className="h-7 w-7 flex-shrink-0 -mt-[3px]">
                      <AvatarImage src={avatarUrl} alt="" />
                      <AvatarFallback className="text-[10px] bg-background-subtle flex items-center justify-center">
                        {fullName?.trim().slice(0, 2).toUpperCase() || <User className="h-3.5 w-3.5" />}
                      </AvatarFallback>
                    </Avatar>
                    <p className="text-sm leading-[1.5] text-foreground flex-1 min-w-0">{msg.content}</p>
                  </div>
                ) : (
                  <div className="flex-1 min-w-0 space-y-3">
                    {msg.content && (
                      <div className="text-foreground">
                        {renderAISupabaseStyle(msg.content)}
                      </div>
                    )}
                    {isStreaming && idx === messages.length - 1 && !msg.suggestedCode && (
                      <p className="text-sm text-foreground-secondary flex items-center gap-1.5 animate-thinking-whole">
                        <Brain className="h-3.5 w-3.5 shrink-0" />
                        <span>Thinking...</span>
                      </p>
                    )}
                      {msg.suggestedCode && msg.targetEditor && (
                        <PolicyAssistantDiffBlock
                          targetEditor={msg.targetEditor}
                          baseCode={msg.baseCodeAtSuggestion ?? getCurrentCode(msg.targetEditor)}
                          requestedCode={msg.suggestedCode}
                        />
                      )}
                    </div>
                )}
              </div>
            ))}
            <div ref={chatEndRef} />
          </div>
        )}
      </div>

      {/* Footer - Accept bar + input; bar is compact, Accept only */}
      <div className="px-3 pb-3 pt-0 flex-shrink-0 flex flex-col gap-0">
        {pendingSuggestion && pendingSuggestionIdx >= 0 && (
          <div className="mx-[14px] rounded-t-lg border border-b-0 border-border px-2 py-1.5 flex items-center justify-end gap-2 bg-background-card shadow-sm shrink-0">
            <button
              onClick={handleAccept}
              className="h-5 px-2 text-[11px] rounded-md bg-primary text-primary-foreground hover:bg-primary/90"
            >
              Accept
            </button>
          </div>
        )}
        <div
          ref={inputContainerRef}
          className={cn(
            'relative flex flex-col overflow-hidden border border-border bg-background-card shadow-sm rounded-lg',
            ''
          )}
        >
          {showSlashMenu && slashMenuRect != null && createPortal(
            <div
              className={cn(
                'fixed z-[9999] py-1 rounded-lg border border-border bg-background-card shadow-lg max-h-48 overflow-y-auto transition-all duration-150',
                slashPopOpen ? 'opacity-100' : 'opacity-0',
              )}
              style={{
                top: slashMenuRect.top,
                left: slashMenuRect.left + 16,
                width: slashMenuRect.width - 32,
                transform: 'translateY(calc(-100% - 8px))',
              }}
            >
              <p className="px-3 py-1.5 text-[11px] font-medium text-foreground-secondary uppercase tracking-wider">Commands</p>
              {slashOptions.length === 0 ? (
                <p className="px-3 py-2 text-sm text-muted-foreground">No match</p>
              ) : (
                slashOptions.map((cmd) => (
                  <button
                    key={cmd.id}
                    type="button"
                    onClick={() => runSlashCommand(cmd.id)}
                    className="w-full flex items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-table-hover transition-colors"
                  >
                    <span className="text-muted-foreground flex-shrink-0">{cmd.icon}</span>
                    <div className="min-w-0">
                      <span className="font-medium">{cmd.label}</span>
                      <span className="text-muted-foreground text-xs block truncate">{cmd.description}</span>
                    </div>
                  </button>
                ))
              )}
            </div>,
            document.body,
          )}
          <textarea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Describe what your policy should do... (type / for commands)"
            rows={1}
            disabled={isStreaming}
            className="w-full resize-none px-4 pt-4 pb-24 text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-0 focus:border-0 disabled:opacity-50 min-h-[88px] border-0 bg-transparent overflow-hidden"
            style={{ minHeight: INPUT_MIN_HEIGHT_PX }}
          />
          {/* Dropdown, context circle, and send inside the input area — extra pt so text doesn’t sit flush above the bar */}
          <div className="absolute bottom-0 left-0 right-0 flex items-center justify-between px-3 pt-4 pb-2.5 gap-2 border-t border-border bg-background-card">
            {!statusCodeOnly && (
            <div className="relative" ref={dropdownRef}>
              <button
                type="button"
                onClick={() => {
                  if (!showTargetDropdown && dropdownRef.current) {
                    const r = dropdownRef.current.getBoundingClientRect();
                    setTargetDropdownRect({ left: r.left, top: r.top, width: r.width });
                  }
                  setShowTargetDropdown((prev) => !prev);
                }}
                className="flex items-center gap-1.5 min-h-9 px-3 py-1.5 rounded-md text-sm text-foreground-secondary hover:text-foreground hover:bg-background-card border border-border bg-background-card transition-colors"
              >
                <span className="truncate">{TARGET_LABELS[targetEditor]}</span>
                <ChevronDown className="h-3.5 w-3.5 opacity-70 shrink-0" />
              </button>
              {/* Portaled so overflow-hidden on input container doesn’t clip the menu */}
              {showTargetDropdown && targetDropdownRect != null && createPortal(
                <div
                  ref={targetDropdownMenuRef}
                  className="fixed z-[9998] min-w-[12rem] rounded-lg border border-border bg-background-card shadow-lg py-1"
                  style={{
                    left: targetDropdownRect.left,
                    bottom: typeof window !== 'undefined' ? window.innerHeight - targetDropdownRect.top + 8 : undefined,
                    width: Math.max(targetDropdownRect.width, 192),
                  }}
                >
                  {(Object.keys(TARGET_LABELS) as TargetEditor[]).map((key) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => {
                        setTargetEditor(key);
                        setShowTargetDropdown(false);
                        setTargetDropdownRect(null);
                      }}
                      className={cn(
                        'w-full text-left px-3 py-2.5 text-sm transition-colors whitespace-normal',
                        targetEditor === key
                          ? 'text-foreground bg-table-hover'
                          : 'text-foreground-secondary hover:text-foreground hover:bg-table-hover'
                      )}
                    >
                      {TARGET_LABELS[key]}
                    </button>
                  ))}
                </div>,
                document.body,
              )}
            </div>
            )}
            {statusCodeOnly && (
              <span
                className="inline-flex items-center min-h-9 px-3 py-1.5 rounded-md text-xs font-medium text-foreground-secondary bg-background-card border border-border shadow-sm cursor-default select-none shrink-0"
                aria-hidden
              >
                Project Status
              </span>
            )}
            <div className="flex items-center gap-1.5 ml-auto">
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="flex items-center justify-center shrink-0 h-6 w-6" aria-label="Context usage">
                    <svg className="h-5 w-5 -rotate-90 text-foreground-muted" viewBox="0 0 20 20">
                      <circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" strokeWidth="2" className="text-border" />
                      <circle
                        cx="10"
                        cy="10"
                        r="8"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeDasharray={`${(contextPercent / 100) * 50.3} 50.3`}
                        strokeLinecap="round"
                        className="text-foreground-muted transition-all duration-300"
                      />
                    </svg>
                  </div>
                </TooltipTrigger>
                <TooltipContent side="top" className="text-xs">
                  {contextUsed > 0
                    ? `${contextPercent.toFixed(1)}% of context used (${contextUsed.toLocaleString()} input tokens)`
                    : 'Context usage will appear after a response'}
                </TooltipContent>
              </Tooltip>
              <button
                type="button"
                onClick={() => handleSend()}
                disabled={!input.trim() || isStreaming}
                className={cn(
                  'h-8 w-8 rounded-full flex items-center justify-center transition-all shrink-0',
                  !input.trim() || isStreaming
                    ? 'bg-primary/25 text-primary/80 border border-primary/40 cursor-not-allowed'
                    : 'bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40'
                )}
              >
                <ArrowUp className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
