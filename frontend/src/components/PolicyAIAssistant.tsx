import { useState, useRef, useEffect, useCallback } from 'react';
import { ArrowUp, X, User, ChevronDown, Brain } from 'lucide-react';
import { api } from '../lib/api';
import { useUserProfile } from '../hooks/useUserProfile';
import { Avatar, AvatarImage, AvatarFallback } from './ui/avatar';
import { cn } from '../lib/utils';
import { PolicyDiffViewer, getDiffLineCounts } from './PolicyDiffViewer';

type TargetEditor = 'compliance' | 'pullRequest';

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
  complianceBody: string;
  pullRequestBody: string;
  onUpdateCompliance: (code: string) => void;
  onUpdatePullRequest: (code: string) => void;
  onClose: () => void;
  /** When 'edge', renders flush to container with dark theme, no X button. Use when fixed overlay sidebar. */
  variant?: 'inline' | 'edge';
}

const TARGET_LABELS: Record<TargetEditor, string> = {
  compliance: 'Project Compliance',
  pullRequest: 'Pull Request Check',
};

const SUGGESTIONS: Array<{ label: string; target: TargetEditor; prompt: string }> = [
  { label: 'Only allow MIT & Apache licenses', target: 'compliance', prompt: 'Make compliance pass only if every dependency uses MIT or Apache-2.0 license.' },
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
  complianceBody,
  pullRequestBody,
  onUpdateCompliance,
  onUpdatePullRequest,
  onClose,
  variant = 'inline',
}: PolicyAIAssistantProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [targetEditor, setTargetEditor] = useState<TargetEditor>('compliance');
  const [isStreaming, setIsStreaming] = useState(false);
  const [showTargetDropdown, setShowTargetDropdown] = useState(false);
  const { avatarUrl, fullName } = useUserProfile();
  const chatEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

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
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowTargetDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isStreaming) onClose();
    };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [isStreaming, onClose]);

  const handleSend = async (overrideMessage?: string, overrideTarget?: TargetEditor) => {
    const msg = overrideMessage ?? input.trim();
    const target = overrideTarget ?? targetEditor;
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

    try {
      const response = await api.policyAIAssistStream(organizationId, {
        message: msg,
        targetEditor: target,
        currentComplianceCode: baseCompliance,
        currentPullRequestCode: basePullRequest,
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
              const baseAtSuggestion = parsed.code ? (target === 'compliance' ? baseCompliance : basePullRequest) : undefined;
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
    if (pendingSuggestion.targetEditor === 'compliance') {
      onUpdateCompliance(pendingSuggestion.suggestedCode);
    } else {
      onUpdatePullRequest(pendingSuggestion.suggestedCode);
    }
    setMessages(prev =>
      prev.map(m =>
        m.suggestedCode ? { ...m, accepted: true } : m
      )
    );
  };

  const getCurrentCode = (target: TargetEditor) =>
    target === 'compliance' ? complianceBody : pullRequestBody;

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

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

  const isEdge = variant === 'edge';

  function DiffBlock({ targetEditor, baseCode, requestedCode }: { targetEditor: TargetEditor; baseCode: string; requestedCode: string }) {
    const { added, removed } = getDiffLineCounts(baseCode, requestedCode);
    return (
      <div className="rounded-lg overflow-hidden border border-border bg-background-card">
        <div className="px-3 py-2 border-b border-border flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-xs font-medium text-foreground">
              {TARGET_LABELS[targetEditor]}
            </span>
            {added > 0 && <span className="text-xs text-green-500">+{added}</span>}
            {removed > 0 && <span className="text-xs text-red-500">-{removed}</span>}
          </div>
        </div>
        <PolicyDiffViewer
          baseCode={baseCode}
          requestedCode={requestedCode}
          minHeight="80px"
          className="text-[11px]"
        />
      </div>
    );
  }

  return (
    <div
      className={`flex flex-col min-h-0 flex-1 overflow-hidden ${
        isEdge
          ? 'bg-background-card-header'
          : 'w-[26rem] min-w-[26rem] flex-shrink-0 self-stretch ml-4 bg-background-card border border-border rounded-lg'
      }`}
    >
      {/* Header - minimal; no X when edge (close via backdrop) */}
      <div className={cn(
        'px-4 py-2 flex items-center flex-shrink-0 border-b border-border',
        'justify-between'
      )}>
        <span className="text-[13px] font-medium text-foreground">Policy assistant</span>
        {!isEdge && (
          <button
            onClick={onClose}
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
              Policy assistant
            </h3>
            <p className="text-sm leading-relaxed mb-6 text-foreground-secondary">
              Describe your policy in plain English. I'll generate the code for your {TARGET_LABELS[targetEditor]} function.
            </p>
            <p className="text-xs font-medium uppercase tracking-wider mb-3 text-foreground-secondary">
              Suggestions
            </p>
            <div className="space-y-0.5">
              {SUGGESTIONS.filter((s) => s.target === targetEditor).map((s, i) => (
                <button
                  key={i}
                  onClick={() => handleSend(s.prompt, s.target)}
                  className="w-full text-left py-2 px-1 -mx-1 text-sm text-foreground-secondary hover:text-foreground hover:bg-table-hover rounded transition-colors"
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
                        <DiffBlock
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
          className={cn(
            'relative flex flex-col overflow-hidden border border-border bg-table-hover shadow-sm rounded-lg',
            ''
          )}
        >
          <textarea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Describe what your policy should do..."
            rows={3}
            disabled={isStreaming}
            className="w-full resize-none px-4 pt-4 pb-12 text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-0 focus:border-0 disabled:opacity-50 min-h-[88px] max-h-32 overflow-y-auto border-0 bg-transparent"
          />
          {/* Dropdown and send inside the input area */}
          <div className="absolute bottom-0 left-0 right-0 flex items-center justify-between px-3 py-2 gap-2 border-t border-border bg-table-hover">
            <div className="relative" ref={dropdownRef}>
              <button
                onClick={() => setShowTargetDropdown(prev => !prev)}
                className="flex items-center gap-1.5 h-8 px-3 rounded-md text-sm text-foreground-secondary hover:text-foreground hover:bg-background-card border border-border bg-background-card transition-colors"
              >
                {TARGET_LABELS[targetEditor]}
                <ChevronDown className="h-3.5 w-3.5 opacity-70" />
              </button>
              {showTargetDropdown && (
                <div className="absolute bottom-full left-0 mb-1 w-48 rounded-lg border border-border bg-background-card shadow-lg py-1 z-10">
                  {(Object.keys(TARGET_LABELS) as TargetEditor[]).map(key => (
                    <button
                      key={key}
                      onClick={() => { setTargetEditor(key); setShowTargetDropdown(false); }}
                      className={cn(
                        'w-full text-left px-3 py-2 text-sm transition-colors',
                        targetEditor === key
                          ? 'text-foreground bg-table-hover'
                          : 'text-foreground-secondary hover:text-foreground hover:bg-table-hover'
                      )}
                    >
                      {TARGET_LABELS[key]}
                    </button>
                  ))}
                </div>
              )}
            </div>
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
  );
}
