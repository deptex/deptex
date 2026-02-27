import { useState, useRef, useEffect, useCallback } from 'react';
import { ArrowUp, Check, X, Loader2, Bot, User } from 'lucide-react';
import { api } from '../lib/api';
import { cn } from '../lib/utils';
import { PolicyDiffViewer } from './PolicyDiffViewer';
import { Button } from './ui/button';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  suggestedCode?: string | null;
  accepted?: boolean;
}

interface NotificationAIAssistantProps {
  organizationId: string;
  currentCode: string;
  onUpdateCode: (code: string) => void;
  onClose: () => void;
  /** When true, hide the close button (e.g. when embedded in Create Rule sidebar) */
  embedded?: boolean;
  /** When 'inline', no header, minimal empty state – for embedding below code block in Create Rule sidebar */
  variant?: 'default' | 'inline';
}

const SUGGESTIONS: Array<{ label: string; prompt: string }> = [
  { label: 'Alert on high Depscore', prompt: 'Notify when Depscore is above 75.' },
  { label: 'npm production deps only', prompt: 'Only trigger for npm ecosystem and production environment.' },
  { label: 'Critical reachable vulnerabilities', prompt: 'Alert when a dependency has critical severity vulnerability that is reachable.' },
  { label: 'Block new deps with low OpenSSF score', prompt: 'Notify when a new dependency has OpenSSF score below 3.' },
];

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

export function NotificationAIAssistant({
  organizationId,
  currentCode,
  onUpdateCode,
  onClose,
  embedded = false,
  variant = 'default',
}: NotificationAIAssistantProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = useCallback(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const autoResizeTextarea = useCallback(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 160) + 'px';
  }, []);

  useEffect(() => {
    autoResizeTextarea();
  }, [input, autoResizeTextarea]);

  useEffect(() => {
    if (embedded) return;
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isStreaming) onClose();
    };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [embedded, isStreaming, onClose]);

  const handleSend = async (overrideMessage?: string) => {
    const msg = overrideMessage ?? input.trim();
    if (!msg || isStreaming) return;

    setInput('');
    if (!isInline) {
      const userMsg: ChatMessage = { role: 'user', content: msg };
      setMessages((prev) => [...prev, userMsg]);
    }
    setIsStreaming(true);

    const conversationHistory = isInline
      ? []
      : messages
          .filter((m) => m.role === 'user' || m.role === 'assistant')
          .map((m) => ({ role: m.role, content: m.content }));

    try {
      const response = await api.notificationRuleAIAssistStream(organizationId, {
        message: msg,
        currentCode,
        conversationHistory,
      });

      const reader = response.body?.getReader();
      if (!reader) throw new Error('No response stream');

      const decoder = new TextDecoder();
      let accumulated = '';
      let buffer = '';

      if (!isInline) {
        const streamingMsg: ChatMessage = { role: 'assistant', content: '' };
        setMessages((prev) => [...prev, streamingMsg]);
      }

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
              if (!isInline) {
                setMessages((prev) => {
                  const updated = [...prev];
                  const last = updated[updated.length - 1];
                  if (last?.role === 'assistant') {
                    updated[updated.length - 1] = { ...last, content: accumulated };
                  }
                  return updated;
                });
              }
            } else if (event.type === 'done') {
              const parsed = parseAIResponse(event.fullContent);
              if (isInline && parsed.code) {
                onUpdateCode(parsed.code);
              }
              if (!isInline) {
                setMessages((prev) => {
                  const updated = [...prev];
                  updated[updated.length - 1] = {
                    role: 'assistant',
                    content: parsed.message,
                    suggestedCode: parsed.code ?? undefined,
                    accepted: isInline && !!parsed.code,
                  };
                  return updated;
                });
              }
            } else if (event.type === 'error' && !isInline) {
              setMessages((prev) => {
                const updated = [...prev];
                updated[updated.length - 1] = {
                  role: 'assistant',
                  content: `Error: ${event.error}`,
                };
                return updated;
              });
            }
          } catch {
            /* skip malformed SSE lines */
          }
        }
      }
    } catch (err: any) {
      if (!isInline) {
        setMessages((prev) => [
          ...prev.filter((m) => !(m.role === 'assistant' && m.content === '')),
          {
            role: 'assistant',
            content: err.message?.includes('404') || err.message?.includes('Not found')
              ? 'Notification rule AI assist is not available yet. You can write the code manually in the editor.'
              : `Error: ${err.message || 'Failed to get response'}`,
          },
        ]);
      }
    } finally {
      setIsStreaming(false);
      inputRef.current?.focus();
    }
  };

  const handleAccept = (idx: number) => {
    const msg = messages[idx];
    if (!msg?.suggestedCode) return;

    onUpdateCode(msg.suggestedCode);

    setMessages((prev) => {
      const updated = [...prev];
      updated[idx] = { ...updated[idx], accepted: true };
      return updated;
    });
  };

  const handleReject = (idx: number) => {
    setMessages((prev) => {
      const updated = [...prev];
      updated[idx] = { ...updated[idx], suggestedCode: null };
      return updated;
    });
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const hasMessages = messages.length > 0;
  const isInline = variant === 'inline';

  return (
    <div className={cn('flex flex-col overflow-hidden', isInline ? 'flex-shrink-0 bg-background' : 'min-h-0 flex-1')}>
      {!isInline && (
        <div className="px-4 py-2 flex items-center justify-between flex-shrink-0 border-b border-border">
          <span className="text-[13px] font-medium text-foreground">Rule assistant</span>
          {!embedded && (
            <button
              onClick={onClose}
              className="h-6 w-6 rounded flex items-center justify-center text-foreground-muted hover:text-foreground hover:bg-background-subtle transition-colors"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      )}

      {!isInline && (
        <div className={cn('custom-scrollbar', 'flex-1 overflow-y-auto min-h-0')}>
          {!hasMessages ? (
            <div className="px-4 py-6">
              <div className="text-center mb-5">
                <p className="text-sm text-foreground-secondary leading-relaxed">
                  Describe when this rule should trigger. I&apos;ll generate the custom code for your notification rule.
                </p>
              </div>
              <div className="space-y-1.5">
                {SUGGESTIONS.map((s, i) => (
                  <button
                    key={i}
                    onClick={() => handleSend(s.prompt)}
                    className="w-full text-left px-3 py-2.5 rounded-md text-sm text-foreground bg-background-subtle/50 hover:bg-background-subtle border border-border transition-colors"
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
                    <div className="flex gap-3">
                      <div className="h-7 w-7 rounded-full bg-background-subtle flex items-center justify-center flex-shrink-0">
                        <User className="h-3.5 w-3.5 text-foreground-secondary" />
                      </div>
                      <div className="flex-1 min-w-0 pt-0.5">
                        <p className="text-sm text-foreground leading-[1.5]">{msg.content}</p>
                      </div>
                    </div>
                  ) : (
                    <div className="flex gap-3">
                      <div className="h-7 w-7 rounded-full bg-background-subtle border border-border flex items-center justify-center flex-shrink-0">
                        <Bot className="h-3.5 w-3.5 text-foreground-secondary" />
                      </div>
                      <div className="flex-1 min-w-0 space-y-3">
                        {msg.content && (
                          <p className="text-sm text-foreground-secondary leading-[1.55] whitespace-pre-wrap">
                            {msg.content}
                          </p>
                        )}
                        {isStreaming && idx === messages.length - 1 && !msg.suggestedCode && (
                          <div className="flex items-center gap-2 text-xs text-foreground-muted">
                            <Loader2 className="h-3 w-3 animate-spin" />
                            Generating...
                          </div>
                        )}
                        {msg.suggestedCode && !msg.accepted && (
                          <div className="rounded-lg overflow-hidden border border-border bg-background">
                            <div className="px-3 py-2 border-b border-border">
                              <span className="text-xs text-foreground-muted font-medium">Suggested code</span>
                            </div>
                            <PolicyDiffViewer
                              baseCode={currentCode}
                              requestedCode={msg.suggestedCode}
                              minHeight="80px"
                              className="text-[11px]"
                            />
                            <div className="px-3 py-2 border-t border-border flex items-center gap-2 bg-background-card">
                              <Button size="sm" onClick={() => handleAccept(idx)} className="h-7 px-3 text-xs gap-1.5">
                                <Check className="h-3 w-3" />
                                Accept
                              </Button>
                              <button
                                onClick={() => handleReject(idx)}
                                className="h-7 px-3 text-xs text-foreground-secondary hover:text-foreground hover:bg-background-subtle rounded-md transition-colors"
                              >
                                Reject
                              </button>
                            </div>
                          </div>
                        )}
                        {msg.accepted && (
                          <div className="flex items-center gap-2 text-xs text-success">
                            <Check className="h-3 w-3" />
                            Applied to editor
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>
          )}
        </div>
      )}

      <div className={isInline ? 'px-6 pb-4 flex-shrink-0' : 'p-3 flex-shrink-0 border-t border-border'}>
        {isInline ? (
          <div className="relative flex flex-col rounded-lg overflow-hidden border border-border shadow-sm" style={{ backgroundColor: '#0D0F12' }}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask AI to write the code"
              rows={1}
              disabled={isStreaming}
              className="w-full resize-none px-4 pt-2 pb-12 text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-0 focus:border-0 disabled:opacity-50 min-h-[44px] max-h-[160px] overflow-y-auto border-0 bg-transparent"
            />
            <div className="absolute bottom-0 left-0 right-0 flex items-center justify-end px-3 py-2 gap-2">
              <button
                type="button"
                onClick={() => handleSend()}
                disabled={!input.trim() || isStreaming}
                className={cn(
                  'h-8 w-8 rounded-full flex items-center justify-center shrink-0 transition-all',
                  !input.trim() || isStreaming
                    ? 'bg-primary/25 text-primary/80 border border-primary/40 cursor-not-allowed'
                    : 'bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40'
                )}
              >
                {isStreaming ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <ArrowUp className="h-4 w-4" />
                )}
              </button>
            </div>
          </div>
        ) : (
          <div className="relative flex items-end">
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Describe when this rule should trigger..."
              rows={1}
              disabled={isStreaming}
              className="w-full resize-none rounded-lg bg-background border border-border pl-3 pr-11 py-2.5 text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary disabled:opacity-50 min-h-[40px] max-h-24 overflow-y-auto"
            />
            <button
              type="button"
              onClick={() => handleSend()}
              disabled={!input.trim() || isStreaming}
              className="absolute right-1.5 bottom-1.5 h-7 w-7 rounded-md flex items-center justify-center text-foreground-muted hover:text-primary hover:bg-primary/10 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent disabled:hover:text-foreground-muted transition-colors"
            >
              {isStreaming ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <ArrowUp className="h-3.5 w-3.5" />
              )}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
