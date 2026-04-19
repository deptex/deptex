import { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import { Sparkles, Send, Loader2 } from 'lucide-react';
import { cn } from '../../../lib/utils';

interface DocsAIAssistantProps {
  currentPage?: string;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
  sources?: { slug: string; title: string }[];
  isError?: boolean;
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';
const MAX_MESSAGES = 10;

export default function DocsAIAssistant({ currentPage }: DocsAIAssistantProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [panelVisible, setPanelVisible] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setPanelVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setPanelVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    }
  }, [isOpen]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    if (panelVisible) {
      inputRef.current?.focus();
    }
  }, [panelVisible]);

  const handleClose = useCallback(() => {
    setPanelVisible(false);
    setTimeout(() => {
      setIsOpen(false);
      setMessages([]);
      setInput('');
      setIsLoading(false);
    }, 150);
  }, []);

  const userMessageCount = messages.filter((m) => m.role === 'user').length;
  const limitReached = userMessageCount >= MAX_MESSAGES;

  const handleSend = useCallback(async () => {
    const trimmed = input.trim();
    if (!trimmed || isLoading || limitReached) return;

    const userMessage: Message = { role: 'user', content: trimmed };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const res = await fetch(`${API_BASE_URL}/api/docs-assistant`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: trimmed, currentPage }),
      });

      if (!res.ok) throw new Error(`Request failed (${res.status})`);

      const data = await res.json();
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: data.answer, sources: data.sources },
      ]);
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'Something went wrong';
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: errorMessage, isError: true },
      ]);
    } finally {
      setIsLoading(false);
    }
  }, [input, isLoading, limitReached, currentPage]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSend();
      }
    },
    [handleSend],
  );

  return (
    <>
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 z-40 flex items-center gap-2 px-4 py-2.5 rounded-full bg-primary text-primary-foreground shadow-lg hover:bg-primary/90 transition-all hover:shadow-xl border border-primary-foreground/20"
        >
          <Sparkles className="h-4 w-4" />
          <span className="text-sm font-medium">Ask AI</span>
        </button>
      )}

      {isOpen && (
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              panelVisible ? 'opacity-100' : 'opacity-0',
            )}
            onClick={handleClose}
          />

          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[420px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              panelVisible ? 'translate-x-0' : 'translate-x-full',
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0">
              <h2 className="text-xl font-semibold text-foreground flex items-center gap-2">
                <Sparkles className="h-5 w-5" />
                Ask AI
              </h2>
              <p className="text-sm text-foreground-secondary mt-1">
                Ask questions about Deptex
              </p>
            </div>

            <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">
              {messages.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full text-center gap-3">
                  <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
                    <Sparkles className="h-5 w-5 text-primary" />
                  </div>
                  <p className="text-sm text-foreground-secondary max-w-[260px]">
                    Ask anything about Deptex — features, setup, compliance, and
                    more.
                  </p>
                </div>
              )}

              <div className="space-y-4">
                {messages.map((msg, i) => (
                  <div
                    key={i}
                    className={cn(
                      'flex',
                      msg.role === 'user' ? 'justify-end' : 'justify-start',
                    )}
                  >
                    <div
                      className={cn(
                        'max-w-[85%] px-3.5 py-2.5 rounded-lg text-sm',
                        msg.role === 'user'
                          ? 'bg-primary/10 text-foreground'
                          : msg.isError
                            ? 'bg-destructive/10 text-destructive'
                            : 'bg-background-card text-foreground',
                      )}
                    >
                      {msg.role === 'assistant' && !msg.isError && (
                        <Sparkles className="h-3 w-3 text-foreground-secondary mb-1.5 inline-block mr-1.5" />
                      )}
                      <span className="whitespace-pre-wrap">{msg.content}</span>

                      {msg.sources && msg.sources.length > 0 && (
                        <div className="mt-2.5 pt-2 border-t border-border">
                          <p className="text-xs font-semibold text-foreground-secondary mb-1.5">
                            Sources
                          </p>
                          <div className="flex flex-col gap-1">
                            {msg.sources.map((source) => (
                              <Link
                                key={source.slug}
                                to={`/docs/${source.slug}`}
                                className="text-xs text-primary hover:underline truncate"
                                onClick={handleClose}
                              >
                                {source.title}
                              </Link>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ))}

                {isLoading && (
                  <div className="flex justify-start">
                    <div className="bg-background-card px-3.5 py-2.5 rounded-lg flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-foreground-secondary animate-bounce [animation-delay:0ms]" />
                      <span className="h-1.5 w-1.5 rounded-full bg-foreground-secondary animate-bounce [animation-delay:150ms]" />
                      <span className="h-1.5 w-1.5 rounded-full bg-foreground-secondary animate-bounce [animation-delay:300ms]" />
                    </div>
                  </div>
                )}

                <div ref={messagesEndRef} />
              </div>
            </div>

            <div className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header">
              {limitReached ? (
                <p className="text-xs text-foreground-secondary text-center py-1">
                  Message limit reached. Close and reopen to start a new
                  session.
                </p>
              ) : (
                <div className="flex items-center gap-2">
                  <input
                    ref={inputRef}
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask a question…"
                    disabled={isLoading}
                    className="flex-1 h-9 px-3 py-2.5 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:ring-2 focus:ring-primary/50 focus:border-primary outline-none disabled:opacity-50"
                  />
                  <button
                    onClick={handleSend}
                    disabled={isLoading || !input.trim()}
                    className="h-9 w-9 flex items-center justify-center rounded-md bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 disabled:opacity-50 disabled:pointer-events-none transition-colors"
                  >
                    {isLoading ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Send className="h-4 w-4" />
                    )}
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
