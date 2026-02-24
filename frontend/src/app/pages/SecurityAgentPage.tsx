import { useState, useEffect, useRef } from 'react';
import { useParams, useOutletContext } from 'react-router-dom';
import { MessageSquare, Activity, Zap, Inbox, Send } from 'lucide-react';
import { api, Organization, AegisMessage } from '../../lib/api';

interface OrganizationContextType {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

type Tab = 'chat' | 'automations' | 'inbox' | 'activity';

export default function SecurityAgentPage() {
  const { id } = useParams<{ id: string }>();
  const [aegisEnabled, setAegisEnabled] = useState<boolean | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('chat');
  const [messages, setMessages] = useState<AegisMessage[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [currentThreadId, setCurrentThreadId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (id) {
      checkAegisStatus();
    }
  }, [id]);

  useEffect(() => {
    if (activeTab === 'chat' && id && aegisEnabled) {
      loadOrCreateThread();
    }
  }, [activeTab, id, aegisEnabled]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const loadOrCreateThread = async () => {
    if (!id) return;
    try {
      const threads = await api.getAegisThreads(id);
      if (threads.length > 0) {
        const thread = threads[0];
        setCurrentThreadId(thread.id);
        const threadMessages = await api.getAegisThreadMessages(thread.id);
        setMessages(threadMessages);
      } else {
        // Create a new thread
        const newThread = await api.createAegisThread(id);
        setCurrentThreadId(newThread.id);
        setMessages([]);
      }
    } catch (error) {
      console.error('Failed to load thread:', error);
    }
  };

  const handleSendMessage = async () => {
    if (!inputMessage.trim() || !id || isLoading) return;

    const userMessage = inputMessage.trim();
    setInputMessage('');
    setIsLoading(true);

    // Add user message optimistically
    const tempUserMessage: AegisMessage = {
      id: `temp-${Date.now()}`,
      thread_id: currentThreadId || '',
      role: 'user',
      content: userMessage,
      metadata: {},
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, tempUserMessage]);

    try {
      const response = await api.sendAegisMessage(id, currentThreadId, userMessage);
      
      // Update thread ID if we got a new one
      if (response.threadId && response.threadId !== currentThreadId) {
        setCurrentThreadId(response.threadId);
      }

      // Extract just the message text from the response
      let messageText = '';
      if (typeof response.message === 'string') {
        messageText = response.message;
      } else if (response.message && typeof response.message === 'object' && (response.message as { message?: unknown }).message) {
        const msg = (response.message as { message: unknown }).message;
        messageText = typeof msg === 'string' ? msg : JSON.stringify(msg);
      } else {
        messageText = JSON.stringify(response.message);
      }

      // Reload messages to get the actual saved ones (this will include both user and assistant messages)
      if (response.threadId) {
        // Small delay to ensure messages are saved
        setTimeout(async () => {
          try {
            const threadMessages = await api.getAegisThreadMessages(response.threadId);
            setMessages(threadMessages);
          } catch (error) {
            console.error('Failed to reload messages:', error);
            // Fallback: add assistant message manually if reload fails
            const assistantMessage: AegisMessage = {
              id: `temp-assistant-${Date.now()}`,
              thread_id: response.threadId,
              role: 'assistant',
              content: messageText,
              metadata: response.type === 'action' ? { action: response.action, result: response.result } : {},
              created_at: new Date().toISOString(),
            };
            setMessages((prev) => {
              // Remove temp messages and add the real ones
              const withoutTemp = prev.filter((msg) => !msg.id.startsWith('temp-'));
              return [...withoutTemp, assistantMessage];
            });
          }
        }, 300);
      } else {
        // If no threadId, add assistant message directly
        const assistantMessage: AegisMessage = {
          id: `temp-assistant-${Date.now()}`,
          thread_id: '',
          role: 'assistant',
          content: messageText,
          metadata: response.type === 'action' ? { action: response.action, result: response.result } : {},
          created_at: new Date().toISOString(),
        };
        setMessages((prev) => [...prev, assistantMessage]);
      }
    } catch (error: any) {
      console.error('Failed to send message:', error);
      // Remove the optimistic messages on error
      setMessages((prev) => prev.filter((msg) => !msg.id.startsWith('temp-')));
    } finally {
      setIsLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const checkAegisStatus = async () => {
    if (!id) return;
    try {
      const status = await api.getAegisStatus(id);
      setAegisEnabled(status.enabled);
    } catch (error: any) {
      console.error('Failed to check Aegis status:', error);
      setAegisEnabled(false);
    }
  };

  if (aegisEnabled === null) {
    return (
      <div className="bg-background flex items-center justify-center min-h-[calc(100vh-200px)]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="bg-background flex absolute inset-0 top-[105px]">
      {/* Left Sidebar */}
      <div className="w-64 border-r border-border bg-background flex-shrink-0 flex flex-col h-full">
        <div className="p-4 flex-shrink-0">
          <h2 className="text-sm font-semibold text-foreground mb-4">Aegis</h2>
          <nav className="space-y-1">
            <button
              onClick={() => setActiveTab('chat')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === 'chat'
                  ? 'text-foreground'
                  : 'text-foreground-secondary hover:text-foreground'
              }`}
            >
              <MessageSquare className="h-4 w-4" />
              Chat
            </button>
            <button
              onClick={() => setActiveTab('automations')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === 'automations'
                  ? 'text-foreground'
                  : 'text-foreground-secondary hover:text-foreground'
              }`}
            >
              <Zap className="h-4 w-4" />
              Automations
            </button>
            <button
              onClick={() => setActiveTab('inbox')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === 'inbox'
                  ? 'text-foreground'
                  : 'text-foreground-secondary hover:text-foreground'
              }`}
            >
              <Inbox className="h-4 w-4" />
              Inbox
            </button>
            <button
              onClick={() => setActiveTab('activity')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === 'activity'
                  ? 'text-foreground'
                  : 'text-foreground-secondary hover:text-foreground'
              }`}
            >
              <Activity className="h-4 w-4" />
              Activity
            </button>
          </nav>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {activeTab === 'chat' && (
          <>
            {/* Messages Area */}
            <div className="flex-1 overflow-y-auto">
              <div className="mx-auto w-full max-w-3xl px-4 py-8">
                {messages.length === 0 ? (
                  <div className="flex items-center justify-center h-full">
                    <div className="text-center">
                      <h2 className="text-2xl font-semibold text-foreground mb-2">Start a conversation with Aegis</h2>
                      <p className="text-foreground-secondary">Ask questions, request actions, or get help with your organization's security.</p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-6">
                    {messages.map((message) => {
                      // Safely extract content - handle both string and object cases
                      let displayContent = '';
                      if (typeof message.content === 'string') {
                        // Check if it's a JSON string that needs parsing
                        try {
                          const parsed = JSON.parse(message.content);
                          // If it's an object with a 'message' field, extract that
                          if (parsed && typeof parsed === 'object' && parsed.message) {
                            displayContent = typeof parsed.message === 'string' ? parsed.message : JSON.stringify(parsed.message);
                          } else {
                            displayContent = message.content;
                          }
                        } catch {
                          // Not JSON, use as-is
                          displayContent = message.content;
                        }
                      } else if (message.content && typeof message.content === 'object') {
                        // If it's an object with a 'message' field, extract that
                        const contentMsg = (message.content as { message?: unknown }).message;
                        if (contentMsg !== undefined && contentMsg !== null) {
                          displayContent = typeof contentMsg === 'string' ? contentMsg : JSON.stringify(contentMsg);
                        } else {
                          displayContent = JSON.stringify(message.content, null, 2);
                        }
                      } else {
                        displayContent = String(message.content || '');
                      }

                      return (
                        <div
                          key={message.id}
                          className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                        >
                          <div
                            className={`max-w-[85%] rounded-lg px-4 py-3 ${
                              message.role === 'user'
                                ? 'bg-primary text-primary-foreground'
                                : 'bg-background-card border border-border text-foreground'
                            }`}
                          >
                            <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">{displayContent}</p>
                            {message.metadata && Object.keys(message.metadata).length > 0 && message.role === 'assistant' && (
                              <div className="mt-2 pt-2 border-t border-border/50">
                                {message.metadata.action && (
                                  <p className="text-xs text-foreground-secondary">
                                    Action: <span className="font-mono">{message.metadata.action}</span>
                                  </p>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                    {isLoading && (
                      <div className="flex justify-start">
                        <div className="bg-background-card border border-border rounded-lg px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
                            <span className="text-foreground-secondary">Aegis is thinking...</span>
                          </div>
                        </div>
                      </div>
                    )}
                    <div ref={messagesEndRef} />
                  </div>
                )}
              </div>
            </div>

            {/* Input Area */}
            <div className="border-t border-border bg-background">
              <div className="mx-auto w-full max-w-3xl px-4 py-4">
                <div className="flex items-center gap-2">
                  <div className="flex-1 relative">
                    <textarea
                      ref={inputRef}
                      value={inputMessage}
                      onChange={(e) => setInputMessage(e.target.value)}
                      onKeyPress={handleKeyPress}
                      placeholder="Message Aegis..."
                      rows={1}
                      className="w-full px-4 py-3 bg-background-card border border-border rounded-lg text-foreground placeholder:text-foreground-secondary resize-none focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                      style={{
                        minHeight: '48px',
                        maxHeight: '200px',
                        lineHeight: '1.5',
                      }}
                      onInput={(e) => {
                        const target = e.target as HTMLTextAreaElement;
                        target.style.height = 'auto';
                        target.style.height = `${Math.min(target.scrollHeight, 200)}px`;
                      }}
                    />
                  </div>
                  <button
                    onClick={handleSendMessage}
                    disabled={!inputMessage.trim() || isLoading}
                    className="flex items-center justify-center w-[48px] h-[48px] rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex-shrink-0"
                  >
                    <Send className="h-5 w-5" />
                  </button>
                </div>
              </div>
            </div>
          </>
        )}
        {activeTab !== 'chat' && (
          <div className="flex-1 overflow-y-auto">
            <div className="mx-auto w-full max-w-7xl px-6 py-8">
              {activeTab === 'automations' && (
                <div>
                  <h1 className="text-3xl font-bold text-foreground mb-4">Automations</h1>
                  <p className="text-foreground-secondary">Automations interface coming soon...</p>
                </div>
              )}
              {activeTab === 'inbox' && (
                <div>
                  <h1 className="text-3xl font-bold text-foreground mb-4">Inbox</h1>
                  <p className="text-foreground-secondary">Inbox interface coming soon...</p>
                </div>
              )}
              {activeTab === 'activity' && (
                <div>
                  <h1 className="text-3xl font-bold text-foreground mb-4">Activity</h1>
                  <p className="text-foreground-secondary">Activity interface coming soon...</p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
