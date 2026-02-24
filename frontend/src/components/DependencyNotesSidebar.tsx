import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Trash2,
  SendHorizontal,
  Loader2,
  MessageSquareText,
  Bold,
  Link as LinkIcon,
  Smile,
  MoreHorizontal,
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import EmojiPicker, { type EmojiClickData, Theme } from 'emoji-picker-react';
import { DependencyNote, DependencyNoteReaction, api } from '../lib/api';
import { useAuth } from '../contexts/AuthContext';
import { useToast } from '../hooks/use-toast';
import { RoleBadge } from './RoleBadge';
import { Tooltip, TooltipTrigger, TooltipContent } from './ui/tooltip';
import { cn } from '../lib/utils';

interface DependencyNotesSidebarProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  organizationId: string;
  projectId: string;
  projectDependencyId: string;
  packageName: string;
  onNotesCountChange?: (count: number) => void;
}

const formatRelativeTime = (dateString: string | null): string => {
  if (!dateString) return '';
  const date = new Date(dateString);
  const now = new Date();
  const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (diffInSeconds < 60) return 'Just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
  if (diffInSeconds < 2592000) return `${Math.floor(diffInSeconds / 86400)}d ago`;
  if (diffInSeconds < 31536000) return `${Math.floor(diffInSeconds / 2592000)}mo ago`;
  return `${Math.floor(diffInSeconds / 31536000)}y ago`;
};

/** Format reaction tooltip: "Alice and you", "Alice, Bob and 2 others", etc. */
function formatReactionTooltip(r: DependencyNoteReaction): string {
  const names = r.reactor_names;
  if (!names?.length) {
    if (r.user_reacted && r.count === 1) return 'You reacted with';
    if (r.user_reacted && r.count === 2) return 'You and 1 other reacted with';
    if (r.user_reacted && r.count > 2) return `You and ${r.count - 1} others reacted with`;
    if (r.count === 1) return '1 person reacted with';
    return `${r.count} people reacted with`;
  }
  const sorted = [...names].sort((a, b) => (a === 'You' ? -1 : b === 'You' ? 1 : 0));
  if (sorted.length === 1) return `${sorted[0]} reacted with`;
  if (sorted.length === 2) return `${sorted[0]} and ${sorted[1]} reacted with`;
  if (sorted.length === 3) return `${sorted[0]}, ${sorted[1]} and ${sorted[2]} reacted with`;
  const firstTwo = sorted.slice(0, 2);
  const others = sorted.length - 2;
  return `${firstTwo.join(', ')} and ${others} other${others === 1 ? '' : 's'} reacted with`;
}

const TOOLBAR_WRAP = [
  { label: 'Bold', icon: Bold, prefix: '**', suffix: '**' },
  { label: 'Link', icon: LinkIcon, prefix: '[', suffix: '](link)', emptyPlaceholder: 'text' },
] as const;

export default function DependencyNotesSidebar({
  open,
  onOpenChange,
  organizationId,
  projectId,
  projectDependencyId,
  packageName,
  onNotesCountChange,
}: DependencyNotesSidebarProps) {
  const [notes, setNotes] = useState<DependencyNote[]>([]);
  const [loading, setLoading] = useState(false);
  const [fetched, setFetched] = useState(false);
  const [newNoteContent, setNewNoteContent] = useState('');
  const [posting, setPosting] = useState(false);
  const [actionNoteId, setActionNoteId] = useState<string | null>(null);
  const [emojiPickerNoteId, setEmojiPickerNoteId] = useState<string | null>(null);
  const [emojiPickerOpensUpward, setEmojiPickerOpensUpward] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const emojiPickerRef = useRef<HTMLDivElement>(null);
  const { user } = useAuth();
  const { toast } = useToast();

  // Fetch notes when the sidebar opens for the first time (use prefetched data if available)
  useEffect(() => {
    if (!open || fetched) return;
    setLoading(true);
    const prefetched = api.consumePrefetchedNotes(organizationId, projectId, projectDependencyId);
    const promise = prefetched ?? api.getDependencyNotes(organizationId, projectId, projectDependencyId);
    promise
      .then((res) => {
        setNotes(res.notes);
        onNotesCountChange?.(res.notes.length);
        setFetched(true);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [open, fetched, organizationId, projectId, projectDependencyId, onNotesCountChange]);

  // Reset when dependency changes
  useEffect(() => {
    setFetched(false);
    setNotes([]);
  }, [projectDependencyId]);

  // When emoji picker opens, measure space above vs below and choose direction so it doesn't get cut off
  useEffect(() => {
    if (!emojiPickerNoteId) return;
    const el = emojiPickerRef.current;
    if (!el) return;
    const raf = requestAnimationFrame(() => {
      const rect = el.getBoundingClientRect();
      const spaceAbove = rect.top;
      const spaceBelow = typeof window !== 'undefined' ? window.innerHeight - rect.bottom : 0;
      setEmojiPickerOpensUpward(spaceAbove >= spaceBelow);
    });
    return () => cancelAnimationFrame(raf);
  }, [emojiPickerNoteId]);

  // Close emoji picker when clicking outside
  useEffect(() => {
    if (!emojiPickerNoteId) return;
    const handleClick = (e: MouseEvent) => {
      if (emojiPickerRef.current && !emojiPickerRef.current.contains(e.target as Node)) {
        setEmojiPickerNoteId(null);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [emojiPickerNoteId]);

  const handlePostNote = async () => {
    if (!newNoteContent.trim()) return;
    setPosting(true);
    try {
      const created = await api.createDependencyNote(organizationId, projectId, projectDependencyId, {
        content: newNoteContent.trim(),
      });
      const updated = [created, ...notes];
      setNotes(updated);
      onNotesCountChange?.(updated.length);
      setNewNoteContent('');
      scrollRef.current?.scrollTo({ top: 0, behavior: 'smooth' });
    } catch {
      toast({ title: 'Error', description: 'Failed to post note' });
    } finally {
      setPosting(false);
    }
  };

  const handleDeleteNote = async (noteId: string) => {
    const noteToRestore = notes.find((n) => n.id === noteId);
    setNotes((prev) => prev.filter((n) => n.id !== noteId));
    onNotesCountChange?.(notes.length - 1);
    setActionNoteId(null);
    try {
      await api.deleteDependencyNote(organizationId, projectId, projectDependencyId, noteId);
    } catch {
      if (noteToRestore) {
        setNotes((prev) => [noteToRestore, ...prev].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()));
        onNotesCountChange?.(notes.length);
      }
      toast({ title: 'Error', description: 'Failed to delete note' });
    }
  };

  const handleAddReaction = async (noteId: string, emoji: string) => {
    setEmojiPickerNoteId(null);
    setActionNoteId(null);
    const pendingId = `pending-${noteId}-${emoji}-${Date.now()}`;
    setNotes((prev) =>
      prev.map((n) => {
        if (n.id !== noteId) return n;
        const reactions = n.reactions ?? [];
        const existing = reactions.find((r) => r.emoji === emoji);
        const nextReactions: DependencyNoteReaction[] = existing
          ? reactions.map((r) =>
              r.emoji === emoji ? { ...r, count: r.count + 1, user_reacted: true, reaction_id: pendingId } : r
            )
          : [...reactions, { emoji, count: 1, user_reacted: true, reaction_id: pendingId }];
        return { ...n, reactions: nextReactions };
      })
    );
    try {
      const created = await api.addNoteReaction(organizationId, projectId, projectDependencyId, noteId, emoji);
      setNotes((prev) =>
        prev.map((n) => {
          if (n.id !== noteId) return n;
          const reactions = (n.reactions ?? []).map((r) =>
            r.reaction_id === pendingId ? { ...r, reaction_id: created.id } : r
          );
          return { ...n, reactions };
        })
      );
    } catch {
      const res = await api.getDependencyNotes(organizationId, projectId, projectDependencyId).catch(() => null);
      if (res) setNotes(res.notes);
      toast({ title: 'Error', description: 'Failed to add reaction' });
    }
  };

  const handleRemoveReaction = async (noteId: string, reactionId: string) => {
    const isPending = reactionId.startsWith('pending-');
    setNotes((prev) =>
      prev.map((n) => {
        if (n.id !== noteId) return n;
        const reactions = (n.reactions ?? []).map((r) => {
          if (r.reaction_id !== reactionId) return r;
          if (r.count <= 1) return null;
          return { ...r, count: r.count - 1, user_reacted: false, reaction_id: null };
        });
        return { ...n, reactions: reactions.filter((r): r is DependencyNoteReaction => r !== null) };
      })
    );
    if (isPending) return;
    try {
      await api.removeNoteReaction(organizationId, projectId, projectDependencyId, noteId, reactionId);
    } catch {
      const res = await api.getDependencyNotes(organizationId, projectId, projectDependencyId).catch(() => null);
      if (res) setNotes(res.notes);
      toast({ title: 'Error', description: 'Failed to remove reaction' });
    }
  };

  const handleReactionClick = (note: DependencyNote, r: DependencyNoteReaction) => {
    if (r.user_reacted && r.reaction_id) {
      handleRemoveReaction(note.id, r.reaction_id);
    } else {
      handleAddReaction(note.id, r.emoji);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      handlePostNote();
    }
  };

  const autoExpandTextarea = useCallback(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 200)}px`;
  }, []);

  useEffect(() => {
    autoExpandTextarea();
  }, [newNoteContent, autoExpandTextarea]);

  const insertAtCursor = (prefix: string, suffix: string, emptyPlaceholder?: string) => {
    const el = textareaRef.current;
    if (!el) return;
    const start = el.selectionStart;
    const end = el.selectionEnd;
    const before = newNoteContent.slice(0, start);
    const selected = newNoteContent.slice(start, end);
    const after = newNoteContent.slice(end);
    const inner = selected || (emptyPlaceholder ?? '');
    const newText = `${before}${prefix}${inner}${suffix}${after}`;
    setNewNoteContent(newText);
    setTimeout(() => {
      el.focus();
      const selStart = start + prefix.length;
      const selEnd = selStart + inner.length;
      el.setSelectionRange(selEnd, selEnd);
      if (inner.length > 0) el.setSelectionRange(selStart, selEnd);
      autoExpandTextarea();
    }, 0);
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
        onClick={() => onOpenChange(false)}
        aria-hidden
      />
      <div
        className="fixed right-0 top-0 h-full w-full max-w-md bg-background border-l border-border shadow-2xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header — unified solid background, no X button */}
        <div className="flex items-center gap-2.5 min-w-0 px-5 pt-5 pb-4 border-b border-border shrink-0 bg-background">
          <MessageSquareText className="h-5 w-5 text-foreground-secondary shrink-0" />
          <div className="min-w-0">
            <h2 className="text-base font-semibold text-foreground truncate">Project notes</h2>
            <p className="text-xs text-foreground-secondary truncate mt-0.5">{packageName}</p>
          </div>
        </div>

        {/* Scrollable notes body */}
        <div ref={scrollRef} className="flex-1 overflow-y-auto px-5 py-4">
          {loading ? (
            <div className="space-y-4 animate-pulse">
              {[
                { nameW: 'w-20', line1: 'w-full', line2: 'w-4/5', line3: 'w-2/3', opacityClass: 'opacity-100' },
                { nameW: 'w-24', line1: 'w-full', line2: 'w-3/4', opacityClass: 'opacity-80' },
                { nameW: 'w-16', line1: 'w-full', line2: 'w-5/6', line3: 'w-1/2', opacityClass: 'opacity-60' },
                { nameW: 'w-24', line1: 'w-full', line2: 'w-2/3', opacityClass: 'opacity-45' },
                { nameW: 'w-20', line1: 'w-full', line2: 'w-4/5', line3: 'w-3/4', opacityClass: 'opacity-30' },
                { nameW: 'w-16', line1: 'w-full', line2: 'w-1/2', opacityClass: 'opacity-20' },
              ].map((row, i) => (
                <div
                  key={i}
                  className={cn('flex items-start gap-2.5 transition-opacity', row.opacityClass)}
                >
                  <div className="w-8 h-8 rounded-full bg-muted/80 shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0 space-y-2">
                    <div className="flex items-center gap-1.5">
                      <div className={cn('h-3.5 bg-muted/80 rounded', row.nameW)} />
                      <div className="h-3.5 w-12 bg-muted/80 rounded-full shrink-0" />
                    </div>
                    <div className="space-y-1.5">
                      <div className={cn('h-3 bg-muted/80 rounded', row.line1)} />
                      <div className={cn('h-3 bg-muted/80 rounded', row.line2)} />
                      {'line3' in row && row.line3 && (
                        <div className={cn('h-3 bg-muted/80 rounded', row.line3)} />
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : notes.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <MessageSquareText className="h-8 w-8 text-foreground-secondary/30 mb-3" />
              <p className="text-sm text-foreground-secondary">No notes yet</p>
              <p className="text-xs text-foreground-secondary/60 mt-1 max-w-[240px]">
                Add context about this dependency for your team.
              </p>
            </div>
          ) : (
            <div className="space-y-0">
              {notes.map((note) => {
                const canDelete = note.can_delete ?? note.author.id === user?.id;
                const showActions = actionNoteId === note.id;
                const showEmojiPicker = emojiPickerNoteId === note.id;
                const reactions = note.reactions || [];

                return (
                  <div
                    key={note.id}
                    className="group flex items-start gap-2.5 transition-[margin] duration-150 ease-out"
                    onMouseEnter={() => setActionNoteId(note.id)}
                    onMouseLeave={() => {
                      if (emojiPickerNoteId !== note.id) setActionNoteId(null);
                    }}
                  >
                    {note.author.avatar_url ? (
                      <img
                        src={note.author.avatar_url}
                        alt={note.author.name || 'User'}
                        className="w-8 h-8 rounded-full shrink-0 mt-0"
                      />
                    ) : (
                      <div className="w-8 h-8 rounded-full bg-primary/10 text-primary flex items-center justify-center text-xs font-semibold shrink-0 mt-0">
                        {(note.author.name || '?')[0].toUpperCase()}
                      </div>
                    )}

                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5 mb-0 flex-wrap">
                        <span className="text-sm font-semibold text-foreground">
                          {note.author.name || 'Unknown'}
                        </span>
                        {note.author.org_role && (
                          <RoleBadge
                            role={note.author.org_role}
                            roleDisplayName={note.author.org_role_display_name}
                            roleColor={note.author.org_role_color}
                            className="text-[10px] px-1.5 py-0"
                          />
                        )}
                        <span className="text-[11px] text-foreground-secondary/60 shrink-0">
                          {formatRelativeTime(note.created_at)}
                        </span>
                      </div>
                      {/* Note content with markdown — Slack-style muted gray */}
                      <div className="text-sm text-foreground-secondary leading-snug break-words prose prose-sm dark:prose-invert max-w-none prose-p:my-0 prose-ul:my-0.5 prose-ol:my-0.5 prose-li:my-0 prose-invert prose-p:text-foreground-secondary prose-li:text-foreground-secondary prose-strong:text-foreground">
                        <ReactMarkdown
                          remarkPlugins={[remarkGfm]}
                          urlTransform={(url) => url}
                          components={{
                            a: ({ href, children, ...props }) => {
                              // #region agent log
                              const _rawHref = href;
                              const isAbsolute = href?.startsWith('http://') || href?.startsWith('https://') || href?.startsWith('//') || href?.startsWith('mailto:') || href?.startsWith('tel:');
                              const targetUrl = href && !isAbsolute ? `https://${href.replace(/^\/+/, '')}` : (href ?? '#');
                              const isWebUrl = targetUrl.startsWith('http://') || targetUrl.startsWith('https://');
                              fetch('http://127.0.0.1:7243/ingest/abaca787-5416-40c4-b6fe-aea97fa8dfd8',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'05fb5b'},body:JSON.stringify({sessionId:'05fb5b',location:'DependencyNotesSidebar.tsx:link-render',message:'Link render',data:{rawHref:_rawHref,targetUrl,isWebUrl,propsHasHref:'href' in props,propsHasOnClick:'onClick' in props},timestamp:Date.now(),hypothesisId:'H1-H5'})}).catch(()=>{});
                              // #endregion
                              const handleClick = isWebUrl ? (e: React.MouseEvent<HTMLAnchorElement>) => {
                                // #region agent log
                                fetch('http://127.0.0.1:7243/ingest/abaca787-5416-40c4-b6fe-aea97fa8dfd8',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'05fb5b'},body:JSON.stringify({sessionId:'05fb5b',location:'DependencyNotesSidebar.tsx:link-click',message:'Link click handler',data:{targetUrl,isWebUrl},timestamp:Date.now(),hypothesisId:'H4',runId:'post-fix'})}).catch(()=>{});
                                // #endregion
                                e.preventDefault();
                                e.stopPropagation();
                                window.open(targetUrl, '_blank', 'noopener,noreferrer');
                              } : undefined;
                              return (
                                <a
                                  {...props}
                                  href={targetUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  onClick={handleClick}
                                >
                                  {children}
                                </a>
                              );
                            },
                          }}
                        >
                          {note.content}
                        </ReactMarkdown>
                      </div>
                      {/* Reactions row */}
                      {reactions.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          {reactions.map((r) => {
                            const key = `${note.id}-${r.emoji}`;
                            const reactedLabel = formatReactionTooltip(r);
                            return (
                              <Tooltip key={key}>
                                <TooltipTrigger asChild>
                                  <button
                                    type="button"
                                    onClick={() => handleReactionClick(note, r)}
                                    className={cn(
                                      'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs border transition-colors',
                                      r.user_reacted
                                        ? 'bg-primary/15 border-primary/30 text-foreground'
                                        : 'bg-muted/50 border-border/50 text-foreground-secondary hover:bg-muted'
                                    )}
                                  >
                                    <span>{r.emoji}</span>
                                    {r.count > 1 && <span>{r.count}</span>}
                                  </button>
                                </TooltipTrigger>
                                <TooltipContent
                                  side="top"
                                  sideOffset={6}
                                  className="relative rounded-lg px-4 py-3 text-center min-w-[200px] border border-border bg-background-card shadow-lg"
                                >
                                  <div className="text-3xl mb-1.5">{r.emoji}</div>
                                  <p className="text-xs text-foreground-secondary">
                                    {reactedLabel} {r.emoji}
                                  </p>
                                  <div
                                    className="absolute -bottom-1.5 left-1/2 -translate-x-1/2 w-0 h-0 border-[6px] border-transparent border-t-background-card"
                                    aria-hidden
                                  />
                                </TooltipContent>
                              </Tooltip>
                            );
                          })}
                        </div>
                      )}
                      {/* Action menu (hover / tap) — fixed min-height so list doesn't jump */}
                      <div className="relative mt-0.5 min-h-7 flex items-center gap-0.5">
                        {(showActions || showEmojiPicker) && (
                          <div className="flex items-center gap-0.5 rounded-md bg-background-subtle/80 p-0.5 shadow-sm border border-border/50 animate-in fade-in duration-150">
                            <div className="relative" ref={emojiPickerNoteId === note.id ? emojiPickerRef : undefined}>
                              <button
                                type="button"
                                onClick={() => setEmojiPickerNoteId((id) => (id === note.id ? null : note.id))}
                                className="flex items-center justify-center w-7 h-7 rounded text-foreground-secondary hover:text-foreground hover:bg-background-subtle"
                                title="Add reaction"
                              >
                                <Smile className="h-4 w-4" />
                              </button>
                              {showEmojiPicker && (
                                <div
                                  className={cn(
                                    'absolute left-0 z-50 rounded-xl border border-border bg-background-card shadow-xl overflow-hidden [&_.EmojiPickerReact]:!bg-transparent [&_.epr-dark-theme]:!bg-background-card',
                                    emojiPickerOpensUpward ? 'bottom-full mb-1' : 'top-full mt-1'
                                  )}
                                >
                                  <EmojiPicker
                                    theme={Theme.DARK}
                                    onEmojiClick={(data: EmojiClickData) => handleAddReaction(note.id, data.emoji)}
                                    reactionsDefaultOpen={true}
                                    allowExpandReactions={true}
                                    previewConfig={{ showPreview: false }}
                                    searchPlaceholder="Search emoji..."
                                    width={320}
                                    height={380}
                                    lazyLoadEmojis={true}
                                  />
                                </div>
                              )}
                            </div>
                            {canDelete && (
                              <button
                                type="button"
                                onClick={() => handleDeleteNote(note.id)}
                                className="flex items-center justify-center w-7 h-7 rounded text-foreground-secondary hover:text-destructive hover:bg-destructive/10"
                                title="Delete note"
                              >
                                <Trash2 className="h-4 w-4" />
                              </button>
                            )}
                          </div>
                        )}
                        {!showActions && !showEmojiPicker && (
                          <button
                            type="button"
                            onClick={() => setActionNoteId(note.id)}
                            className="opacity-0 group-hover:opacity-100 transition-opacity duration-150 flex items-center justify-center w-6 h-6 rounded text-foreground-secondary hover:text-foreground hover:bg-background-subtle"
                            title="More actions"
                          >
                            <MoreHorizontal className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Compose footer — unified bg-background, toolbar + auto-expanding input */}
        <div className="shrink-0 px-5 pt-0 pb-3 bg-background">
          <div className="relative rounded-lg border border-border bg-background-card overflow-hidden">
            {/* Formatting toolbar */}
            <div className="flex items-center gap-0.5 px-2 py-1.5 border-b border-border/50">
              {TOOLBAR_WRAP.map((item) => {
                const { label, icon: Icon, prefix, suffix } = item;
                const emptyPlaceholder = 'emptyPlaceholder' in item ? item.emptyPlaceholder : undefined;
                return (
                  <Tooltip key={label}>
                    <TooltipTrigger asChild>
                      <button
                        type="button"
                        onClick={() => insertAtCursor(prefix, suffix, emptyPlaceholder)}
                        className="flex items-center justify-center w-7 h-7 rounded text-foreground-secondary hover:text-foreground hover:bg-muted/50"
                      >
                        <Icon className="h-4 w-4" />
                      </button>
                    </TooltipTrigger>
                    <TooltipContent>{label}</TooltipContent>
                  </Tooltip>
                );
              })}
            </div>
            <textarea
              ref={textareaRef}
              value={newNoteContent}
              onChange={(e) => setNewNoteContent(e.target.value)}
              onKeyDown={handleKeyDown}
              onInput={autoExpandTextarea}
              placeholder="Write a note..."
              rows={2}
              className="w-full min-h-[60px] max-h-[200px] bg-transparent px-3 pt-2 pb-10 text-sm text-foreground placeholder:text-foreground-secondary/40 focus:outline-none focus:ring-0 border-0 resize-none"
              style={{ minHeight: '60px' }}
            />
            <div className="absolute bottom-1.5 right-1.5">
              <button
                onClick={handlePostNote}
                disabled={posting || !newNoteContent.trim()}
                className="flex items-center justify-center w-8 h-8 rounded-md transition-colors bg-primary text-primary-foreground hover:bg-primary/90 disabled:bg-transparent disabled:text-foreground-secondary disabled:hover:bg-transparent disabled:cursor-not-allowed"
              >
                {posting ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <SendHorizontal className="h-4 w-4" />
                )}
              </button>
            </div>
          </div>
          <p className="text-[10px] text-foreground-secondary/40 mt-1.5 text-right">
            Ctrl+Enter to send
          </p>
        </div>
      </div>
    </div>
  );
}
