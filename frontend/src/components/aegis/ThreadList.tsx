import { useMemo, useState, type KeyboardEvent } from 'react';
import { MoreHorizontal, SquarePen, Search, Pencil, Trash2, Loader2, Pin, PinOff, Archive, ArchiveRestore, Clock, ChevronRight } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '../ui/dialog';
import { Button } from '../ui/button';
import { cn } from '../../lib/utils';
import type { AegisThread } from '../../lib/aegis-api';

interface ThreadListProps {
  threads: AegisThread[];
  activeThreadId: string | null;
  loading?: boolean;
  pendingTitleThreadId?: string | null;
  onCreate: () => void;
  onSelect: (threadId: string) => void;
  onRename: (threadId: string, title: string) => Promise<void>;
  onDelete: (threadId: string) => Promise<void>;
  onSetPinned: (threadId: string, pinned: boolean) => Promise<void>;
  onSetArchived: (threadId: string, archived: boolean) => Promise<void>;
  onOpenSearch: () => void;
}

export function ThreadList({
  threads,
  activeThreadId,
  loading,
  pendingTitleThreadId,
  onCreate,
  onSelect,
  onRename,
  onDelete,
  onSetPinned,
  onSetArchived,
  onOpenSearch,
}: ThreadListProps) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draftTitle, setDraftTitle] = useState('');
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [archivedOpen, setArchivedOpen] = useState(false);

  const { pinned, recents, archived } = useMemo(() => {
    const pinned = threads.filter((t) => t.pinnedAt && !t.archivedAt);
    const recents = threads.filter((t) => !t.pinnedAt && !t.archivedAt);
    const archived = threads.filter((t) => !!t.archivedAt);
    pinned.sort((a, b) => (b.pinnedAt ?? '').localeCompare(a.pinnedAt ?? ''));
    recents.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    archived.sort((a, b) => (b.archivedAt ?? '').localeCompare(a.archivedAt ?? ''));
    return { pinned, recents, archived };
  }, [threads]);

  const renderRow = (thread: AegisThread) => {
    const isActive = thread.id === activeThreadId;
    const isEditing = thread.id === editingId;
    const isPinned = !!thread.pinnedAt;
    const isArchived = !!thread.archivedAt;
    const isPending = thread.id === pendingTitleThreadId;
    return (
      <div
        key={thread.id}
        className={cn(
          'group relative rounded-md',
          isActive && !isPending ? 'bg-white/[0.06]' : 'hover:bg-white/[0.04]',
        )}
      >
        {isEditing ? (
          <input
            autoFocus
            value={draftTitle}
            onChange={(e) => setDraftTitle(e.target.value)}
            onBlur={commitRename}
            onKeyDown={onEditKeyDown}
            className="w-full bg-background-subtle px-3 py-2 text-sm text-foreground outline-none rounded-md ring-1 ring-border focus:ring-foreground/30"
          />
        ) : (
          <button
            type="button"
            onClick={() => onSelect(thread.id)}
            className="w-full text-left px-3 py-2 text-sm truncate pr-8 flex items-center gap-2 text-foreground/90"
            title={thread.title}
          >
            {thread.id === pendingTitleThreadId
              ? <span className="h-3 w-40 rounded bg-foreground/10 animate-pulse inline-block" />
              : <span className="truncate">{thread.title}</span>
            }

          </button>
        )}
        {!isEditing && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6 flex items-center justify-center rounded text-foreground/60 hover:text-foreground opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity"
                onClick={(e) => e.stopPropagation()}
                aria-label="Thread actions"
              >
                <MoreHorizontal className="h-4 w-4" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-40">
              {thread.isCreator && (
                <DropdownMenuItem onClick={() => beginRename(thread)}>
                  <Pencil className="h-4 w-4 mr-2" />
                  Rename
                </DropdownMenuItem>
              )}
              <DropdownMenuItem onClick={() => void onSetPinned(thread.id, !isPinned)}>
                {isPinned ? <PinOff className="h-4 w-4 mr-2" /> : <Pin className="h-4 w-4 mr-2" />}
                {isPinned ? 'Unpin' : 'Pin'}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => void onSetArchived(thread.id, !isArchived)}>
                {isArchived ? <ArchiveRestore className="h-4 w-4 mr-2" /> : <Archive className="h-4 w-4 mr-2" />}
                {isArchived ? 'Unarchive' : 'Archive'}
              </DropdownMenuItem>
              {thread.isCreator && (
                <DropdownMenuItem
                  className="text-red-500 focus:text-red-500"
                  onClick={() => setConfirmDeleteId(thread.id)}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Delete
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
    );
  };

  const beginRename = (thread: AegisThread) => {
    setEditingId(thread.id);
    setDraftTitle(thread.title);
  };

  const commitRename = () => {
    if (!editingId) return;
    const title = draftTitle.trim();
    const id = editingId;
    setEditingId(null);
    if (!title) return;
    // Optimistic — fire and forget; AegisPage already updates state optimistically.
    void onRename(id, title);
  };

  const onEditKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') { e.preventDefault(); commitRename(); }
    else if (e.key === 'Escape') { e.preventDefault(); setEditingId(null); }
  };

  const confirmDelete = async () => {
    if (!confirmDeleteId) return;
    const id = confirmDeleteId;
    setDeleting(true);
    try {
      await onDelete(id);
      setConfirmDeleteId(null);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="px-2 pt-3 pb-1 space-y-1">
        <button
          type="button"
          onClick={onCreate}
          className="w-full flex items-center gap-2 rounded-md px-3 py-2 text-sm text-foreground/90 hover:bg-background-subtle/60 transition-colors"
        >
          <SquarePen className="h-4 w-4" />
          New chat
        </button>
        <button
          type="button"
          onClick={onOpenSearch}
          className="w-full flex items-center gap-2 rounded-md px-3 py-2 text-sm text-foreground/90 hover:bg-background-subtle/60 transition-colors"
        >
          <Search className="h-4 w-4" />
          Search chats
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-2 pb-2">
        {loading && threads.length === 0 && (
          <>
            <div className="px-3 pt-3 pb-1 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-foreground/60">
              <Clock className="h-3 w-3" />
              Recents
            </div>
            <div className="space-y-0.5">
              {[160, 112, 144, 96, 128].map((w, i) => (
                <div key={i} className="px-3 py-2" style={{ opacity: 1 - i * 0.18 }}>
                  <div
                    className="h-3 rounded bg-foreground/[0.08] animate-pulse"
                    style={{ width: w, animationDelay: `${i * 80}ms` }}
                  />
                </div>
              ))}
            </div>
          </>
        )}

        {pinned.length > 0 && (
          <>
            <div className="px-3 pt-3 pb-1 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-foreground/60">
              <Pin className="h-3 w-3" />
              Pinned
            </div>
            <div className="space-y-0.5">
              {pinned.map((t) => renderRow(t))}
            </div>
          </>
        )}

        {recents.length > 0 && (
          <>
            <div className="px-3 pt-3 pb-1 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-foreground/60">
              <Clock className="h-3 w-3" />
              Recents
            </div>
            <div className="space-y-0.5">
              {recents.map((t) => renderRow(t))}
            </div>
          </>
        )}

        {archived.length > 0 && (
          <>
            <button
              type="button"
              onClick={() => setArchivedOpen((o) => !o)}
              className="w-full px-3 pt-3 pb-1 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-foreground/40 hover:text-foreground/60 transition-colors"
            >
              <ChevronRight className={cn('h-3 w-3 transition-transform', archivedOpen && 'rotate-90')} />
              Archived
              <span className="ml-auto font-normal normal-case tracking-normal text-foreground/30">{archived.length}</span>
            </button>
            {archivedOpen && (
              <div className="space-y-0.5 opacity-70">
                {archived.map((t) => renderRow(t))}
              </div>
            )}
          </>
        )}

      </div>

      <Dialog open={!!confirmDeleteId} onOpenChange={(open) => !open && !deleting && setConfirmDeleteId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete chat?</DialogTitle>
            <DialogDescription>
              This will permanently delete the thread and its messages. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setConfirmDeleteId(null)} disabled={deleting}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmDelete} disabled={deleting}>
              {deleting ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Deleting…</> : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
