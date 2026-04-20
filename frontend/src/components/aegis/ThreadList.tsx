import { useMemo, useState, type KeyboardEvent } from 'react';
import { MoreHorizontal, SquarePen, Search, Pencil, Trash2, Loader2, Pin, PinOff, Archive, ArchiveRestore } from 'lucide-react';
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
  onCreate: () => void;
  onSelect: (threadId: string) => void;
  onRename: (threadId: string, title: string) => Promise<void>;
  onDelete: (threadId: string) => Promise<void>;
  onSetPinned: (threadId: string, pinned: boolean) => Promise<void>;
  onSetArchived: (threadId: string, archived: boolean) => Promise<void>;
}

export function ThreadList({
  threads,
  activeThreadId,
  loading,
  onCreate,
  onSelect,
  onRename,
  onDelete,
  onSetPinned,
  onSetArchived,
}: ThreadListProps) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draftTitle, setDraftTitle] = useState('');
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [query, setQuery] = useState('');

  const isSearching = query.trim().length > 0;

  const { pinned, recents, archivedMatches } = useMemo(() => {
    const q = query.trim().toLowerCase();
    const match = (t: AegisThread) => !q || t.title.toLowerCase().includes(q);
    const all = threads.filter(match);
    const pinned = all.filter((t) => t.pinnedAt && !t.archivedAt);
    const recents = all.filter((t) => !t.pinnedAt && !t.archivedAt);
    // Archived only surfaced while searching.
    const archivedMatches = q ? all.filter((t) => t.archivedAt) : [];
    // Pinned sort: most-recently pinned first. Recents: most-recently updated.
    pinned.sort((a, b) => (b.pinnedAt ?? '').localeCompare(a.pinnedAt ?? ''));
    recents.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    archivedMatches.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    return { pinned, recents, archivedMatches };
  }, [threads, query]);

  const totalVisible = pinned.length + recents.length + archivedMatches.length;

  const renderRow = (thread: AegisThread, opts?: { archivedBadge?: boolean }) => {
    const isActive = thread.id === activeThreadId;
    const isEditing = thread.id === editingId;
    const isPinned = !!thread.pinnedAt;
    const isArchived = !!thread.archivedAt;
    return (
      <div
        key={thread.id}
        className={cn(
          'group relative rounded-md',
          isActive ? 'bg-background-subtle' : 'hover:bg-background-subtle/60',
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
            className={cn(
              'w-full text-left px-3 py-2 text-sm truncate pr-8 flex items-center gap-2',
              opts?.archivedBadge ? 'text-foreground/60 italic' : 'text-foreground/90',
            )}
            title={thread.title}
          >
            <span className="truncate">{thread.title}</span>
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
              <DropdownMenuItem onClick={() => beginRename(thread)}>
                <Pencil className="h-4 w-4 mr-2" />
                Rename
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => void onSetPinned(thread.id, !isPinned)}>
                {isPinned ? <PinOff className="h-4 w-4 mr-2" /> : <Pin className="h-4 w-4 mr-2" />}
                {isPinned ? 'Unpin' : 'Pin'}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => void onSetArchived(thread.id, !isArchived)}>
                {isArchived ? <ArchiveRestore className="h-4 w-4 mr-2" /> : <Archive className="h-4 w-4 mr-2" />}
                {isArchived ? 'Unarchive' : 'Archive'}
              </DropdownMenuItem>
              <DropdownMenuItem
                className="text-red-500 focus:text-red-500"
                onClick={() => setConfirmDeleteId(thread.id)}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete
              </DropdownMenuItem>
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
        <div className="relative px-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-foreground/40 pointer-events-none" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search chats"
            className="w-full rounded-md bg-background-subtle/60 pl-8 pr-3 py-1.5 text-xs text-foreground placeholder:text-foreground/40 outline-none focus:bg-background-subtle"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-2 pb-2">
        {loading && threads.length === 0 && (
          <div className="space-y-1 px-1 py-2">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-8 rounded-md bg-background-subtle/50 animate-pulse" />
            ))}
          </div>
        )}
        {!loading && threads.length === 0 && (
          <p className="px-2 py-4 text-xs text-foreground/60">No chats yet.</p>
        )}
        {!loading && threads.length > 0 && totalVisible === 0 && (
          <p className="px-2 py-4 text-xs text-foreground/60">No matches.</p>
        )}

        {pinned.length > 0 && (
          <>
            <div className="px-3 pt-3 pb-1 text-[11px] font-medium uppercase tracking-wide text-foreground/40">
              Pinned
            </div>
            <div className="space-y-0.5">
              {pinned.map((t) => renderRow(t))}
            </div>
          </>
        )}

        {recents.length > 0 && (
          <>
            <div className="px-3 pt-3 pb-1 text-[11px] font-medium uppercase tracking-wide text-foreground/40">
              Recents
            </div>
            <div className="space-y-0.5">
              {recents.map((t) => renderRow(t))}
            </div>
          </>
        )}

        {isSearching && archivedMatches.length > 0 && (
          <>
            <div className="px-3 pt-3 pb-1 text-[11px] font-medium uppercase tracking-wide text-foreground/40">
              Archived
            </div>
            <div className="space-y-0.5">
              {archivedMatches.map((t) => renderRow(t, { archivedBadge: true }))}
            </div>
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
