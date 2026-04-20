import { useState, KeyboardEvent } from 'react';
import { MoreHorizontal, Plus, Pencil, Trash2 } from 'lucide-react';
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
}

export function ThreadList({
  threads,
  activeThreadId,
  loading,
  onCreate,
  onSelect,
  onRename,
  onDelete,
}: ThreadListProps) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draftTitle, setDraftTitle] = useState('');
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const beginRename = (thread: AegisThread) => {
    setEditingId(thread.id);
    setDraftTitle(thread.title);
  };

  const commitRename = async () => {
    if (!editingId) return;
    const title = draftTitle.trim();
    const id = editingId;
    setEditingId(null);
    if (!title) return;
    await onRename(id, title);
  };

  const onEditKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      void commitRename();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setEditingId(null);
    }
  };

  const confirmDelete = async () => {
    if (!confirmDeleteId) return;
    const id = confirmDeleteId;
    setConfirmDeleteId(null);
    await onDelete(id);
  };

  return (
    <div className="flex h-full flex-col">
      <div className="p-3 border-b border-border">
        <Button onClick={onCreate} className="w-full h-9" size="sm">
          <Plus className="h-4 w-4 mr-2" />
          New chat
        </Button>
      </div>
      <div className="flex-1 overflow-y-auto px-2 py-2 space-y-0.5">
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
        {threads.map((thread) => {
          const isActive = thread.id === activeThreadId;
          const isEditing = thread.id === editingId;
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
                  className="w-full bg-transparent px-3 py-2 text-sm text-foreground outline-none ring-1 ring-border rounded-md"
                />
              ) : (
                <button
                  type="button"
                  onClick={() => onSelect(thread.id)}
                  className="w-full text-left px-3 py-2 text-sm text-foreground/90 truncate pr-8"
                  title={thread.title}
                >
                  {thread.title}
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
                  <DropdownMenuContent align="end" className="w-32">
                    <DropdownMenuItem onClick={() => beginRename(thread)}>
                      <Pencil className="h-4 w-4 mr-2" />
                      Rename
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
        })}
      </div>

      <Dialog open={!!confirmDeleteId} onOpenChange={(open) => !open && setConfirmDeleteId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete chat?</DialogTitle>
            <DialogDescription>
              This will permanently delete the thread and its messages. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setConfirmDeleteId(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmDelete}>
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
