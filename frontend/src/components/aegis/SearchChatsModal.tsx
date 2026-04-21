import { useMemo, useState } from 'react';
import { Dialog, DialogContent } from '../ui/dialog';
import { Search, Users } from 'lucide-react';
import { cn } from '../../lib/utils';
import type { AegisThread } from '../../lib/aegis-api';

interface SearchChatsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  threads: AegisThread[];
  onSelect: (threadId: string) => void;
}

export function SearchChatsModal({ open, onOpenChange, threads, onSelect }: SearchChatsModalProps) {
  const [query, setQuery] = useState('');

  const { pinned, recents, archived } = useMemo(() => {
    const q = query.trim().toLowerCase();
    const match = (t: AegisThread) => !q || t.title.toLowerCase().includes(q);
    const all = threads.filter(match);
    const pinned = all.filter((t) => t.pinnedAt && !t.archivedAt);
    const recents = all.filter((t) => !t.pinnedAt && !t.archivedAt);
    const archived = all.filter((t) => t.archivedAt);
    pinned.sort((a, b) => (b.pinnedAt ?? '').localeCompare(a.pinnedAt ?? ''));
    recents.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    archived.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    return { pinned, recents, archived };
  }, [threads, query]);

  const total = pinned.length + recents.length + archived.length;

  const handleSelect = (id: string) => {
    onSelect(id);
    onOpenChange(false);
    setQuery('');
  };

  const renderGroup = (label: string, items: AegisThread[], muted?: boolean) => {
    if (items.length === 0) return null;
    return (
      <>
        <div className="px-3 pt-3 pb-1 text-[11px] font-medium uppercase tracking-wide text-foreground/40">
          {label}
        </div>
        <div className="space-y-0.5">
          {items.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => handleSelect(t.id)}
              className={cn(
                'w-full flex items-center gap-2 rounded-md px-3 py-2 text-sm text-left hover:bg-background-subtle/60',
                muted ? 'text-foreground/60 italic' : 'text-foreground/90',
              )}
            >
              <span className="truncate flex-1">{t.title}</span>
              {t.participantCount > 1 && <Users className="h-3 w-3 flex-shrink-0 text-foreground/40" />}
            </button>
          ))}
        </div>
      </>
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg p-0 gap-0">
        <div className="relative border-b border-border">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground/40 pointer-events-none" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search chats"
            className="w-full bg-transparent border-0 pl-11 pr-4 py-4 text-sm text-foreground placeholder:text-foreground/40 outline-none focus:outline-none focus:ring-0"
            autoFocus
          />
        </div>
        <div className="max-h-96 overflow-y-auto px-2 pb-2">
          {total === 0 && (
            <p className="px-3 py-6 text-xs text-foreground/60 text-center">
              {threads.length === 0 ? 'No chats yet.' : 'No matches.'}
            </p>
          )}
          {renderGroup('Pinned', pinned)}
          {renderGroup('Recents', recents)}
          {renderGroup('Archived', archived, true)}
        </div>
      </DialogContent>
    </Dialog>
  );
}
