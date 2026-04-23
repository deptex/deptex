import { useMemo, useState, type KeyboardEvent } from 'react';
import { Dialog, DialogContent } from '../ui/dialog';
import { Search, MessageCircle, Users, X, Archive } from 'lucide-react';
import { cn } from '../../lib/utils';
import type { AegisThread } from '../../lib/aegis-api';

interface SearchChatsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  threads: AegisThread[];
  onSelect: (threadId: string) => void;
}

function monthLabel(iso: string): string {
  const d = new Date(iso);
  const now = new Date();
  const opts: Intl.DateTimeFormatOptions = d.getFullYear() === now.getFullYear()
    ? { month: 'long' }
    : { month: 'long', year: 'numeric' };
  return d.toLocaleDateString('en-US', opts);
}

export function SearchChatsModal({ open, onOpenChange, threads, onSelect }: SearchChatsModalProps) {
  const [query, setQuery] = useState('');

  const { groups, flatResults } = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = threads.filter((t) => !q || t.title.toLowerCase().includes(q));
    filtered.sort((a, b) => {
      // Non-archived first, then by date
      if (!!a.archivedAt !== !!b.archivedAt) return a.archivedAt ? 1 : -1;
      return b.updatedAt.localeCompare(a.updatedAt);
    });

    const map = new Map<string, AegisThread[]>();
    for (const t of filtered) {
      const label = t.archivedAt ? 'Archived' : monthLabel(t.updatedAt);
      if (!map.has(label)) map.set(label, []);
      map.get(label)!.push(t);
    }
    const groups = Array.from(map.entries()).map(([label, items]) => ({ label, items }));
    return { groups, flatResults: filtered };
  }, [threads, query]);

  const total = flatResults.length;

  const handleSelect = (id: string) => {
    onSelect(id);
    onOpenChange(false);
    setQuery('');
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && flatResults.length > 0) {
      handleSelect(flatResults[0].id);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) setQuery(''); onOpenChange(o); }}>
      <DialogContent className="max-w-2xl p-0 gap-0">
        {/* Search bar */}
        <div className="relative flex items-center border-b border-border">
          <Search className="absolute left-4 h-4 w-4 text-foreground/40 pointer-events-none" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Search chats..."
            className="w-full bg-transparent border-0 pl-11 pr-10 py-4 text-sm text-foreground placeholder:text-foreground/40 outline-none focus:outline-none focus:ring-0"
            autoFocus
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery('')}
              className="absolute right-3 flex h-6 w-6 items-center justify-center rounded text-foreground/40 hover:text-foreground"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {/* Results */}
        <div className="overflow-y-auto min-h-[420px] max-h-[560px] px-2 pb-2">
          {total === 0 && (
            <div className="flex items-center gap-2.5 px-3 py-4 text-sm text-foreground/50">
              <Search className="h-4 w-4 flex-shrink-0" />
              <span>{threads.length === 0 ? 'No chats yet.' : 'No results'}</span>
            </div>
          )}
          {groups.map(({ label, items }) => (
            <div key={label}>
              <div className="px-3 pt-3 pb-1 text-xs text-foreground/40 flex items-center gap-1.5">
                {label === 'Archived' && <Archive className="h-3 w-3" />}
                {label}
              </div>
              <div className="space-y-0.5">
                {items.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => handleSelect(t.id)}
                    className={cn(
                      'w-full flex items-center gap-2.5 rounded-md px-3 py-2 text-sm text-left hover:bg-background-subtle/60',
                      t.archivedAt ? 'text-foreground/40' : 'text-foreground/90',
                    )}
                  >
                    <MessageCircle className="h-4 w-4 flex-shrink-0 text-foreground/30" />
                    <span className="truncate flex-1">{t.title}</span>
                    {t.participantCount > 1 && <Users className="h-3 w-3 flex-shrink-0 text-foreground/30" />}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
