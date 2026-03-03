import { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Search, X, BookOpen, Mail, LayoutDashboard, Settings } from 'lucide-react';
import {
  Dialog,
  DialogContent,
} from './ui/dialog';

export interface CommandAction {
  id: string;
  label: string;
  description?: string;
  icon: React.ReactNode;
  run: () => void;
}

interface CommandPaletteProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

export default function CommandPalette({ open: controlledOpen, onOpenChange }: CommandPaletteProps = {}) {
  const [internalOpen, setInternalOpen] = useState(false);
  const isControlled = controlledOpen !== undefined && onOpenChange !== undefined;
  const open = isControlled ? controlledOpen : internalOpen;
  const setOpen = isControlled ? onOpenChange : setInternalOpen;

  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen(!open);
        setQuery('');
        setTimeout(() => inputRef.current?.focus(), 0);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, setOpen]);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 0);
  }, [open]);

  const orgId = location.pathname.match(/^\/organizations\/([^/]+)/)?.[1];

  const actions: CommandAction[] = [
    {
      id: 'organizations',
      label: 'Go to Organizations',
      description: 'Organization list',
      icon: <LayoutDashboard className="h-4 w-4" />,
      run: () => { setOpen(false); navigate('/organizations'); },
    },
    {
      id: 'settings',
      label: 'Settings',
      description: 'Your account settings',
      icon: <Settings className="h-4 w-4" />,
      run: () => { setOpen(false); navigate('/settings'); },
    },
    {
      id: 'docs',
      label: 'Docs',
      description: 'Documentation',
      icon: <BookOpen className="h-4 w-4" />,
      run: () => { setOpen(false); window.open('/docs', '_blank'); },
    },
    {
      id: 'help',
      label: 'Help & Support',
      description: 'Contact and help center',
      icon: <Mail className="h-4 w-4" />,
      run: () => { setOpen(false); window.open('/docs/help', '_blank'); },
    },
  ];

  if (orgId) {
    actions.unshift(
      {
        id: 'org-overview',
        label: 'Organization overview',
        description: `View org summary`,
        icon: <LayoutDashboard className="h-4 w-4" />,
        run: () => { setOpen(false); navigate(`/organizations/${orgId}`); },
      },
      {
        id: 'org-projects',
        label: 'Projects',
        description: 'List projects',
        icon: <LayoutDashboard className="h-4 w-4" />,
        run: () => { setOpen(false); navigate(`/organizations/${orgId}/projects`); },
      },
    );
  }

  const q = query.trim().toLowerCase();
  const filtered = q
    ? actions.filter(
        (a) =>
          a.label.toLowerCase().includes(q) ||
          (a.description && a.description.toLowerCase().includes(q))
      )
    : actions;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent
        hideClose
        className="max-w-xl w-[90vw] p-0 gap-0 bg-background-card border-border overflow-hidden"
      >
        <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
          <Search className="h-4 w-4 text-foreground-secondary shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Search or run a command..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 bg-transparent text-sm text-foreground placeholder:text-foreground-secondary border-0 min-h-8 outline-none focus:outline-none focus:ring-0"
            autoFocus
          />
          <kbd className="hidden sm:inline-flex items-center justify-center h-6 min-w-[1.75rem] px-1.5 rounded bg-background border border-border font-mono text-xs text-foreground-secondary">
            ESC
          </kbd>
          <button
            onClick={() => setOpen(false)}
            className="flex items-center justify-center w-8 h-8 rounded-md text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors shrink-0"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[60vh] overflow-y-auto py-2">
          {filtered.length > 0 ? (
            filtered.map((action) => (
              <button
                key={action.id}
                onClick={action.run}
                className="w-full flex items-center gap-3 px-4 py-2.5 text-left rounded-none hover:bg-background-subtle transition-colors text-foreground"
              >
                <span className="text-foreground-secondary">{action.icon}</span>
                <div className="flex flex-col gap-0.5 min-w-0">
                  <span className="text-sm font-medium">{action.label}</span>
                  {action.description && (
                    <span className="text-xs text-foreground-secondary">{action.description}</span>
                  )}
                </div>
              </button>
            ))
          ) : (
            <p className="px-4 py-4 text-sm text-foreground-secondary">No commands match.</p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
