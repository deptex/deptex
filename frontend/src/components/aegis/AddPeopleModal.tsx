import { useEffect, useMemo, useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '../ui/dialog';
import { Button } from '../ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '../ui/avatar';
import { Loader2, Copy, Check, RefreshCw } from 'lucide-react';
import { aegisApi, type InvitableUser } from '../../lib/aegis-api';
import { useToast } from '../../hooks/use-toast';

interface AddPeopleModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  organizationId: string;
  threadId: string;
  onAdded: () => void;
}

export function AddPeopleModal({ open, onOpenChange, organizationId, threadId, onAdded }: AddPeopleModalProps) {
  const [users, setUsers] = useState<InvitableUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [adding, setAdding] = useState<Record<string, boolean>>({});
  const [code, setCode] = useState<string | null>(null);
  const [codeBusy, setCodeBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setLoading(true);
    setQuery('');
    setCopied(false);
    Promise.all([
      aegisApi.listInvitableUsers(organizationId, threadId),
      aegisApi.getInviteCode(threadId),
    ])
      .then(([users, codeRes]) => {
        if (cancelled) return;
        setUsers(users);
        setCode(codeRes.code);
      })
      .catch((err) => {
        if (cancelled) return;
        toast({ title: 'Failed to load', description: err?.message, variant: 'destructive' });
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [open, organizationId, threadId, toast]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return users;
    return users.filter((u) =>
      (u.displayName ?? '').toLowerCase().includes(q)
      || (u.email ?? '').toLowerCase().includes(q),
    );
  }, [users, query]);

  const handleAdd = async (user: InvitableUser) => {
    setAdding((prev) => ({ ...prev, [user.userId]: true }));
    try {
      await aegisApi.addParticipant(threadId, user.userId);
      setUsers((prev) => prev.filter((u) => u.userId !== user.userId));
      onAdded();
    } catch (err: any) {
      toast({ title: 'Could not add', description: err?.message, variant: 'destructive' });
    } finally {
      setAdding((prev) => ({ ...prev, [user.userId]: false }));
    }
  };

  const handleCreateCode = async () => {
    setCodeBusy(true);
    try {
      const res = await aegisApi.createInviteCode(threadId);
      setCode(res.code);
    } catch (err: any) {
      toast({ title: 'Could not create code', description: err?.message, variant: 'destructive' });
    } finally {
      setCodeBusy(false);
    }
  };

  const handleRevokeCode = async () => {
    setCodeBusy(true);
    try {
      await aegisApi.revokeInviteCode(threadId);
      setCode(null);
    } catch (err: any) {
      toast({ title: 'Could not revoke code', description: err?.message, variant: 'destructive' });
    } finally {
      setCodeBusy(false);
    }
  };

  const handleCopy = async () => {
    if (!code) return;
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Add people</DialogTitle>
          <DialogDescription>
            You can invite people you already share a team or project with. For everyone else, share the invite code.
          </DialogDescription>
        </DialogHeader>

        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search by name or email"
          className="w-full rounded-md bg-background-subtle px-3 py-2 text-sm text-foreground outline-none ring-1 ring-border focus:ring-foreground/30"
        />

        <div className="max-h-64 overflow-y-auto -mx-1 px-1 space-y-1">
          {loading && <div className="p-4 text-sm text-foreground/60 flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>}
          {!loading && filtered.length === 0 && (
            <p className="p-4 text-sm text-foreground/60">
              {users.length === 0
                ? "No one to invite directly. Share the code below."
                : "No matches."}
            </p>
          )}
          {!loading && filtered.map((user) => (
            <div key={user.userId} className="flex items-center gap-3 p-2 rounded-md hover:bg-background-subtle/60">
              <Avatar className="h-8 w-8">
                {user.avatarUrl && <AvatarImage src={user.avatarUrl} />}
                <AvatarFallback>{(user.displayName ?? user.email ?? '?').charAt(0).toUpperCase()}</AvatarFallback>
              </Avatar>
              <div className="flex-1 min-w-0">
                <div className="text-sm text-foreground/90 truncate">{user.displayName ?? user.email}</div>
                <div className="text-xs text-foreground/50 truncate">{user.email ?? user.role}</div>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => void handleAdd(user)}
                disabled={!!adding[user.userId]}
              >
                {adding[user.userId] ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Add'}
              </Button>
            </div>
          ))}
        </div>

        <div className="pt-2 border-t border-border">
          <div className="text-xs font-medium text-foreground/60 mb-2">Invite code</div>
          {code ? (
            <div className="flex items-center gap-2">
              <code className="flex-1 px-3 py-2 rounded-md bg-background-subtle text-sm font-mono">{code}</code>
              <Button variant="ghost" size="sm" onClick={handleCopy}>
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </Button>
              <Button variant="ghost" size="sm" onClick={handleRevokeCode} disabled={codeBusy} title="Revoke">
                <RefreshCw className="h-4 w-4" />
              </Button>
            </div>
          ) : (
            <Button variant="outline" size="sm" onClick={handleCreateCode} disabled={codeBusy}>
              {codeBusy ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Creating…</> : 'Create invite code'}
            </Button>
          )}
          <p className="mt-2 text-xs text-foreground/50">
            Anyone in this organization with the Aegis permission can join with this code.
          </p>
        </div>
      </DialogContent>
    </Dialog>
  );
}
