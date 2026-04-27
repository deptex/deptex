import { useEffect, useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import { Avatar, AvatarFallback, AvatarImage } from '../ui/avatar';
import { Button } from '../ui/button';
import { Crown, Loader2, UserPlus, X } from 'lucide-react';
import { aegisApi, type AegisParticipant } from '../../lib/aegis-api';
import { useToast } from '../../hooks/use-toast';

interface ParticipantsPanelProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  threadId: string;
  currentUserId: string;
  isCreator: boolean;
  onOpenAddPeople: () => void;
  onParticipantsChanged: () => void;
}

export function ParticipantsPanel({
  open,
  onOpenChange,
  threadId,
  currentUserId,
  isCreator,
  onOpenAddPeople,
  onParticipantsChanged,
}: ParticipantsPanelProps) {
  const [participants, setParticipants] = useState<AegisParticipant[]>([]);
  const [loading, setLoading] = useState(true);
  const [removing, setRemoving] = useState<Record<string, boolean>>({});
  const { toast } = useToast();

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setLoading(true);
    aegisApi.listParticipants(threadId)
      .then((list) => { if (!cancelled) setParticipants(list); })
      .catch((err) => { if (!cancelled) toast({ title: 'Failed to load', description: err?.message, variant: 'destructive' }); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [open, threadId, toast]);

  const handleRemove = async (userId: string) => {
    setRemoving((prev) => ({ ...prev, [userId]: true }));
    try {
      await aegisApi.removeParticipant(threadId, userId);
      setParticipants((prev) => prev.filter((p) => p.userId !== userId));
      onParticipantsChanged();
    } catch (err: any) {
      toast({ title: 'Could not remove', description: err?.message, variant: 'destructive' });
    } finally {
      setRemoving((prev) => ({ ...prev, [userId]: false }));
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Participants</DialogTitle>
        </DialogHeader>

        <div className="max-h-72 overflow-y-auto space-y-1">
          {loading && <div className="p-4 text-sm text-foreground/60 flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>}
          {!loading && participants.map((p) => (
            <div key={p.userId} className="flex items-center gap-3 p-2 rounded-md hover:bg-background-subtle/60">
              <Avatar className="h-8 w-8">
                {p.avatarUrl && <AvatarImage src={p.avatarUrl} />}
                <AvatarFallback>{(p.displayName ?? p.email ?? '?').charAt(0).toUpperCase()}</AvatarFallback>
              </Avatar>
              <div className="flex-1 min-w-0">
                <div className="text-sm text-foreground/90 truncate flex items-center gap-1.5">
                  {p.displayName ?? p.email}
                  {p.userId === currentUserId && <span className="text-xs text-foreground/50">(you)</span>}
                  {p.isCreator && <Crown className="h-3 w-3 text-amber-500" aria-label="Creator" />}
                </div>
                <div className="text-xs text-foreground/50 truncate">{p.email}</div>
              </div>
              {isCreator && p.userId !== currentUserId && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => void handleRemove(p.userId)}
                  disabled={!!removing[p.userId]}
                  title="Remove"
                >
                  {removing[p.userId] ? <Loader2 className="h-4 w-4 animate-spin" /> : <X className="h-4 w-4" />}
                </Button>
              )}
            </div>
          ))}
        </div>

        <Button variant="outline" onClick={onOpenAddPeople} className="w-full">
          <UserPlus className="h-4 w-4 mr-2" /> Add people
        </Button>
      </DialogContent>
    </Dialog>
  );
}
