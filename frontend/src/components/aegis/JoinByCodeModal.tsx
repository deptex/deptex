import { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '../ui/dialog';
import { Button } from '../ui/button';
import { Loader2 } from 'lucide-react';
import { aegisApi } from '../../lib/aegis-api';
import { useToast } from '../../hooks/use-toast';

interface JoinByCodeModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onJoined: (threadId: string) => void;
}

export function JoinByCodeModal({ open, onOpenChange, onJoined }: JoinByCodeModalProps) {
  const [code, setCode] = useState('');
  const [joining, setJoining] = useState(false);
  const { toast } = useToast();

  const handleJoin = async () => {
    const trimmed = code.trim();
    if (!trimmed) return;
    setJoining(true);
    try {
      const { threadId } = await aegisApi.redeemInviteCode(trimmed);
      onJoined(threadId);
      setCode('');
      onOpenChange(false);
    } catch (err: any) {
      toast({ title: 'Could not join', description: err?.message ?? 'Invalid code', variant: 'destructive' });
    } finally {
      setJoining(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => !joining && onOpenChange(v)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Join chat by code</DialogTitle>
          <DialogDescription>
            Paste an invite code to join an Aegis chat that was shared with you.
          </DialogDescription>
        </DialogHeader>
        <input
          type="text"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="Invite code"
          className="w-full rounded-md bg-background-subtle px-3 py-2 text-sm text-foreground outline-none ring-1 ring-border focus:ring-foreground/30"
          autoFocus
          onKeyDown={(e) => { if (e.key === 'Enter') void handleJoin(); }}
        />
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={joining}>
            Cancel
          </Button>
          <Button onClick={handleJoin} disabled={joining || !code.trim()}>
            {joining ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Joining…</> : 'Join'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
