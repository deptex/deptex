import { useEffect, useState } from 'react';
import { AlertTriangle, Loader2 } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';

const STORAGE_PREFIX = 'deptex.dast.activeScanOptIn.';

export function hasActiveScanOptIn(targetId: string): boolean {
  try {
    return window.localStorage.getItem(STORAGE_PREFIX + targetId) === '1';
  } catch {
    return false;
  }
}

export function recordActiveScanOptIn(targetId: string): void {
  try {
    window.localStorage.setItem(STORAGE_PREFIX + targetId, '1');
  } catch {
    /* swallow — quota / private mode */
  }
}

interface ActiveScanOptInDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  targetUrl: string;
  /** Confirm callback. Resolves when caller's scan trigger settles. */
  onConfirm: () => Promise<void> | void;
}

export function ActiveScanOptInDialog({
  open,
  onOpenChange,
  targetUrl,
  onConfirm,
}: ActiveScanOptInDialogProps) {
  const [confirmText, setConfirmText] = useState('');
  const [running, setRunning] = useState(false);

  useEffect(() => {
    if (open) setConfirmText('');
  }, [open]);

  const matches = confirmText.trim() === targetUrl.trim();

  const handleConfirm = async () => {
    if (!matches || running) return;
    setRunning(true);
    try {
      await onConfirm();
      onOpenChange(false);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !running && onOpenChange(o)}>
      <DialogContent hideClose className="p-0 gap-0 overflow-hidden bg-background-card-header">
        <div className="p-6 space-y-4">
          <DialogHeader>
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              <DialogTitle>Run an active scan?</DialogTitle>
            </div>
            <DialogDescription>
              Active scanning sends fuzzed payloads at this target — including injection probes,
              bad authentication attempts, and request mutations. Don't run this against
              production without authorization.
            </DialogDescription>
          </DialogHeader>
          <div>
            <Label className="text-sm text-foreground">
              Type <code className="text-foreground-secondary">{targetUrl}</code> to confirm
            </Label>
            <Input
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              disabled={running}
              autoFocus
              className="mt-2 font-mono text-xs"
              placeholder={targetUrl}
            />
          </div>
        </div>
        <div className="flex items-center justify-between px-6 py-4 border-t border-border bg-background">
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={running}
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={handleConfirm}
            disabled={!matches || running}
          >
            {running ? (
              <>
                <Loader2 className="h-3.5 w-3.5 mr-2 animate-spin" /> Starting…
              </>
            ) : (
              'Run active scan'
            )}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
