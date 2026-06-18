import { useEffect, useState } from 'react';
import { Button } from '../ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from '../ui/dialog';
import { useToast } from '../../hooks/use-toast';
import {
  api,
  type DastCredentialSummaryDTO,
  type DastTargetDTO,
} from '../../lib/api';
import { DastAuthPanel } from './DastAuthPanel';

interface DastTargetAuthDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
  target: DastTargetDTO | null;
  /** Called after a credential is saved/removed so the parent can refresh the row. */
  onChanged?: () => void;
  canManage: boolean;
}

export function DastTargetAuthDialog({
  open,
  onOpenChange,
  projectId,
  target,
  onChanged,
  canManage,
}: DastTargetAuthDialogProps) {
  const { toast } = useToast();
  const [summary, setSummary] = useState<DastCredentialSummaryDTO | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || !target) return;
    setSummary(null);
    setLoading(true);
    api
      .getDastTargetCredentials(projectId, target.id)
      .then((s) => setSummary(s))
      .catch((e) =>
        toast({
          title: 'Failed to load credential',
          description: e?.message,
          variant: 'destructive',
        }),
      )
      .finally(() => setLoading(false));
  }, [open, target, projectId, toast]);

  const refresh = async () => {
    if (!target) return;
    try {
      const s = await api.getDastTargetCredentials(projectId, target.id);
      setSummary(s);
    } catch (e: any) {
      console.error('[dast] refresh credential failed', e);
    }
    onChanged?.();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent hideClose className="sm:max-w-[640px] bg-background p-0 gap-0 overflow-hidden flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="px-6 pt-6 pb-4 flex-shrink-0">
          <DialogTitle>Authentication</DialogTitle>
          <DialogDescription className="mt-1">
            Scan behind a login. Credentials are encrypted at rest and never written to logs.
          </DialogDescription>
          {target ? (
            <div className="mt-2 text-xs font-mono text-foreground-secondary break-all">
              {target.target_url}
            </div>
          ) : null}
        </div>

        {/* Body */}
        <div className="px-6 py-4 overflow-y-auto flex-1 min-h-0">
          {loading || !target ? (
            <AuthPanelSkeleton />
          ) : (
            <DastAuthPanel
              projectId={projectId}
              targetId={target.id}
              initialSummary={summary}
              onChange={refresh}
              disabled={!canManage}
            />
          )}
        </div>

        {/* Footer */}
        <DialogFooter className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header sm:rounded-b-lg sm:justify-end">
          <Button
            variant="outline"
            className="h-8 rounded-lg px-3"
            onClick={() => onOpenChange(false)}
          >
            Done
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function AuthPanelSkeleton() {
  const pulse = 'bg-muted animate-pulse rounded';
  return (
    <div className="space-y-4">
      {/* strategy select */}
      <div className="space-y-2">
        <div className={`h-4 w-44 ${pulse}`} />
        <div className={`h-3 w-72 max-w-full ${pulse}`} />
        <div className={`h-9 w-[260px] max-w-full ${pulse}`} />
      </div>
      {/* current credential summary */}
      <div className={`h-9 w-full ${pulse}`} />
      {/* two field rows */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="space-y-2">
          <div className={`h-4 w-28 ${pulse}`} />
          <div className={`h-9 w-full ${pulse}`} />
        </div>
        <div className="space-y-2">
          <div className={`h-4 w-28 ${pulse}`} />
          <div className={`h-9 w-full ${pulse}`} />
        </div>
      </div>
      <div className="flex justify-end gap-2 pt-1">
        <div className={`h-8 w-32 rounded-lg ${pulse}`} />
      </div>
    </div>
  );
}
