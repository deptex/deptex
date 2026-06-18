import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { Button } from '../ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from '../ui/dialog';
import { useToast } from '../../hooks/use-toast';
import { api, type DastTargetDTO } from '../../lib/api';

interface DastTargetEditDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
  /** When null, the dialog is in create mode — a new target. */
  target: DastTargetDTO | null;
  onSaved: (target: DastTargetDTO) => void;
  canManage: boolean;
}

const INPUT_CLASS =
  'w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-ring focus:border-input transition-colors disabled:cursor-not-allowed disabled:opacity-50';

export function DastTargetEditDialog({
  open,
  onOpenChange,
  projectId,
  target,
  onSaved,
  canManage,
}: DastTargetEditDialogProps) {
  const { toast } = useToast();
  const isEdit = !!target;

  const [draftUrl, setDraftUrl] = useState('');
  const [draftLabel, setDraftLabel] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setDraftUrl(target?.target_url ?? '');
    setDraftLabel(target?.label ?? '');
  }, [open, target]);

  const handleSave = async () => {
    if (!canManage) return;
    setSaving(true);
    try {
      if (isEdit && target) {
        const updated = await api.updateDastTarget(projectId, target.id, {
          label: draftLabel.trim(),
        });
        onSaved(updated);
        toast({ title: 'Target updated' });
      } else {
        const created = await api.createDastTarget(projectId, {
          target_url: draftUrl.trim(),
          label: draftLabel.trim(),
          enabled: true,
        });
        onSaved(created);
        toast({ title: 'Target added' });
      }
      onOpenChange(false);
    } catch (e: any) {
      const code = e?.message ?? 'Failed to save target';
      toast({
        title: 'Failed to save target',
        description: humanizeTargetError(code),
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent hideClose className="sm:max-w-[480px] bg-background p-0 gap-0 overflow-hidden flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="px-6 pt-6 pb-4 flex-shrink-0">
          <DialogTitle>{isEdit ? 'Edit target' : 'Add target'}</DialogTitle>
          <DialogDescription className="mt-1">
            {isEdit
              ? 'Rename this target. Configure login from the target menu; recreate the target to change its URL.'
              : "Add your deployed app's URL to scan. Loopback / private hosts are blocked."}
          </DialogDescription>
        </div>

        {/* Body */}
        <div className="px-6 py-4 grid gap-4 overflow-y-auto flex-1 min-h-0">
          {isEdit ? (
            <div className="grid gap-2">
              <span className="text-sm font-medium text-foreground">Target URL</span>
              <div className="px-3 py-2.5 bg-black/20 border border-border rounded-lg text-sm font-mono text-foreground-secondary break-all">
                {target?.target_url}
              </div>
            </div>
          ) : (
            <div className="grid gap-2">
              <label htmlFor="dast-target-url" className="text-sm font-medium text-foreground">Target URL</label>
              <input
                id="dast-target-url"
                type="url"
                value={draftUrl}
                onChange={(e) => setDraftUrl(e.target.value)}
                disabled={saving || !canManage}
                placeholder="https://staging.example.com"
                className={`${INPUT_CLASS} font-mono`}
              />
            </div>
          )}

          <div className="grid gap-2">
            <label htmlFor="dast-target-label" className="text-sm font-medium text-foreground">
              Label
            </label>
            <input
              id="dast-target-label"
              value={draftLabel}
              onChange={(e) => setDraftLabel(e.target.value)}
              disabled={saving || !canManage}
              placeholder="Staging API"
              className={INPUT_CLASS}
            />
          </div>
        </div>

        {/* Footer */}
        <DialogFooter className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header sm:rounded-b-lg sm:justify-between">
          <Button
            variant="outline"
            className="h-8 rounded-lg px-3"
            disabled={saving}
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          {canManage ? (
            <Button
              variant="green"
              className="relative"
              onClick={handleSave}
              disabled={saving || draftLabel.trim().length === 0 || (!isEdit && draftUrl.trim().length === 0)}
            >
              <span className={saving ? 'invisible' : undefined}>
                {isEdit ? 'Save changes' : 'Add target'}
              </span>
              {saving && (
                <span className="absolute inset-0 flex items-center justify-center">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                </span>
              )}
            </Button>
          ) : (
            <span />
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function humanizeTargetError(code: string): string {
  switch (code) {
    case 'invalid_target_url':
      return 'URL is invalid or points at a private host.';
    case 'target_url_duplicate':
      return 'Another target in this project already uses this URL.';
    case 'target_not_found':
      return 'Target no longer exists.';
    default:
      return 'See console for details.';
  }
}
