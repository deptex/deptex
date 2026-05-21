import { useEffect, useState } from 'react';
import { X, Loader2, Save } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Switch } from '../ui/switch';
import { useToast } from '../../hooks/use-toast';
import {
  api,
  type DastCredentialSummaryDTO,
  type DastTargetDTO,
} from '../../lib/api';
import { DastAuthPanel } from './DastAuthPanel';
import { DastSpecPanel } from './DastSpecPanel';

interface DastTargetEditDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
  /** When null, the dialog is in create mode — a new target. */
  target: DastTargetDTO | null;
  onSaved: (target: DastTargetDTO) => void;
  onDeleted?: (targetId: string) => void;
  canManage: boolean;
}

export function DastTargetEditDialog({
  open,
  onOpenChange,
  projectId,
  target,
  onSaved,
  onDeleted,
  canManage,
}: DastTargetEditDialogProps) {
  const { toast } = useToast();
  const isEdit = !!target;

  const [draftUrl, setDraftUrl] = useState('');
  const [draftLabel, setDraftLabel] = useState('');
  const [draftEnabled, setDraftEnabled] = useState(true);
  const [saving, setSaving] = useState(false);
  const [credentialSummary, setCredentialSummary] = useState<DastCredentialSummaryDTO | null>(null);
  const [credentialLoading, setCredentialLoading] = useState(false);

  // Reset draft + load credential each time the dialog opens for a different target.
  useEffect(() => {
    if (!open) return;
    setDraftUrl(target?.target_url ?? '');
    setDraftLabel(target?.label ?? '');
    setDraftEnabled(target?.enabled ?? true);
    setCredentialSummary(null);
    if (target) {
      setCredentialLoading(true);
      api
        .getDastTargetCredentials(projectId, target.id)
        .then((s) => setCredentialSummary(s))
        .catch((e) =>
          toast({
            title: 'Failed to load credential',
            description: e?.message,
            variant: 'destructive',
          }),
        )
        .finally(() => setCredentialLoading(false));
    }
  }, [open, target, projectId, toast]);

  const refreshCredential = async () => {
    if (!target) return;
    try {
      const s = await api.getDastTargetCredentials(projectId, target.id);
      setCredentialSummary(s);
    } catch (e: any) {
      console.error('[dast] refresh credential failed', e);
    }
  };

  const handleSave = async () => {
    if (!canManage) return;
    setSaving(true);
    try {
      if (isEdit && target) {
        const updated = await api.updateDastTarget(projectId, target.id, {
          label: draftLabel.length > 0 ? draftLabel : null,
          enabled: draftEnabled,
        });
        onSaved(updated);
        toast({ title: 'Target updated' });
      } else {
        const created = await api.createDastTarget(projectId, {
          target_url: draftUrl.trim(),
          label: draftLabel.length > 0 ? draftLabel : null,
          enabled: draftEnabled,
        });
        onSaved(created);
        toast({
          title: 'Target added',
          description:
            created.detected_runtime === 'spa'
              ? 'Detected as SPA — first scan will use a 16GB machine.'
              : created.detected_runtime === 'classic'
                ? 'Detected as classic SSR — scans run on shared-cpu-4x.'
                : 'Runtime probe inconclusive; first scan will retry.',
        });
        onOpenChange(false);
      }
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

  const handleDelete = async () => {
    if (!target || !canManage) return;
    setSaving(true);
    try {
      await api.deleteDastTarget(projectId, target.id);
      onDeleted?.(target.id);
      onOpenChange(false);
      toast({ title: 'Target removed' });
    } catch (e: any) {
      toast({
        title: 'Failed to remove target',
        description: e?.message,
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
        onClick={() => !saving && onOpenChange(false)}
        aria-hidden
      />
      <div
        className="fixed right-0 top-0 h-full w-full max-w-[640px] bg-background-card border-l border-border shadow-2xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-5 pt-5 pb-4 border-b border-border flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-foreground">
              {isEdit ? 'Edit target' : 'Add target'}
            </h2>
            <p className="text-xs text-foreground-secondary mt-1">
              {isEdit
                ? 'Update label, toggle scanning, or configure authenticated scanning.'
                : 'Add a new URL to scan. Loopback / private hosts are blocked.'}
            </p>
          </div>
          <Button
            variant="outline"
            size="icon"
            onClick={() => onOpenChange(false)}
            disabled={saving}
            aria-label="Close"
          >
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>

        <div className="flex-1 overflow-y-auto custom-scrollbar px-5 py-5 space-y-5">
          <div>
            <Label htmlFor="dast-target-url" className="text-sm text-foreground">Target URL</Label>
            <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
              {isEdit
                ? 'URL is immutable — delete and recreate to migrate.'
                : 'Public-facing URL of the deployed app. Staging recommended.'}
            </p>
            <Input
              id="dast-target-url"
              type="url"
              value={draftUrl}
              onChange={(e) => setDraftUrl(e.target.value)}
              disabled={isEdit || saving || !canManage}
              placeholder="https://staging.example.com"
              className="font-mono text-xs"
            />
          </div>

          <div>
            <Label htmlFor="dast-target-label" className="text-sm text-foreground">Label</Label>
            <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
              Friendly name shown in the targets list.
            </p>
            <Input
              id="dast-target-label"
              value={draftLabel}
              onChange={(e) => setDraftLabel(e.target.value)}
              disabled={saving || !canManage}
              placeholder="Staging API"
            />
          </div>

          <div className="flex items-center justify-between gap-4">
            <div>
              <Label className="text-sm text-foreground">Enabled</Label>
              <p className="text-xs text-foreground-secondary mt-0.5">
                Disabled targets keep their findings but don't accept new scans.
              </p>
            </div>
            <Switch
              checked={draftEnabled}
              onCheckedChange={setDraftEnabled}
              disabled={saving || !canManage}
            />
          </div>

          {isEdit && target ? (
            <div className="pt-2 border-t border-border">
              <h3 className="text-sm font-semibold text-foreground mb-1">Authentication</h3>
              <p className="text-xs text-foreground-secondary mb-4">
                ZAP authenticates the scan via the strategy below. Credentials are encrypted at
                rest with <code>DAST_CREDENTIAL_KEY</code> and never written to logs.
              </p>
              {credentialLoading ? (
                <div className="flex items-center gap-2 text-xs text-foreground-secondary">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading credential…
                </div>
              ) : (
                <DastAuthPanel
                  projectId={projectId}
                  targetId={target.id}
                  initialSummary={credentialSummary}
                  onChange={refreshCredential}
                  disabled={!canManage}
                />
              )}
            </div>
          ) : null}
          {isEdit && target ? (
            <DastSpecPanel
              projectId={projectId}
              target={target}
              canManage={canManage}
              onUpdated={onSaved}
            />
          ) : null}
        </div>

        <div className="px-5 py-4 border-t border-border bg-background flex items-center justify-between">
          {isEdit && canManage ? (
            <Button
              variant="outline"
              size="sm"
              onClick={handleDelete}
              disabled={saving}
              className="text-destructive hover:text-destructive"
            >
              Delete target
            </Button>
          ) : <span />}
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => onOpenChange(false)}
              disabled={saving}
            >
              {isEdit ? 'Done' : 'Cancel'}
            </Button>
            {canManage ? (
              <Button
                variant="outline"
                size="sm"
                onClick={handleSave}
                disabled={saving || (!isEdit && draftUrl.trim().length === 0)}
              >
                {saving ? (
                  <Loader2 className="h-3.5 w-3.5 mr-2 animate-spin" />
                ) : (
                  <Save className="h-3.5 w-3.5 mr-2" />
                )}
                {isEdit ? 'Save changes' : 'Add target'}
              </Button>
            ) : null}
          </div>
        </div>
      </div>
    </div>
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
