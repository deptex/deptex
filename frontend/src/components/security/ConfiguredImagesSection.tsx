import { useEffect, useState, useCallback } from 'react';
import { Loader2, Plus, Trash2 } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '../ui/dialog';
import { Button } from '../ui/button';
import { Switch } from '../ui/switch';
import { cn } from '../../lib/utils';
import { api, type ConfiguredImage } from '../../lib/api';
import AddConfiguredImageDialog from './AddConfiguredImageDialog';

interface Props {
  organizationId: string;
  projectId: string;
  canManage: boolean;
}

export default function ConfiguredImagesSection({ organizationId, projectId, canManage }: Props) {
  const [images, setImages] = useState<ConfiguredImage[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<ConfiguredImage | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [togglingIds, setTogglingIds] = useState<Set<string>>(new Set());

  const reload = useCallback(async () => {
    setError(null);
    try {
      const list = await api.listConfiguredImages(organizationId, projectId);
      setImages(list);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to load configured images');
    } finally {
      setLoading(false);
    }
  }, [organizationId, projectId]);

  useEffect(() => {
    setLoading(true);
    reload();
  }, [reload]);

  const handleCreated = (img: ConfiguredImage) => {
    setImages((prev) => (prev ? [img, ...prev] : [img]));
  };

  const handleToggle = async (img: ConfiguredImage, nextEnabled: boolean) => {
    setTogglingIds((s) => new Set(s).add(img.id));
    // Optimistic flip — backend re-validates the cap and may reject; on error
    // the catch reloads the canonical list so the toggle returns to its real
    // state.
    setImages((prev) =>
      (prev ?? []).map((i) => (i.id === img.id ? { ...i, enabled: nextEnabled } : i)),
    );
    try {
      await api.toggleConfiguredImage(organizationId, projectId, img.id, nextEnabled);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to toggle image');
      reload();
    } finally {
      setTogglingIds((s) => {
        const next = new Set(s);
        next.delete(img.id);
        return next;
      });
    }
  };

  const handleConfirmDelete = async () => {
    if (!confirmDelete) return;
    setDeleting(true);
    try {
      await api.deleteConfiguredImage(organizationId, projectId, confirmDelete.id);
      setImages((prev) => (prev ?? []).filter((i) => i.id !== confirmDelete.id));
      setConfirmDelete(null);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to delete image');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="rounded-lg border border-border bg-background-card overflow-hidden">
      <div className="flex items-center justify-between p-6 pb-4">
        <div>
          <h3 className="text-base font-semibold text-foreground">Configured images</h3>
          <p className="text-sm text-foreground-secondary mt-1">
            Specific images to scan in addition to whatever the Dockerfile produces. Up to 20
            enabled images per project.
          </p>
        </div>
        {canManage && (
          <Button variant="outline" size="sm" onClick={() => setShowAdd(true)}>
            <Plus className="h-3.5 w-3.5 mr-1.5" />
            Add image
          </Button>
        )}
      </div>

      <div className="border-t border-border">
        {loading ? (
          <div className="divide-y divide-border">
            {[0, 1].map((i) => (
              <div key={i} className="px-6 py-4">
                <div className="h-4 w-56 bg-foreground/5 rounded mb-2 animate-pulse" />
                <div className="h-3 w-32 bg-foreground/5 rounded animate-pulse" />
              </div>
            ))}
          </div>
        ) : error ? (
          <div className="px-6 py-6 text-sm text-destructive">{error}</div>
        ) : !images || images.length === 0 ? (
          <div className="px-6 py-10 text-center">
            <div className="text-sm text-foreground-secondary">No configured images yet.</div>
            {canManage && (
              <div className="text-xs text-foreground-muted mt-1">
                Add one to scan an image not covered by an in-repo Dockerfile.
              </div>
            )}
          </div>
        ) : (
          <ul className="divide-y divide-border">
            {images.map((img) => {
              const toggling = togglingIds.has(img.id);
              return (
                <li key={img.id} className="px-6 py-4 flex items-center justify-between gap-4">
                  <div className="min-w-0">
                    <div className={cn('text-sm font-mono truncate', img.enabled ? 'text-foreground' : 'text-foreground-muted')}>
                      {img.image_reference}
                    </div>
                    <div className="text-xs text-foreground-secondary mt-0.5">
                      {img.credentials_display
                        ? `${img.credentials_display.display_name} (${img.credentials_display.registry_type})`
                        : 'Public image — no credentials'}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <Switch
                      checked={img.enabled}
                      disabled={!canManage || toggling}
                      onCheckedChange={(v) => handleToggle(img, v)}
                      aria-label={img.enabled ? 'Disable image' : 'Enable image'}
                    />
                    {canManage && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setConfirmDelete(img)}
                        aria-label={`Delete ${img.image_reference}`}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {showAdd && (
        <AddConfiguredImageDialog
          open={showAdd}
          organizationId={organizationId}
          projectId={projectId}
          onClose={() => setShowAdd(false)}
          onCreated={handleCreated}
        />
      )}

      <Dialog open={!!confirmDelete} onOpenChange={(o) => !o && !deleting && setConfirmDelete(null)}>
        <DialogContent hideClose className="p-0 gap-0 overflow-hidden bg-background-card-header">
          <div className="p-6">
            <DialogHeader>
              <DialogTitle>Delete configured image?</DialogTitle>
              <DialogDescription>
                Removing &ldquo;{confirmDelete?.image_reference}&rdquo; stops future scans of this
                image for the current project. Existing finding history is kept. This cannot be
                undone.
              </DialogDescription>
            </DialogHeader>
          </div>
          <div className="flex items-center justify-between px-6 py-4 border-t border-border bg-background">
            <Button variant="outline" onClick={() => setConfirmDelete(null)} disabled={deleting}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleConfirmDelete}
              disabled={deleting}
              className={cn(
                deleting && 'disabled:opacity-100 disabled:bg-background-subtle disabled:text-foreground/70',
              )}
            >
              {deleting ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Delete</> : 'Delete'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
