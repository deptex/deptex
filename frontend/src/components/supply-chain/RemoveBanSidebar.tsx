import { useState } from 'react';
import { Ban, Loader2, X, ShieldCheck } from 'lucide-react';
import { api } from '../../lib/api';
import type { BannedVersion } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../ui/button';

interface RemoveBanSidebarProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  ban: BannedVersion | null;
  orgId: string;
  dependencyName: string;
  /** Called after a ban is successfully removed; receives the unbanned version. */
  onUnbanComplete?: (unbannedVersion: string) => void;
}

const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
};

export function RemoveBanSidebar({
  open,
  onOpenChange,
  ban,
  orgId,
  dependencyName,
  onUnbanComplete,
}: RemoveBanSidebarProps) {
  const [removing, setRemoving] = useState(false);
  const { toast } = useToast();

  const handleRemoveBan = async () => {
    if (!ban) return;
    setRemoving(true);
    try {
      await api.removeBan(orgId, ban.id);
      toast({
        title: 'Ban removed',
        description: `Removed ban on v${ban.banned_version} of ${dependencyName}.`,
      });
      onUnbanComplete?.(ban.banned_version);
      onOpenChange(false);
    } catch (err: any) {
      toast({
        title: 'Failed to remove ban',
        description: err.message || 'An unexpected error occurred',
        variant: 'destructive',
      });
    } finally {
      setRemoving(false);
    }
  };

  if (!open || !ban) return null;

  return (
    <div className="fixed inset-0 z-50">
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
        onClick={() => onOpenChange(false)}
        aria-hidden
      />
      <div
        className="fixed right-0 top-0 h-full w-full max-w-md bg-background border-l border-border shadow-2xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header — distinct darker strip like watchtower table header */}
        <div className="px-6 py-5 border-b border-border flex-shrink-0 flex items-center justify-between bg-[#141618]">
          <div className="flex items-center gap-2.5">
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-destructive/10">
              <Ban className="h-4 w-4 text-destructive" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-foreground">Remove ban</h2>
              <p className="text-xs text-foreground-secondary font-mono">{dependencyName}@{ban.banned_version}</p>
            </div>
          </div>
          <Button variant="ghost" size="icon" onClick={() => onOpenChange(false)} className="h-9 w-9">
            <X className="h-4 w-4" />
          </Button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-6 pt-5 pb-6 space-y-6">
          {/* Ban details */}
          <div className="rounded-lg border border-border bg-background-card p-4 space-y-3">
            <h3 className="text-sm font-medium text-foreground">Ban details</h3>
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs text-foreground-secondary">Banned version</span>
                <span className="text-xs font-mono text-destructive font-medium">{ban.banned_version}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-foreground-secondary">Bumped to</span>
                <span className="text-xs font-mono text-foreground font-medium">{ban.bump_to_version}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-foreground-secondary">Banned on</span>
                <span className="text-xs text-foreground-secondary">{formatDate(ban.created_at)}</span>
              </div>
            </div>
          </div>

          {/* Confirmation message */}
          <div className="rounded-lg border border-primary/20 bg-primary/10 px-4 py-3.5">
            <div className="flex items-start gap-2.5">
              <ShieldCheck className="h-4 w-4 text-primary flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-foreground">Remove this ban?</p>
                <p className="text-xs text-foreground-secondary leading-relaxed mt-1">
                  Removing this ban will allow projects in your organization to use{' '}
                  <span className="font-mono font-medium text-foreground">v{ban.banned_version}</span> of{' '}
                  <span className="font-mono font-medium text-foreground">{dependencyName}</span> again.
                  Existing bump PRs that were created will not be closed.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Footer — darker strip like watchtower table footer */}
        <div className="px-6 py-4 border-t border-border flex-shrink-0 flex items-center gap-3 bg-[#141618]">
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            className="flex-1"
            disabled={removing}
          >
            Cancel
          </Button>
          <Button
            onClick={handleRemoveBan}
            disabled={removing}
            className="flex-1"
          >
            <>
              {removing ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1.5" />
              ) : (
                <ShieldCheck className="h-4 w-4 mr-1.5" />
              )}
              Remove ban
            </>
          </Button>
        </div>
      </div>
    </div>
  );
}
