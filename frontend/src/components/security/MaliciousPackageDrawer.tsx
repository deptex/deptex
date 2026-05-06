/**
 * Malicious package drawer — opens from MaliciousFindingCard's package-name
 * click. Surfaces the v2 capability tags via CapabilitiesSection. The full
 * PackageOverview (license, score, vulns) lives on the dependencies page;
 * this drawer is the security-tab entry point so users can see why a
 * package is suspicious without leaving the finding context.
 */
import { Package, X } from 'lucide-react';
import { Dialog, DialogContent, DialogTitle } from '../ui/dialog';
import { CapabilitiesSection } from '../CapabilitiesSection';

interface MaliciousPackageDrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  organizationId: string;
  packageName: string;
  packageVersion: string | null | undefined;
  ecosystem: string | null | undefined;
}

export function MaliciousPackageDrawer({
  open,
  onOpenChange,
  organizationId,
  packageName,
  packageVersion,
  ecosystem,
}: MaliciousPackageDrawerProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        hideClose
        className="max-w-2xl border border-border bg-background-card p-0 sm:max-w-3xl"
      >
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <div className="flex items-center gap-3 min-w-0">
            <Package className="h-4 w-4 text-foreground-secondary shrink-0" />
            <DialogTitle className="text-sm font-semibold text-foreground truncate">
              {packageName}
              {packageVersion ? (
                <span className="text-foreground-secondary font-normal"> @{packageVersion}</span>
              ) : null}
              {ecosystem ? (
                <span className="text-foreground-muted font-normal text-xs ml-2">({ecosystem})</span>
              ) : null}
            </DialogTitle>
          </div>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            className="text-foreground-secondary hover:text-foreground transition-colors"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4 max-h-[70vh] overflow-y-auto custom-scrollbar">
          {packageVersion ? (
            <CapabilitiesSection
              organizationId={organizationId}
              ecosystem={ecosystem}
              packageName={packageName}
              version={packageVersion}
            />
          ) : (
            <div className="text-xs text-foreground-muted">
              Package version unavailable — capability scan needs an exact version.
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
