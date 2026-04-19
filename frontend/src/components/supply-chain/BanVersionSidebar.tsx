import { useState } from 'react';
import { Ban, ChevronDown, Loader2 } from 'lucide-react';
import { api } from '../../lib/api';
import type { SupplyChainAvailableVersion, BannedVersion } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from '../ui/dropdown-menu';
import { Button } from '../ui/button';
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogTitle,
  DialogDescription,
} from '../ui/dialog';

interface BanVersionSidebarProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  versionToBan: string;
  availableVersions: SupplyChainAvailableVersion[];
  bannedVersions?: BannedVersion[];
  orgId: string;
  dependencyId: string;
  /** Package name for display only (e.g. in header "lodash@1.0.0") */
  packageName?: string;
  bumpScope: 'org' | 'team' | 'project';
  bumpTeamId?: string;
  /** Called after a version is successfully banned; receives the banned version. */
  onBanComplete?: (bannedVersion: string) => void;
}

export function BanVersionSidebar({
  open,
  onOpenChange,
  versionToBan,
  availableVersions,
  bannedVersions,
  orgId,
  dependencyId,
  packageName,
  bumpScope,
  bumpTeamId,
  onBanComplete,
}: BanVersionSidebarProps) {
  const displayName = packageName ?? 'this package';
  const [bumpToVersion, setBumpToVersion] = useState<string>('');
  const [banning, setBanning] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const { toast } = useToast();

  // Filter out the version being banned AND already-banned versions from available target versions
  const bannedSet = new Set(bannedVersions?.map((b) => b.banned_version) ?? []);
  const targetVersions = availableVersions.filter((v) => v.version !== versionToBan && !bannedSet.has(v.version));

  const handleBan = async () => {
    if (!bumpToVersion) return;
    if (bumpScope === 'project' || (bumpScope === 'team' && !bumpTeamId)) return;
    setBanning(true);
    try {
      const result = bumpScope === 'org'
        ? await api.banVersion(orgId, dependencyId, versionToBan, bumpToVersion)
        : await api.banVersionTeam(orgId, bumpTeamId!, dependencyId, versionToBan, bumpToVersion);
      const successCount = result.pr_results.filter((r) => r.pr_url).length;
      const errorCount = result.pr_results.filter((r) => r.error).length;
      const scopeLabel = bumpScope === 'org' ? 'organization' : 'team';

      if (successCount > 0 && errorCount === 0) {
        toast({
          title: 'Version banned',
          description: `Banned v${versionToBan}. Created ${successCount} PR${successCount !== 1 ? 's' : ''} to bump affected projects to v${bumpToVersion}.`,
        });
      } else if (successCount > 0 && errorCount > 0) {
        toast({
          title: 'Version banned with some errors',
          description: `Banned v${versionToBan}. Created ${successCount} PR${successCount !== 1 ? 's' : ''}, but ${errorCount} failed.`,
          variant: 'destructive',
        });
      } else if (result.affected_projects === 0) {
        toast({
          title: 'Version banned',
          description: `Banned v${versionToBan}. No projects in this ${scopeLabel} are currently on this version.`,
        });
      } else {
        toast({
          title: 'Version banned',
          description: `Banned v${versionToBan}, but PR creation failed for ${errorCount} project${errorCount !== 1 ? 's' : ''}.`,
          variant: 'destructive',
        });
      }

      onBanComplete?.(versionToBan);
      onOpenChange(false);
      setBumpToVersion('');
    } catch (err: any) {
      toast({
        title: 'Failed to ban version',
        description: err.message || 'An unexpected error occurred',
        variant: 'destructive',
      });
    } finally {
      setBanning(false);
    }
  };

  if (!open) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden">
        <div className="px-6 pt-6 pb-4 border-b border-border">
          <DialogTitle>Ban version</DialogTitle>
          <DialogDescription className="mt-1">
            Ban <span className="font-medium text-foreground">v{versionToBan}</span> of{' '}
            <span className="font-medium text-foreground">{displayName}</span> across your{' '}
            {bumpScope === 'org' ? 'organization' : 'team'}. This will create PRs to bump affected projects.
          </DialogDescription>
        </div>

        <div className="px-6 py-4 grid gap-4 bg-background">
          <div className="grid gap-2">
            <label className="text-sm font-medium text-foreground">
              Bump to version
            </label>
            <DropdownMenu open={dropdownOpen} onOpenChange={setDropdownOpen}>
              <DropdownMenuTrigger asChild>
                <button
                  className="flex h-9 items-center justify-between w-full px-3 py-1 rounded-md border border-border bg-background text-sm text-foreground shadow-sm transition-colors hover:border-foreground-secondary/40 cursor-pointer"
                  onClick={(e) => e.stopPropagation()}
                >
                  <span className={bumpToVersion ? 'text-foreground' : 'text-foreground-secondary'}>
                    {bumpToVersion || 'Select version...'}
                  </span>
                  <ChevronDown className="h-4 w-4 text-foreground-secondary" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="start"
                className="max-h-64 overflow-y-auto min-w-[240px]"
                onPointerDownOutside={(e) => e.stopPropagation()}
              >
                <DropdownMenuLabel className="text-xs text-foreground-secondary">
                  Available versions
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuRadioGroup
                  value={bumpToVersion}
                  onValueChange={(value) => {
                    setBumpToVersion(value);
                    setDropdownOpen(false);
                  }}
                >
                  {targetVersions.map((v) => (
                    <DropdownMenuRadioItem
                      key={v.dependency_version_id}
                      value={v.version}
                      className="text-sm cursor-pointer"
                    >
                      {v.version}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        <DialogFooter className="px-6 py-4 bg-background">
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={banning}
          >
            Cancel
          </Button>
          <Button
            className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
            onClick={handleBan}
            disabled={!bumpToVersion || banning}
          >
            {banning ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Ban className="h-4 w-4 mr-2" />
            )}
            Ban version
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
