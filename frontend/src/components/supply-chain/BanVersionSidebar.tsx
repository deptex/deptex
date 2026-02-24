import { useState } from 'react';
import { Ban, ChevronDown, Loader2, AlertTriangle } from 'lucide-react';
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
        {/* Header — same style as DeprecateSidebar */}
        <div className="px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]">
          <div className="flex items-center gap-3 mb-2">
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-destructive/10">
              <Ban className="h-4 w-4 text-destructive" />
            </div>
            <h2 className="text-lg font-semibold text-foreground">Ban version</h2>
          </div>
          <p className="text-sm text-foreground-secondary">
            Ban <span className="font-medium text-foreground">v{versionToBan}</span> of{' '}
            <span className="font-medium text-foreground">{displayName}</span> across your{' '}
            {bumpScope === 'org' ? 'organization' : 'team'}
          </p>
        </div>

        {/* Content — form scrolls; actions at bottom, same background as main (no border/different colour) */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
            {/* Warning */}
            <div className="rounded-lg border border-amber-500/15 bg-amber-500/5 px-4 py-3.5">
              <div className="flex items-start gap-2.5">
                <AlertTriangle className="h-4 w-4 text-amber-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-foreground">
                    {bumpScope === 'org' ? 'Organization-wide action' : 'Team-wide action'}
                  </p>
                  <p className="text-xs text-foreground-secondary leading-relaxed mt-1">
                    This will create PRs in all projects currently on this version to bump them to the
                    version you select below.
                  </p>
                </div>
              </div>
            </div>

            {/* Target version selection — normal app font */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">
                Bump to version
              </label>
              <p className="text-xs text-foreground-secondary">
                Choose the version that affected projects should be bumped to.
              </p>
              <DropdownMenu open={dropdownOpen} onOpenChange={setDropdownOpen}>
                <DropdownMenuTrigger asChild>
                  <button
                    className="flex items-center justify-between w-full px-3 py-2 rounded-md border border-border bg-background-card text-sm text-foreground hover:border-foreground-secondary/40 transition-colors cursor-pointer"
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

          {/* Buttons — part of main section, no border or different colour */}
          <div className="flex-shrink-0 px-6 py-4 flex items-center justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => onOpenChange(false)}
              disabled={banning}
            >
              Cancel
            </Button>
            <Button
              variant="default"
              size="sm"
              onClick={handleBan}
              disabled={!bumpToVersion || banning}
              className="gap-1.5"
            >
              {banning ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Ban className="h-3.5 w-3.5" />
              )}
              Ban version
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
