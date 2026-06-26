import { type MaliciousFinding } from '../../lib/api';
import { cn } from '../../lib/utils';
import { ReachabilityBadge, type MaliciousReachabilityLevel } from './ReachabilityBadge';
import { MaliciousIcon } from './MaliciousIcon';

interface MaliciousFindingCardProps {
  organizationId: string;
  projectId: string;
  finding: MaliciousFinding;
  canManage: boolean;
  onStatusChange?: () => void;
  /**
   * When provided, the package name renders as a clickable button that
   * fires this callback. Hosting pages typically use it to open a drawer
   * showing the package's capability tags + other metadata.
   */
  onPackageClick?: (info: {
    package_name: string;
    package_version: string | null | undefined;
    ecosystem: string | null | undefined;
    project_dependency_id: string;
  }) => void;
}

export function MaliciousFindingCard({
  finding,
  onPackageClick,
}: MaliciousFindingCardProps) {
  return (
    <div className="space-y-4">
      {/* Signal badges — severity, scanner, reachability, the package. Ignoring a
          malicious finding is driven by the row's status pill, so no per-card
          suppress / accept-risk actions here. */}
      <div className="flex flex-wrap items-center gap-1.5">
        <span className={cn(
          'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border',
          finding.severity === 'critical' ? 'bg-red-500/15 text-red-300 border-red-500/30'
            : finding.severity === 'high' ? 'bg-red-500/10 text-red-400 border-red-500/20'
            : finding.severity === 'medium' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20'
            : 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20'
        )}>
          <MaliciousIcon size={12} className="mr-1" />
          {finding.severity.toUpperCase()}
        </span>
        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-purple-500/10 text-purple-300 border border-purple-500/20">
          {finding.scanner === 'feed' ? 'Feed match' : finding.scanner === 'maintainer' ? 'Maintainer signal' : 'GuardDog'}
        </span>
        <ReachabilityBadge
          level={(finding.reachability_level ?? null) as MaliciousReachabilityLevel | null}
          details={finding.reachability_details}
        />
        {finding.package_name && (
          onPackageClick ? (
            <button
              type="button"
              onClick={() =>
                onPackageClick({
                  package_name: finding.package_name!,
                  package_version: finding.package_version,
                  ecosystem: finding.ecosystem,
                  project_dependency_id: finding.project_dependency_id,
                })
              }
              className="text-[11px] text-foreground-secondary font-mono hover:text-foreground hover:underline underline-offset-2 transition-colors"
            >
              {finding.package_name}@{finding.package_version} ({finding.ecosystem})
            </button>
          ) : (
            <span className="text-[11px] text-foreground-secondary font-mono">
              {finding.package_name}@{finding.package_version} ({finding.ecosystem})
            </span>
          )
        )}
      </div>

      {finding.message && (
        <div className="text-xs text-foreground-secondary leading-relaxed">
          {finding.message}
        </div>
      )}

      {finding.evidence && finding.evidence.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-3 py-1.5 bg-[#0a0a0b] border-b border-zinc-800/50">
            <span className="text-[11px] text-foreground font-mono">
              {finding.evidence[0].file_path}:{finding.evidence[0].lines[0]}
            </span>
          </div>
          <pre className="bg-[#0a0a0b] px-3 py-2 text-[11px] text-zinc-300 overflow-auto whitespace-pre-wrap">
            {finding.evidence[0].snippet}
          </pre>
        </div>
      )}
    </div>
  );
}
