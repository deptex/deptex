import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import {
  ReactFlow,
  Background,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type NodeTypes,
  type NodeProps,
  BackgroundVariant,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  GitPullRequest,
  Loader2,
  Package,
  RotateCcw,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { api, type SupplyChainResponse, type SupplyChainChild, type SupplyChainBumpPr, type ProjectEffectivePolicies, type LatestSafeVersionResponse, type BannedVersion, type SupplyChainVersionSecurityData, type DependencyVersionsResponse, type DependencyVersionItem, type DependencyVersionVulnerability, type AssetTier } from '../../lib/api';
import { calculateDexcore, SEVERITY_TO_CVSS } from '../../lib/scoring/dexcore';
import { Button } from '../../components/ui/button';
import { CenterNode } from '../../components/supply-chain/CenterNode';
import { DependencyNode } from '../../components/supply-chain/DependencyNode';
import { VulnerabilityNode } from '../../components/supply-chain/VulnerabilityNode';
import { SafeVersionCard } from '../../components/supply-chain/SafeVersionCard';
import { UnusedInProjectCard } from '../../components/supply-chain/UnusedInProjectCard';
import { useGraphLayout } from '../../components/supply-chain/useGraphLayout';
import { BanVersionSidebar } from '../../components/supply-chain/BanVersionSidebar';
import { RemoveBanSidebar } from '../../components/supply-chain/RemoveBanSidebar';
import { VersionSidebar } from '../../components/VersionSidebar';
import { useToast } from '../../hooks/use-toast';
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';

// Skeleton center node – shows package name, version, and loading placeholders for license + Ban version
function SkeletonCenterNodeCard({ packageName, packageVersion }: { packageName?: string; packageVersion?: string }) {
  return (
    <div
      className="relative px-5 pt-4 pb-0 rounded-xl border-2 shadow-lg bg-background-card border-primary/50 shadow-primary/10"
      style={{ minWidth: 260 }}
    >
      <div className="absolute inset-0 rounded-xl blur-xl opacity-20 -z-10 bg-primary" />
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-primary/15 text-primary">
          <Package className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-foreground truncate">
            {packageName ?? '…'}
          </p>
          <p className="text-xs text-foreground-secondary font-mono">
            {packageVersion ?? '…'}
          </p>
        </div>
        {/* License skeleton */}
        <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-[10px] font-medium border flex-shrink-0 bg-muted/50 border-border animate-pulse w-14 h-6" />
      </div>
      {/* Ban version strip skeleton */}
      <div className="mt-2 -mx-5 px-5 py-2.5 border-t border-border bg-background-card-header rounded-b-xl">
        <div
          className="h-8 w-full rounded-md bg-muted/50 border border-border animate-pulse"
          aria-busy="true"
          aria-label="Loading"
        />
      </div>
    </div>
  );
}

// ReactFlow node wrapper so the skeleton card is a real node in the graph (not an overlay)
function SkeletonCenterNode({ data }: NodeProps) {
  const { packageName, packageVersion } = (data ?? {}) as { packageName?: string; packageVersion?: string };
  return <SkeletonCenterNodeCard packageName={packageName} packageVersion={packageVersion} />;
}

const skeletonCenterNodeTypes: NodeTypes = {
  skeletonCenterNode: SkeletonCenterNode,
};

// Match real layout center position so viewport stays the same when we swap skeleton → real nodes
const CENTER_NODE_WIDTH = 260;
const CENTER_NODE_HEIGHT = 80;
const SKELETON_CENTER_POS = { x: -CENTER_NODE_WIDTH / 2, y: -CENTER_NODE_HEIGHT / 2 };

// Ancestor path visualization
function AncestorPath({
  path,
}: {
  path: Array<{ name: string; version: string; dependency_version_id: string; is_direct: boolean }>;
}) {
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      <span className="text-xs font-medium text-primary">Your App</span>
      {path.map((node, index) => (
        <div key={node.dependency_version_id} className="flex items-center gap-1.5">
          <span className="text-foreground-muted text-xs">&rarr;</span>
          <span
            className={`text-xs font-medium ${index === path.length - 1
                ? 'text-foreground'
                : node.is_direct
                  ? 'text-success'
                  : 'text-foreground-secondary'
              }`}
          >
            {node.name}
          </span>
          <span className="text-[11px] text-foreground-muted font-mono">{node.version}</span>
        </div>
      ))}
    </div>
  );
}

// Register custom node types (must be defined outside the component or memoized)
const nodeTypes: NodeTypes = {
  centerNode: CenterNode,
  dependencyNode: DependencyNode,
  vulnerabilityNode: VulnerabilityNode,
};

const getVulnSeverityStyles = (severity: string) => {
  switch (severity) {
    case 'critical':
      return 'bg-destructive/10 text-destructive border-destructive/20';
    case 'high':
      return 'bg-orange-500/10 text-orange-500 border-orange-500/20';
    case 'medium':
      return 'bg-warning/10 text-warning border-warning/20';
    case 'low':
      return 'bg-foreground-secondary/10 text-foreground-secondary border-foreground-secondary/20';
    default:
      return 'bg-foreground-secondary/10 text-foreground-secondary border-foreground-secondary/20';
  }
};

/** Dexcore badge: 75-100 red, 40-74 yellow, 0-39 gray */
function getDexcoreBadgeClass(score: number): string {
  if (score >= 75) return 'bg-destructive/10 text-destructive border-destructive/20';
  if (score >= 40) return 'bg-warning/10 text-warning border-warning/20';
  return 'bg-foreground-secondary/10 text-foreground-secondary border-foreground-secondary/20';
}

function WatchtowerStatusIcon({
  status,
  reason,
  label,
}: {
  status: string | null;
  reason: string | null;
  label: string;
}) {
  const content = reason ? `${label}: ${reason}` : label;
  const icon =
    status === 'pass' ? (
      <CheckCircle2 className="h-3 w-3 text-success shrink-0" />
    ) : status === 'warning' ? (
      <AlertTriangle className="h-3 w-3 text-warning shrink-0" />
    ) : status === 'fail' ? (
      <XCircle className="h-3 w-3 text-destructive shrink-0" />
    ) : null;
  if (!icon) return null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex cursor-default">{icon}</span>
      </TooltipTrigger>
      <TooltipContent>{content}</TooltipContent>
    </Tooltip>
  );
}

function RecentVersionBlock({
  version,
  currentVersion,
  getVulnSeverityStyles,
  bannedVersions,
  bannedVersionsLoading,
  canManage,
  onBanClick,
  onUnbanClick,
  versionSecurityData,
  safeVersion,
  bumpPrs,
  onPrCreated,
  orgId,
  projectId,
  dependencyId,
  assetTier,
}: {
  version: DependencyVersionItem;
  currentVersion: string;
  getVulnSeverityStyles: (severity: string) => string;
  bannedVersions: BannedVersion[];
  bannedVersionsLoading: boolean;
  canManage: boolean;
  onBanClick: (version: string) => void;
  onUnbanClick: (banId: string) => void;
  versionSecurityData: SupplyChainVersionSecurityData | null | undefined;
  safeVersion: string | null;
  bumpPrs: SupplyChainBumpPr[];
  onPrCreated: (pr: SupplyChainBumpPr) => void;
  orgId: string;
  projectId: string;
  dependencyId: string;
  assetTier: AssetTier;
}) {
  const { toast } = useToast();
  const [creatingPr, setCreatingPr] = useState(false);

  const direct = version.vulnerabilities ?? [];
  const transitive = version.transitiveVulnerabilities ?? [];
  const hasAny = direct.length > 0 || transitive.length > 0;
  const isCurrent = version.version === currentVersion;
  const isBanned = bannedVersions.some((b) => b.banned_version === version.version);
  const activeBan = bannedVersions.find((b) => b.banned_version === version.version);
  const existingPr = bumpPrs.find((pr) => pr.target_version === version.version);
  const isSafest = safeVersion != null && version.version === safeVersion;
  const onWatchtower = versionSecurityData?.onWatchtower ?? false;

  const handleCreatePr = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!orgId || !projectId || !dependencyId || creatingPr) return;
    setCreatingPr(true);
    try {
      const result = await api.createWatchtowerBumpPR(orgId, projectId, dependencyId, version.version);
      onPrCreated({
        target_version: version.version,
        pr_url: result.pr_url,
        pr_number: result.pr_number,
      });
      toast({
        title: 'PR created',
        description: `Created PR to bump to v${version.version}.`,
      });
    } catch (err: any) {
      toast({
        title: 'Failed to create PR',
        description: err.message ?? 'An unexpected error occurred',
        variant: 'destructive',
      });
    } finally {
      setCreatingPr(false);
    }
  };

  const fixedDisplay = (vuln: DependencyVersionVulnerability) => {
    const fixedVersions = vuln.fixed_versions ?? [];
    if (fixedVersions.length === 0) return '—';
    return fixedVersions.length === 1
      ? `Fixed in ${fixedVersions[0]}`
      : `Fixed in ${fixedVersions[0]} +${fixedVersions.length - 1}`;
  };

  const getDexcoreScore = (vuln: DependencyVersionVulnerability): number => {
    if (vuln.dexcore != null && Number.isFinite(vuln.dexcore)) return vuln.dexcore;
    const cvss = vuln.cvss_score ?? (vuln.severity ? (SEVERITY_TO_CVSS[vuln.severity] ?? 0) : 0);
    return calculateDexcore({
      cvss,
      epss: vuln.epss_score ?? 0,
      cisaKev: vuln.cisa_kev ?? false,
      isReachable: vuln.is_reachable ?? true,
      assetTier,
    });
  };

  const renderRow = (vuln: DependencyVersionVulnerability, introducedBy: string) => {
    const link = vuln.osv_id.startsWith('GHSA-')
      ? `https://github.com/advisories/${vuln.osv_id}`
      : `https://osv.dev/vulnerability/${vuln.osv_id}`;
    const cveAliases = (vuln.aliases ?? []).filter((a) => a.startsWith('CVE-')).slice(0, 2);
    const isTransitive = introducedBy !== 'Direct';
    const dexcoreScore = getDexcoreScore(vuln);
    return (
      <tr key={`${vuln.osv_id}-${introducedBy}`} className="hover:bg-table-hover transition-colors">
        <td className="px-4 py-3">
          <span
            className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border capitalize ${getVulnSeverityStyles(vuln.severity)}`}
          >
            {vuln.severity}
          </span>
        </td>
        <td className="px-4 py-3">
          <span
            className={`inline-flex items-center justify-center w-9 px-2 py-0.5 rounded-full text-xs font-medium border ${getDexcoreBadgeClass(dexcoreScore)}`}
            title="Dexcore score (0-100)"
          >
            {dexcoreScore}
          </span>
        </td>
        <td className="px-4 py-3">
          <div className="flex flex-col gap-1">
            <a
              href={link}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm font-medium text-foreground hover:text-foreground-secondary flex items-center gap-1 w-fit"
              onClick={(e) => e.stopPropagation()}
            >
              {vuln.osv_id}
              <ExternalLink className="h-3 w-3" />
            </a>
            {cveAliases.length > 0 && (
              <span className="text-xs text-foreground-secondary">
                {cveAliases.join(', ')}
                {(vuln.aliases ?? []).filter((a) => a.startsWith('CVE-')).length > 2 && ' ...'}
              </span>
            )}
          </div>
        </td>
        <td className="px-4 py-3 min-w-0 overflow-hidden">
          <p className="text-sm text-foreground line-clamp-2">
            {vuln.summary || 'No summary available'}
          </p>
        </td>
        <td className="px-4 py-3">
          <span className="text-sm text-foreground-secondary">{fixedDisplay(vuln)}</span>
        </td>
        <td className="px-4 py-3">
          <span className={`text-xs font-medium ${isTransitive ? 'text-foreground-secondary' : 'text-foreground'}`}>
            {introducedBy}
          </span>
        </td>
      </tr>
    );
  };

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <h3 className="text-sm font-semibold text-foreground">v{version.version}</h3>
        {onWatchtower && (
          <span className="inline-flex items-center gap-1">
            <WatchtowerStatusIcon status={version.registry_integrity_status ?? null} reason={version.registry_integrity_reason ?? null} label="Registry" />
            <WatchtowerStatusIcon status={version.install_scripts_status ?? null} reason={version.install_scripts_reason ?? null} label="Install scripts" />
            <WatchtowerStatusIcon status={version.entropy_analysis_status ?? null} reason={version.entropy_analysis_reason ?? null} label="Entropy" />
          </span>
        )}
        {isCurrent && (
          <span className="shrink-0 text-xs px-1.5 py-0.5 rounded bg-success/10 text-success border border-success/20">
            Current
          </span>
        )}
        {isSafest && (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-primary/15 text-green-600 border border-primary/30">
            <ShieldCheck className="h-3 w-3" />
            Safest version
          </span>
        )}
        {!isCurrent && existingPr ? (
          <a
            href={existingPr.pr_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-primary/15 text-green-600 border border-primary/30 hover:bg-primary/25 transition-colors"
          >
            <GitPullRequest className="h-3 w-3" />
            View PR #{existingPr.pr_number}
            <ExternalLink className="h-2.5 w-2.5" />
          </a>
        ) : !isCurrent && !isBanned && (
          <button
            type="button"
            onClick={handleCreatePr}
            disabled={creatingPr}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-primary/15 text-green-600 border border-primary/30 hover:bg-primary/25 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {creatingPr ? <Loader2 className="h-3 w-3 animate-spin" /> : <GitPullRequest className="h-3 w-3" />}
            Create PR
          </button>
        )}
        {bannedVersionsLoading ? (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-foreground-secondary/5 text-foreground-secondary border border-border">
            <Loader2 className="h-3 w-3 animate-spin" />
            Banned
          </span>
        ) : activeBan ? (
          <button
            type="button"
            onClick={() => onUnbanClick(activeBan.id)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/15 transition-colors"
          >
            <Ban className="h-3 w-3" />
            Unban
          </button>
        ) : canManage ? (
          <button
            type="button"
            onClick={() => onBanClick(version.version)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-foreground-secondary/5 text-foreground-secondary border border-border hover:bg-destructive/10 hover:text-destructive hover:border-destructive/20 transition-colors"
          >
            <Ban className="h-3 w-3" />
            Ban version
          </button>
        ) : null}
      </div>
      <div className="bg-background-card border border-border rounded-lg overflow-hidden">
        <table className="w-full table-fixed">
          <colgroup>
            <col style={{ width: '9%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '16%' }} />
            <col style={{ width: '34%' }} />
            <col style={{ width: '15%' }} />
            <col style={{ width: '18%' }} />
          </colgroup>
          <thead className="sticky top-0 bg-background-card-header z-10">
            <tr className="border-b border-border">
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                Severity
              </th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                Dexcore
              </th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                ID
              </th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                Summary
              </th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                Affected versions
              </th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                Introduced by
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {hasAny ? (
              <>
                {direct.map((v) => renderRow(v, 'Direct'))}
                {transitive.map((v) => renderRow(v, v.from_package ?? 'Transitive'))}
              </>
            ) : (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                  No vulnerabilities for this version.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * Inner component that owns its own useNodesState / useEdgesState.
 * Keyed by selectedVersionId so it fully remounts on version switch,
 * giving ReactFlow a clean slate (identical to the initial load).
 */
const SYNC_DEBOUNCE_MS = 80;

function SupplyChainGraph({
  initialNodes,
  initialEdges,
  graphLoading,
  parentName,
  selectedVersion,
  isViewingAlternateVersion,
  totalChildren,
  onReset,
  safeVersionOverlay,
}: {
  initialNodes: Node[];
  initialEdges: Edge[];
  graphLoading: boolean;
  parentName: string;
  selectedVersion: string | null;
  isViewingAlternateVersion: boolean;
  totalChildren: number;
  onReset: () => void;
  safeVersionOverlay?: React.ReactNode;
}) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const latestNodesRef = useRef(initialNodes);
  const latestEdgesRef = useRef(initialEdges);
  latestNodesRef.current = initialNodes;
  latestEdgesRef.current = initialEdges;

  // Sync when layout changes AFTER mount; debounced and never overwrite with empty when we have layout data
  useEffect(() => {
    if (initialNodes.length === 0) return;

    const timer = window.setTimeout(() => {
      const nodesToApply = latestNodesRef.current;
      const edgesToApply = latestEdgesRef.current;
      if (nodesToApply.length > 0) {
        setNodes(nodesToApply);
        setEdges(edgesToApply);
      }
    }, SYNC_DEBOUNCE_MS);

    return () => window.clearTimeout(timer);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  // Recovery: if we have layout data but React Flow state is empty (and not loading), re-apply once
  useEffect(() => {
    if (graphLoading || initialNodes.length === 0) return;
    if (nodes.length > 0) return;

    const timer = window.setTimeout(() => {
      setNodes(latestNodesRef.current);
      setEdges(latestEdgesRef.current);
    }, 200);

    return () => window.clearTimeout(timer);
  }, [graphLoading, initialNodes.length, nodes.length, setNodes, setEdges]);

  return (
    <>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.3, maxZoom: 1.2 }}
        minZoom={0.3}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
        defaultEdgeOptions={{ type: 'smoothstep' }}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={16}
          size={1.2}
          color="rgba(148, 163, 184, 0.3)"
        />
      </ReactFlow>

      {/* Safe version card overlay (top-right) */}
      {safeVersionOverlay && (
        <div className="absolute top-4 right-4 sm:right-6 lg:right-8 z-40">
          {safeVersionOverlay}
        </div>
      )}

      {/* Floating reset button when viewing alternate version */}
      {isViewingAlternateVersion && !graphLoading && (
        <button
          onClick={onReset}
          className="absolute top-4 right-4 sm:right-6 lg:right-8 z-40 flex items-center gap-1.5 rounded-lg border border-border bg-background-card/95 backdrop-blur-sm px-3 py-1.5 shadow-md text-xs font-medium text-foreground-secondary hover:text-foreground hover:border-primary/40 transition-colors cursor-pointer"
        >
          <RotateCcw className="h-3 w-3" />
          Reset to current version
        </button>
      )}

      {/* Loading overlay while switching versions */}
      {graphLoading && (
        <div className="absolute inset-0 bg-background/40 flex items-center justify-center z-50">
          <Loader2 className="h-8 w-8 text-primary animate-spin" />
        </div>
      )}
    </>
  );
}

export interface SupplyChainContentProps {
  orgId: string;
  projectId: string;
  dependencyId: string;
  /** Optional: when loading we show a graph skeleton with this name/version */
  dependencyName?: string;
  dependencyVersion?: string;
  /** Optional: when a version is banned or unbanned, called so the parent can update the dependencies list (e.g. sidebar "Version banned" badge). */
  onDependencyListBanChange?: (version: string, isBanned: boolean) => void;
}

export function SupplyChainContent({ orgId, projectId, dependencyId, dependencyName, dependencyVersion, onDependencyListBanChange }: SupplyChainContentProps) {
  const { toast } = useToast();

  const [data, setData] = useState<SupplyChainResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [projectAssetTier, setProjectAssetTier] = useState<AssetTier>('EXTERNAL');
  const [showAllPaths, setShowAllPaths] = useState(false);
  const [versionsData, setVersionsData] = useState<DependencyVersionsResponse | null>(null);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [versionsLoadingMore, setVersionsLoadingMore] = useState(false);
  const versionsLoadMoreRef = useRef<HTMLDivElement>(null);

  // Version switching state
  const [selectedVersionId, setSelectedVersionId] = useState<string | null>(null);
  const [selectedVersion, setSelectedVersion] = useState<string | null>(null);
  const [versionChildren, setVersionChildren] = useState<SupplyChainChild[] | null>(null);
  const [versionVulnerabilities, setVersionVulnerabilities] = useState<SupplyChainResponse['parent']['vulnerabilities'] | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  /** 'preview' = switched via SafeVersionCard Preview; 'dropdown' = via CenterNode dropdown. Drives which spinner shows. */
  const [versionLoadSource, setVersionLoadSource] = useState<'preview' | 'dropdown' | 'sidebar' | null>(null);
  const isViewingAlternateVersion = selectedVersionId !== null && data !== null && selectedVersionId !== data.parent.dependency_version_id;

  // Policies + bump PRs state
  const [policies, setPolicies] = useState<ProjectEffectivePolicies | null>(null);
  const [bumpPrs, setBumpPrs] = useState<SupplyChainBumpPr[]>([]);

  // Latest safe version state
  const [safeVersionData, setSafeVersionData] = useState<LatestSafeVersionResponse | null>(null);
  const [safeVersionLoading, setSafeVersionLoading] = useState(false);
  const [safeVersionSeverity, setSafeVersionSeverity] = useState('high');
  const safeVersionRequestRef = useRef(0);

  // Banned versions state
  const [bannedVersions, setBannedVersions] = useState<BannedVersion[]>([]);
  const [bannedVersionsLoading, setBannedVersionsLoading] = useState(false);
  const [banSidebarOpen, setBanSidebarOpen] = useState(false);
  const [selectedVersionToBan, setSelectedVersionToBan] = useState<string>('');
  const [unbanSidebarOpen, setUnbanSidebarOpen] = useState(false);
  const [selectedBanToRemove, setSelectedBanToRemove] = useState<BannedVersion | null>(null);
  const [versionSidebarOpen, setVersionSidebarOpen] = useState(false);

  // Bump all state
  const [bumpingAll, setBumpingAll] = useState(false);

  // Counter to force safe-version re-fetch after ban/unban
  const [banRefreshCounter, setBanRefreshCounter] = useState(0);

  // Bump scope: org / team / project (loaded async; until then show loading in ban strip to avoid empty flash when prefetch wins)
  const [bumpScope, setBumpScope] = useState<'org' | 'team' | 'project'>('project');
  const [bumpScopeLoading, setBumpScopeLoading] = useState(true);
  const [bumpTeamId, setBumpTeamId] = useState<string | undefined>(undefined);

  // Zombie (unused) package: remove PR state (from server or set after creating PR)
  const [removePrUrl, setRemovePrUrl] = useState<string | null>(null);
  const [removingPr, setRemovingPr] = useState(false);

  // Can manage (ban/deprecate) when org or team scope; neither permission = project only = no ban
  const canManage = bumpScope === 'org' || bumpScope === 'team';

  // Data for the graph: same as effectiveData but parent.vulnerabilities is only vulns affecting the displayed version
  const graphData: SupplyChainResponse | null = data
    ? isViewingAlternateVersion && versionChildren !== null
      ? {
          ...data,
          parent: {
            ...data.parent,
            version: selectedVersion ?? data.parent.version,
            vulnerabilities: versionVulnerabilities ?? [],
          },
          children: versionChildren,
        }
      : {
          ...data,
          parent: {
            ...data.parent,
            vulnerabilities: data.parent.vulnerabilities_affecting_current_version ?? data.parent.vulnerabilities,
          },
        }
    : null;

  // Effective data for table etc. (table uses data.parent.vulnerabilities directly for “all” vulns)
  const effectiveData: SupplyChainResponse | null = graphData;

  // Fetch bump scope on mount (so we know canManage; until resolved, CenterNode shows loading strip to avoid empty flash when prefetch wins)
  useEffect(() => {
    if (!orgId || !projectId) return;
    setBumpScopeLoading(true);
    api.getBumpScope(orgId, projectId)
      .then((res) => {
        setBumpScope(res.scope);
        if (res.team_id) setBumpTeamId(res.team_id);
      })
      .catch(() => setBumpScope('project'))
      .finally(() => setBumpScopeLoading(false));
  }, [orgId, projectId]);

  // Load project asset tier for Dexcore (use cache or fetch)
  useEffect(() => {
    if (!orgId || !projectId) return;
    const cached = api.getCachedProject(orgId, projectId);
    if (cached?.asset_tier) {
      setProjectAssetTier(cached.asset_tier);
      return;
    }
    api.getProject(orgId, projectId, false).then((p) => setProjectAssetTier(p.asset_tier ?? 'EXTERNAL')).catch(() => {});
  }, [orgId, projectId]);

  useEffect(() => {
    if (!orgId || !projectId || !dependencyId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    // Reset version switching state and banned versions on initial load
    setSelectedVersionId(null);
    setSelectedVersion(null);
    setVersionChildren(null);
    setVersionVulnerabilities(null);
    setBumpPrs([]);
    setBannedVersions([]);
    setBannedVersionsLoading(true);
    setRemovePrUrl(null);

    // Use prefetched data if available (from tab hover), otherwise fetch fresh
    const dataPromise = api.consumePrefetchedSupplyChain(orgId, projectId, dependencyId)
      ?? Promise.all([
        api.getDependencySupplyChain(orgId, projectId, dependencyId),
        api.getProjectPolicies(orgId, projectId).catch(() => null),
      ]);

    dataPromise
      .then(([res, policiesRes]) => {
        if (res == null) {
          setError('Failed to load supply chain data');
          return;
        }
        setData(res);
        setSelectedVersionId(res.parent.dependency_version_id);
        setSelectedVersion(res.parent.version);
        setBumpPrs(res.bumpPrs ?? []);
        setRemovePrUrl(res.parent.remove_pr_url ?? null);
        setPolicies(policiesRes ?? null);
        // Use banned_versions from initial response so we don't need a second request
        if (res.banned_versions !== undefined) {
          setBannedVersions(res.banned_versions);
          setBannedVersionsLoading(false);
          setBanRefreshCounter((c) => c + 1);
        } else {
          // Backend didn't return banned_versions (e.g. old version); fetch once
          const depId = res.parent.dependency_id;
          if (depId) {
            setBannedVersionsLoading(true);
            api.getBannedVersions(orgId, depId, projectId ?? undefined)
              .then((bannedRes) => {
                setBannedVersions(bannedRes.banned_versions);
                setBanRefreshCounter((c) => c + 1);
              })
              .catch((err) => console.error('Failed to fetch banned versions:', err))
              .finally(() => setBannedVersionsLoading(false));
          }
        }
        if (!policiesRes && orgId && projectId) {
          api.getProjectPolicies(orgId, projectId).then(setPolicies).catch(() => {});
        }
      })
      .catch((err) => setError(err.message ?? 'Failed to load supply chain data'))
      .finally(() => setLoading(false));
  }, [orgId, projectId, dependencyId]);

  const VERSIONS_PAGE_SIZE = 10;

  // Fetch first page of versions (fast initial load)
  useEffect(() => {
    if (!orgId || !projectId || !dependencyId) return;
    setVersionsLoading(true);
    api
      .getDependencyVersions(orgId, projectId, dependencyId, { limit: VERSIONS_PAGE_SIZE, offset: 0 })
      .then(setVersionsData)
      .catch(() => setVersionsData(null))
      .finally(() => setVersionsLoading(false));
  }, [orgId, projectId, dependencyId]);

  // Backend returns semver-sorted; we show what we've fetched so far
  const displayedVersions = versionsData?.versions ?? [];
  const totalVersions = versionsData?.total ?? 0;
  const hasMoreVersions = displayedVersions.length < totalVersions;

  const loadMoreVersions = useCallback(() => {
    if (!orgId || !projectId || !dependencyId || versionsLoadingMore || !hasMoreVersions || !versionsData) return;
    setVersionsLoadingMore(true);
    const offset = versionsData.versions.length;
    api
      .getDependencyVersions(orgId, projectId, dependencyId, { limit: VERSIONS_PAGE_SIZE, offset })
      .then((res) => {
        setVersionsData((prev) =>
          prev ? { ...prev, versions: [...prev.versions, ...res.versions] } : null
        );
      })
      .catch(() => {})
      .finally(() => setVersionsLoadingMore(false));
  }, [orgId, projectId, dependencyId, versionsLoadingMore, hasMoreVersions, versionsData]);

  // Hold sentinel DOM node in state so effect runs after it's mounted
  const [versionsLoadMoreNode, setVersionsLoadMoreNode] = useState<HTMLDivElement | null>(null);
  const setVersionsLoadMoreRef = useCallback((el: HTMLDivElement | null) => {
    setVersionsLoadMoreNode(el);
  }, []);

  useEffect(() => {
    if (!hasMoreVersions || !versionsLoadMoreNode) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting) loadMoreVersions();
      },
      { threshold: 0.1 }
    );
    observer.observe(versionsLoadMoreNode);
    return () => observer.disconnect();
  }, [hasMoreVersions, versionsLoadMoreNode, loadMoreVersions]);

  // Fetch latest safe version once supply chain data is loaded
  useEffect(() => {
    if (!orgId || !projectId || !dependencyId || !data) return;
    const requestId = ++safeVersionRequestRef.current;
    setSafeVersionLoading(true);
    api
      .getLatestSafeVersion(orgId, projectId, dependencyId, safeVersionSeverity, true)
      .then((res) => {
        if (requestId === safeVersionRequestRef.current) {
          setSafeVersionData(res);
        }
      })
      .catch((err) => {
        console.error('Failed to fetch latest safe version:', err);
        if (requestId === safeVersionRequestRef.current) {
          setSafeVersionData(null);
        }
      })
      .finally(() => {
        if (requestId === safeVersionRequestRef.current) {
          setSafeVersionLoading(false);
        }
      });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, projectId, dependencyId, data, safeVersionSeverity, banRefreshCounter]);

  // Severity change handler for safe version card
  const handleSafeVersionSeverityChange = useCallback((newSeverity: string) => {
    setSafeVersionSeverity(newSeverity);
    // The useEffect above will re-fetch with the new severity
  }, []);

  // Re-fetch policies when tab becomes visible (e.g. user returned from settings after changing policies)
  useEffect(() => {
    if (!orgId || !projectId) return;
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        api.getProjectPolicies(orgId, projectId).then(setPolicies).catch(() => {});
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  }, [orgId, projectId]);

  // Fetch banned versions when data loads, and bump refresh counter so safe version re-fetches
  const fetchBannedVersions = useCallback(() => {
    if (!orgId || !data?.parent?.dependency_id) return Promise.resolve();
    return api.getBannedVersions(orgId, data.parent.dependency_id, projectId ?? undefined)
      .then((res) => {
        setBannedVersions(res.banned_versions);
        setBanRefreshCounter((c) => c + 1);
      })
      .catch((err) => console.error('Failed to fetch banned versions:', err));
  }, [orgId, data, projectId]);

  // Bump handler — scoped by bumpScope
  const handleBumpAll = useCallback(async () => {
    if (!orgId || !projectId || !dependencyId || !data || !safeVersionData?.safeVersion) return;
    setBumpingAll(true);
    try {
      if (bumpScope === 'project') {
        // Single project bump
        await api.createWatchtowerBumpPR(orgId, projectId, dependencyId, safeVersionData.safeVersion);
        toast({
          title: 'PR created',
          description: `Created PR to bump this project to v${safeVersionData.safeVersion}.`,
        });
      } else {
        // Org or team scope
        const result = await api.bumpAllProjects(orgId, data.parent.dependency_id!, safeVersionData.safeVersion, bumpScope === 'team' ? bumpTeamId : undefined);
        const successCount = result.pr_results.filter((r) => r.pr_url).length;
        const errorCount = result.pr_results.filter((r) => r.error).length;

        if (result.affected_projects === 0) {
          toast({
            title: 'No projects to bump',
            description: `All ${bumpScope === 'team' ? 'team' : 'organization'} projects are already on v${safeVersionData.safeVersion}.`,
          });
        } else if (successCount > 0 && errorCount === 0) {
          toast({
            title: 'PRs created',
            description: `Created ${successCount} PR${successCount !== 1 ? 's' : ''} to bump projects to v${safeVersionData.safeVersion}.`,
          });
        } else if (successCount > 0 && errorCount > 0) {
          toast({
            title: 'Some PRs created',
            description: `Created ${successCount} PR${successCount !== 1 ? 's' : ''}, but ${errorCount} failed.`,
            variant: 'destructive',
          });
        } else {
          toast({
            title: 'Failed to create PRs',
            description: `All ${errorCount} PR creation${errorCount !== 1 ? 's' : ''} failed.`,
            variant: 'destructive',
          });
        }
      }
    } catch (err: any) {
      toast({
        title: 'Failed to bump',
        description: err.message || 'An unexpected error occurred',
        variant: 'destructive',
      });
    } finally {
      setBumpingAll(false);
    }
  }, [orgId, projectId, dependencyId, data, safeVersionData, bumpScope, bumpTeamId, toast]);

  // Ban click handler — opens sidebar
  const handleBanClickRef = useRef<(version: string) => void>(() => { });
  handleBanClickRef.current = useCallback((version: string) => {
    setSelectedVersionToBan(version);
    setBanSidebarOpen(true);
  }, []);
  const stableHandleBanClick = useCallback((version: string) => {
    handleBanClickRef.current(version);
  }, []);

  // Unban click handler — opens sidebar
  const handleUnbanClickRef = useRef<(banId: string) => void>(() => { });
  handleUnbanClickRef.current = useCallback((banId: string) => {
    const ban = bannedVersions.find((b) => b.id === banId);
    if (ban) {
      setSelectedBanToRemove(ban);
      setUnbanSidebarOpen(true);
    }
  }, [bannedVersions]);
  const stableHandleUnbanClick = useCallback((banId: string) => {
    handleUnbanClickRef.current(banId);
  }, []);

  const versionChangeRequestRef = useRef(0);

  const doVersionChange = useCallback((
    newVersionId: string,
    source: 'preview' | 'dropdown' | 'sidebar',
  ) => {
    if (!orgId || !projectId || !dependencyId || !data) return;

    if (newVersionId === data.parent.dependency_version_id) {
      setSelectedVersionId(data.parent.dependency_version_id);
      setSelectedVersion(data.parent.version);
      setVersionChildren(null);
      setVersionVulnerabilities(null);
      setGraphLoading(false);
      setVersionLoadSource(null);
      return;
    }

    const versionInfo =
      data.availableVersions.find((v) => v.dependency_version_id === newVersionId) ??
      data.availableVersions.find((v) => v.version === newVersionId) ??
      (safeVersionData?.safeVersion && data.availableVersions.find((v) => v.version === safeVersionData.safeVersion));
    if (!versionInfo) return;

    const req = ++versionChangeRequestRef.current;
    setVersionLoadSource(source);
    setSelectedVersionId(versionInfo.dependency_version_id);
    setSelectedVersion(versionInfo.version);
    setVersionChildren(null);
    setVersionVulnerabilities(null);
    setGraphLoading(true);

    api
      .getSupplyChainForVersion(orgId, projectId, dependencyId, versionInfo.dependency_version_id)
      .then((res) => {
        if (req !== versionChangeRequestRef.current) return;
        setVersionChildren(res.children);
        setVersionVulnerabilities(res.vulnerabilities ?? []);
      })
      .catch((err) => {
        console.error('Failed to load version supply chain:', err);
        if (req !== versionChangeRequestRef.current) return;
        setSelectedVersionId(data.parent.dependency_version_id);
        setSelectedVersion(data.parent.version);
        setVersionChildren(null);
        setVersionVulnerabilities(null);
      })
      .finally(() => {
        if (req === versionChangeRequestRef.current) {
          setGraphLoading(false);
          setVersionLoadSource(null);
        }
      });
  }, [orgId, projectId, dependencyId, data, safeVersionData?.safeVersion]);

  const handleSimulateSafeVersion = useCallback((versionId: string) => {
    doVersionChange(versionId, 'preview');
  }, [doVersionChange]);

  const handleVersionChangeFromDropdown = useCallback((versionId: string) => {
    doVersionChange(versionId, 'dropdown');
  }, [doVersionChange]);

  const handlePreviewVersionFromSidebar = useCallback((version: string) => {
    if (!data) return;
    const versionInfo = data.availableVersions?.find((v) => v.version === version);
    if (versionInfo) {
      doVersionChange(versionInfo.dependency_version_id, 'sidebar');
      setVersionSidebarOpen(false);
    }
  }, [data, doVersionChange]);

  // PR created callback
  const handlePrCreatedRef = useRef<(pr: SupplyChainBumpPr) => void>(() => { });
  handlePrCreatedRef.current = useCallback((pr: SupplyChainBumpPr) => {
    setBumpPrs((prev) => {
      // Remove any existing PR for a different target version (backend closes them)
      const filtered = prev.filter((p) => p.target_version === pr.target_version);
      // Add the new one if not already present
      if (filtered.some((p) => p.pr_url === pr.pr_url)) return filtered;
      return [...filtered, pr];
    });
  }, []);
  const stableHandlePrCreated = useCallback((pr: SupplyChainBumpPr) => {
    handlePrCreatedRef.current(pr);
  }, []);

  // Reset to original version handler
  const handleReset = useCallback(() => {
    if (!data) return;
    setSelectedVersionId(data.parent.dependency_version_id);
    setSelectedVersion(data.parent.version);
    setVersionChildren(null);
    setVersionVulnerabilities(null);
  }, [data]);

  // Create PR to remove zombie (unused) dependency
  const handleCreateRemovePr = useCallback(async () => {
    if (!orgId || !projectId || !dependencyId || removingPr) return;
    setRemovingPr(true);
    try {
      const result = await api.createRemoveDependencyPR(orgId, projectId, dependencyId);
      setRemovePrUrl(result.pr_url);
      toast({
        title: result.already_exists ? 'Removal PR already exists' : 'Removal PR created',
        description: result.already_exists ? 'A PR to remove this dependency already exists.' : undefined,
      });
    } catch (err) {
      console.error('Failed to create remove PR:', err);
      toast({
        variant: 'destructive',
        title: 'Failed to create removal PR',
        description: err instanceof Error ? err.message : 'Something went wrong.',
      });
    } finally {
      setRemovingPr(false);
    }
  }, [orgId, projectId, dependencyId, removingPr, toast]);

  // Compute graph layout from data (memoized to reduce useGraphLayout churn)
  const versionSwitcher = useMemo(
    () =>
      data
        ? {
            availableVersions: data.availableVersions ?? [],
            selectedVersionId: selectedVersionId ?? data.parent.dependency_version_id,
            selectedVersion: selectedVersion ?? data.parent.version,
            onVersionChange: handleVersionChangeFromDropdown,
          }
        : undefined,
    [
      data,
      selectedVersionId,
      selectedVersion,
      handleVersionChangeFromDropdown,
    ]
  );

  const extras = useMemo(
    () =>
      data
        ? {
            policies,
            isViewingAlternateVersion,
            originalVersion: data.parent.version,
            bumpPrs,
            dependencyId: dependencyId ?? '',
            orgId: orgId ?? '',
            projectId: projectId ?? '',
            onPrCreated: stableHandlePrCreated,
            canManage,
            bannedVersions,
            bannedVersionsLoading,
            bumpScopeLoading,
            onBanClick: stableHandleBanClick,
            onUnbanClick: stableHandleUnbanClick,
            currentVersion: data.parent.version,
            versionSecurityData: data.versionSecurityData ?? null,
            safeVersion: safeVersionData?.safeVersion ?? null,
            versionSwitching: graphLoading && (versionLoadSource === 'dropdown' || versionLoadSource === 'sidebar'),
            onOpenVersionsSidebar: () => setVersionSidebarOpen(true),
            assetTier: projectAssetTier,
          }
        : undefined,
    [
      data,
      policies,
      graphLoading,
      versionLoadSource,
      isViewingAlternateVersion,
      bumpPrs,
      dependencyId,
      orgId,
      projectId,
      projectAssetTier,
      stableHandlePrCreated,
      canManage,
      bannedVersions,
      bannedVersionsLoading,
      bumpScopeLoading,
      stableHandleBanClick,
      stableHandleUnbanClick,
      safeVersionData?.safeVersion,
    ]
  );

  const { nodes: layoutNodes, edges: layoutEdges } = useGraphLayout(effectiveData ?? null, versionSwitcher, extras);

  const skeletonNodes = useMemo(
    () => [
      {
        id: 'skeleton-center',
        type: 'skeletonCenterNode',
        position: SKELETON_CENTER_POS,
        data: { packageName: dependencyName, packageVersion: dependencyVersion },
      },
    ],
    [dependencyName, dependencyVersion]
  );
  const [graphNodes, setGraphNodes, onGraphNodesChange] = useNodesState<Node>(skeletonNodes);
  const [graphEdges, setGraphEdges, onGraphEdgesChange] = useEdgesState<Edge>([]);

  // Show skeleton until we have synced real layout into graph state. Otherwise when loading
  // becomes false we briefly render graphNodes (still skeleton) with real nodeTypes, and
  // the skeleton node type is missing from nodeTypes so the center node disappears.
  const stillShowingSkeleton =
    loading ||
    (layoutNodes.length > 0 && graphNodes.length === 1 && graphNodes[0]?.id === 'skeleton-center');

  // Stable signature: include node structure AND center-node extras (ban/canManage, versionSwitching) so we re-apply
  // when those change. Must include versionSwitching so spinner shows in dropdown during load.
  const layoutSignature =
    layoutNodes.length + '-' + layoutNodes.map((n) => n.id).join(',') +
    '-' + (versionChildren?.length ?? -1) + '-' + (versionChildren?.map((c) => c.dependency_version_id).join(',') ?? '') +
    '-' + [bannedVersionsLoading, bumpScopeLoading, canManage, bannedVersions.length, safeVersionData?.safeVersion ?? '', graphLoading && (versionLoadSource === 'dropdown' || versionLoadSource === 'sidebar')].join(',');

  const lastAppliedLayoutRef = useRef<string | null>(null);
  if (loading) lastAppliedLayoutRef.current = null;

  // Sync real layout into graph when data loads or layout meaningfully changes; only apply when
  // signature changed to avoid effect loop (setGraphNodes every render -> disappear).
  useEffect(() => {
    if (!loading && layoutNodes.length > 0 && lastAppliedLayoutRef.current !== layoutSignature) {
      lastAppliedLayoutRef.current = layoutSignature;
      setGraphNodes(layoutNodes);
      setGraphEdges(layoutEdges);
    }
  }, [loading, layoutSignature, layoutNodes, layoutEdges, setGraphNodes, setGraphEdges]);

  // Debounced sync when layout changes (e.g. version switch); re-run when versionChildren loads so graph updates
  useEffect(() => {
    if (loading || layoutNodes.length === 0) return;
    const t = setTimeout(() => {
      if (lastAppliedLayoutRef.current === layoutSignature) return;
      lastAppliedLayoutRef.current = layoutSignature;
      setGraphNodes(layoutNodes);
      setGraphEdges(layoutEdges);
    }, SYNC_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [loading, layoutSignature, layoutNodes, layoutEdges, setGraphNodes, setGraphEdges, versionChildren]);

  if (!orgId || !projectId || !dependencyId) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 bg-background-content min-h-[calc(100vh-3rem)]">
        <p className="text-foreground-secondary">Missing org, project, or dependency in URL.</p>
      </main>
    );
  }

  if (!loading && (error || !data)) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 bg-background-content min-h-[calc(100vh-3rem)]">
        <p className="text-destructive">{error ?? 'Failed to load supply chain data'}</p>
      </main>
    );
  }

  const displayData = effectiveData ?? null;
  const totalChildren = displayData?.children.length ?? 0;
  const isDirect = data?.parent?.is_direct ?? false;
  const isZombie = isDirect && (data?.parent?.files_importing_count ?? 0) === 0;
  const hasAncestors = (data?.ancestors?.length ?? 0) > 0;
  const displayedPaths = showAllPaths ? (data?.ancestors ?? []) : (data?.ancestors ?? []).slice(0, 1);

  const isViewingSimulatedSafeVersion =
    isViewingAlternateVersion &&
    !graphLoading &&
    versionChildren !== null &&
    safeVersionData?.safeVersionId != null &&
    selectedVersionId === safeVersionData.safeVersionId;

  return (
    <main className="relative h-full w-full min-h-0 bg-background-content">
      {/* Overlay header and notices on top of the graph */}
      <div className="absolute top-0 left-0 right-0 z-30 pointer-events-none">
        <div className="pl-12 pr-4 sm:pr-6 lg:pr-8 pt-4">
          {/* Transitive dependency notice + paths (only show when loaded and for the original version) */}
          {!loading && data && !isViewingAlternateVersion && !isDirect && hasAncestors && (
            <div className="mb-4 space-y-3 pointer-events-auto">
              <div className="rounded-lg border border-amber-500/15 bg-amber-500/5 px-4 py-3.5">
                <div className="flex items-center gap-2.5 mb-1">
                  <AlertTriangle className="h-3.5 w-3.5 text-amber-500 flex-shrink-0" />
                  <span className="text-sm font-medium text-foreground">Transitive dependency</span>
                </div>
                <p className="text-xs text-foreground-secondary leading-relaxed pl-6">
                  Imported by{' '}
                  <span className="font-mono font-medium text-foreground">
                    {data.ancestors[0]?.[0]?.name ?? 'unknown'}
                  </span>
                  . To update or remove this package, manage the direct dependency that brings it in.
                </p>
              </div>

              {/* Dependency paths */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-foreground-secondary uppercase tracking-wider">
                    Dependency Path{data.ancestors.length > 1 ? 's' : ''}
                  </span>
                  {data.ancestors.length > 1 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setShowAllPaths(!showAllPaths)}
                      className="gap-1.5 h-6 text-xs text-foreground-secondary hover:text-foreground px-2"
                    >
                      {showAllPaths ? 'Show primary' : `All ${data.ancestors.length} paths`}
                      {showAllPaths ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                    </Button>
                  )}
                </div>
                <div className="space-y-2">
                  {displayedPaths.map((path, idx) => (
                    <div key={idx} className="rounded-lg border border-border bg-background-card px-4 py-3">
                      <AncestorPath path={path} />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Graph visualization — single ReactFlow so zoom/viewport is preserved when switching from skeleton to real nodes */}
      <div className="absolute inset-0 overflow-hidden">
        <ReactFlow
          nodes={stillShowingSkeleton ? skeletonNodes : graphNodes}
          edges={stillShowingSkeleton ? [] : graphEdges}
          onNodesChange={onGraphNodesChange}
          onEdgesChange={onGraphEdgesChange}
          nodeTypes={stillShowingSkeleton ? skeletonCenterNodeTypes : nodeTypes}
          fitView={stillShowingSkeleton}
          fitViewOptions={{ padding: 0.3, maxZoom: 1.2 }}
          minZoom={0.3}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
          defaultEdgeOptions={{ type: 'smoothstep' }}
        >
          <Background
            variant={BackgroundVariant.Dots}
            gap={16}
            size={1.2}
            color="rgba(148, 163, 184, 0.3)"
          />
        </ReactFlow>
        {!loading && (
          <>
            <div className="absolute top-4 right-4 sm:right-6 lg:right-8 z-40 flex flex-col gap-2 items-end">
              {isZombie ? (
                <UnusedInProjectCard
                  removePrUrl={removePrUrl ?? data?.parent?.remove_pr_url ?? null}
                  removePrNumber={data?.parent?.remove_pr_number ?? null}
                  onRemove={handleCreateRemovePr}
                  removing={removingPr}
                />
              ) : (
                <SafeVersionCard
                  data={safeVersionData}
                  loading={safeVersionLoading}
                  severity={safeVersionSeverity}
                  onSeverityChange={handleSafeVersionSeverityChange}
                  onSimulate={handleSimulateSafeVersion}
                  canManage={canManage}
                  onBumpAll={handleBumpAll}
                  bumpingAll={bumpingAll}
                  bumpScope={bumpScope}
                  isViewingSimulatedSafeVersion={isViewingSimulatedSafeVersion}
                  simulating={graphLoading && versionLoadSource === 'preview'}
                />
              )}
              {isViewingAlternateVersion && !graphLoading && (
                <Button variant="outline" size="sm" onClick={handleReset}>
                  <RotateCcw className="h-3 w-3" />
                  Reset to current version
                </Button>
              )}
            </div>
          </>
        )}
      </div>

      {/* Recent versions: commented out for now (full-screen graph only)
      <section className="mt-8" aria-labelledby="recent-versions-heading">
        <h2 id="recent-versions-heading" className="text-sm font-medium text-foreground-secondary uppercase tracking-wider mb-3">
          Recent versions
        </h2>
        {versionsLoading && !versionsData ? (
          <div className="space-y-6">
            {[1, 2].map((i) => (
              <div key={i}>
                <div className="h-5 w-24 bg-muted rounded animate-pulse mb-2" />
                <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                  <table className="w-full table-fixed">
                    <thead className="bg-background-card-header">
                      <tr className="border-b border-border">
                        <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[10%]" />
                        <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[18%]" />
                        <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[40%]" />
                        <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[17%]" />
                        <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[15%]" />
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {[1, 2, 3].map((j) => (
                        <tr key={j} className="animate-pulse">
                          <td className="px-4 py-3"><div className="h-5 w-16 bg-muted rounded-full" /></td>
                          <td className="px-4 py-3"><div className="h-4 w-24 bg-muted rounded" /></td>
                          <td className="px-4 py-3"><div className="h-4 w-48 bg-muted rounded" /></td>
                          <td className="px-4 py-3"><div className="h-4 w-20 bg-muted rounded" /></td>
                          <td className="px-4 py-3"><div className="h-4 w-16 bg-muted rounded" /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
          </div>
        ) : !versionsData?.versions?.length ? (
          <div className="bg-background-card border border-border rounded-lg px-6 py-8 text-center text-sm text-foreground-secondary">
            No version data available.
          </div>
        ) : (
          <div className="max-h-[600px] overflow-y-auto custom-scrollbar space-y-6">
            {displayedVersions.map((ver) => (
              <RecentVersionBlock
                key={ver.version}
                version={ver}
                currentVersion={data.parent.version}
                getVulnSeverityStyles={getVulnSeverityStyles}
                bannedVersions={bannedVersions}
                bannedVersionsLoading={bannedVersionsLoading}
                canManage={canManage}
                onBanClick={stableHandleBanClick}
                onUnbanClick={stableHandleUnbanClick}
                versionSecurityData={data.versionSecurityData ?? null}
                safeVersion={safeVersionData?.safeVersion ?? null}
                bumpPrs={bumpPrs}
                onPrCreated={stableHandlePrCreated}
                orgId={orgId!}
                projectId={projectId!}
                dependencyId={dependencyId!}
                assetTier={projectAssetTier}
              />
            ))}
            {hasMoreVersions && (
              <div ref={setVersionsLoadMoreRef} className="flex justify-center py-4 min-h-[50px]">
                {versionsLoadingMore ? (
                  <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" />
                ) : null}
              </div>
            )}
          </div>
        )}
      </section>
      */}

      {/* Versions sidebar (supply chain: open from center node) */}
      {versionSidebarOpen && data && orgId && projectId && dependencyId && (
        <VersionSidebar
          packageName={data.parent.name}
          currentVersion={data.parent.version}
          organizationId={orgId}
          projectId={projectId}
          dependencyId={dependencyId}
          versionsInQuarantine={data.versionSecurityData?.quarantinedVersions ?? []}
          onClose={() => setVersionSidebarOpen(false)}
          variant="supply-chain"
          onPreviewVersion={handlePreviewVersionFromSidebar}
          onWatchtower={data.versionSecurityData?.onWatchtower ?? false}
        />
      )}

      {/* Ban version sidebar — only when we have data */}
      {data && (
        <>
          <BanVersionSidebar
            open={banSidebarOpen}
            onOpenChange={setBanSidebarOpen}
            versionToBan={selectedVersionToBan}
            availableVersions={data.availableVersions ?? []}
            bannedVersions={bannedVersions}
            orgId={orgId}
            dependencyId={data.parent.dependency_id ?? ''}
            packageName={data.parent.name}
            bumpScope={bumpScope}
            bumpTeamId={bumpTeamId}
            onBanComplete={(bannedVersion) => {
              fetchBannedVersions();
              onDependencyListBanChange?.(bannedVersion, true);
            }}
          />
          <RemoveBanSidebar
            open={unbanSidebarOpen}
            onOpenChange={setUnbanSidebarOpen}
            ban={selectedBanToRemove}
            orgId={orgId}
            dependencyName={data.parent.name}
            onUnbanComplete={(unbannedVersion) => {
              fetchBannedVersions();
              onDependencyListBanChange?.(unbannedVersion, false);
            }}
          />
        </>
      )}
    </main>
  );
}

export default function DependencySupplyChainPage() {
  const { orgId, projectId, dependencyId } = useParams<{
    orgId: string;
    projectId: string;
    dependencyId: string;
  }>();
  if (!orgId || !projectId || !dependencyId) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 bg-background-content min-h-[calc(100vh-3rem)]">
        <p className="text-foreground-secondary">Missing org, project, or dependency in URL.</p>
      </main>
    );
  }
  return <SupplyChainContent orgId={orgId} projectId={projectId} dependencyId={dependencyId} />;
}
