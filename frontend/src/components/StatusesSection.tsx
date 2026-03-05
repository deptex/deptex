import { useState, useEffect, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useParams, useOutletContext } from 'react-router-dom';
import { Plus, Lock, Trash2, Loader2, Check, X, Info, Eye } from 'lucide-react';
import { api, OrganizationStatus, OrganizationAssetTier, OrganizationPolicyChange, ProjectPolicyChangeRequest } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { useToast } from '@/hooks/use-toast';
import { PolicyCodeEditor } from '@/components/PolicyCodeEditor';
import { PolicyDiffViewer, getDiffLineCounts } from '@/components/PolicyDiffViewer';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from '@/components/ui/dialog';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { RoleBadge } from '@/components/RoleBadge';
import { cn } from '@/lib/utils';

/** Extract the body of a named function from full code. */
function extractFunctionBody(code: string, fnName: string): string | null {
  const regex = new RegExp(`function\\s+${fnName}\\s*\\([^)]*\\)\\s*\\{`, 'g');
  const match = regex.exec(code);
  if (!match) return null;
  const startIdx = match.index + match[0].length;
  let depth = 1;
  let i = startIdx;
  while (i < code.length && depth > 0) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') depth--;
    i++;
  }
  return code.slice(startIdx, i - 1).trim();
}

/** Wrap projectStatus body into full function. */
function wrapProjectStatusBody(body: string): string {
  const lines = body.trim().split('\n').map((l) => (l ? `  ${l}` : ''));
  return `function projectStatus(context) {\n${lines.join('\n')}\n}`;
}

const DEFAULT_PROJECT_STATUS_BODY = 'return { status: "Compliant", violations: [] };';

function formatRelativeTime(dateStr: string): string {
  const d = new Date(dateStr);
  const now = new Date();
  const sec = Math.floor((now.getTime() - d.getTime()) / 1000);
  if (sec < 60) return 'just now';
  if (sec < 3600) return `${Math.floor(sec / 60)} minutes ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} hours ago`;
  if (sec < 604800) return `${Math.floor(sec / 86400)} days ago`;
  return d.toLocaleDateString();
}

const COLOR_PRESETS = [
  { color: '#ef4444', name: 'Red' },
  { color: '#f97316', name: 'Orange' },
  { color: '#eab308', name: 'Yellow' },
  { color: '#22c55e', name: 'Green' },
  { color: '#14b8a6', name: 'Teal' },
  { color: '#3b82f6', name: 'Blue' },
  { color: '#8b5cf6', name: 'Purple' },
  { color: '#ec4899', name: 'Pink' },
];
const PRESET_HEXES = COLOR_PRESETS.map((p) => p.color);

type SubTab = 'statuses' | 'asset_tiers' | 'status_code' | 'change_history' | 'change_requests';

interface OrganizationContextType {
  organization: { permissions?: { manage_compliance?: boolean }; role?: string } | null;
}

export default function StatusesSection() {
  const { id: orgId } = useParams<{ id: string }>();
  const { toast } = useToast();
  const { organization } = useOutletContext<OrganizationContextType>();
  const [subTab, setSubTab] = useState<SubTab>('statuses');
  const [statuses, setStatuses] = useState<OrganizationStatus[]>([]);
  const [assetTiers, setAssetTiers] = useState<OrganizationAssetTier[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusCodeValue, setStatusCodeValue] = useState('');
  const [statusCodeOriginal, setStatusCodeOriginal] = useState('');
  const [statusCodeDirty, setStatusCodeDirty] = useState(false);
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<any>(null);
  const [showCommitSidebar, setShowCommitSidebar] = useState(false);
  const [commitMessage, setCommitMessage] = useState('');
  const [commitSidebarVisible, setCommitSidebarVisible] = useState(false);
  const [committing, setCommitting] = useState(false);
  const commitSidebarCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const validationCardRef = useRef<HTMLDivElement>(null);

  // Add Status dialog
  const [addStatusOpen, setAddStatusOpen] = useState(false);
  const [newStatusName, setNewStatusName] = useState('');
  const [newStatusColor, setNewStatusColor] = useState('');
  const [newStatusPassing, setNewStatusPassing] = useState(false);
  const [addingStatus, setAddingStatus] = useState(false);

  // Add Tier dialog
  const [addTierOpen, setAddTierOpen] = useState(false);
  const [newTierName, setNewTierName] = useState('');
  const [newTierColor, setNewTierColor] = useState('');
  const [newTierMultiplier, setNewTierMultiplier] = useState('1.0');
  const [addingTier, setAddingTier] = useState(false);

  // Delete in progress (show spinner instead of trash)
  const [deletingStatusId, setDeletingStatusId] = useState<string | null>(null);
  const [deletingTierId, setDeletingTierId] = useState<string | null>(null);

  // Change history
  const [changes, setChanges] = useState<OrganizationPolicyChange[]>([]);
  const [loadingChanges, setLoadingChanges] = useState(false);
  const [selectedChange, setSelectedChange] = useState<OrganizationPolicyChange | null>(null);
  const [changeDetailVisible, setChangeDetailVisible] = useState(false);
  const changeDetailCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const changeHistoryLoadedRef = useRef(false);

  // Change requests (pending project status code requests only)
  const [changeRequests, setChangeRequests] = useState<ProjectPolicyChangeRequest[]>([]);
  const [loadingChangeRequests, setLoadingChangeRequests] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState<ProjectPolicyChangeRequest | null>(null);
  const [requestDetailVisible, setRequestDetailVisible] = useState(false);
  const requestDetailCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [reviewingRequestId, setReviewingRequestId] = useState<string | null>(null);
  const changeRequestsLoadedRef = useRef(false);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const [statusesData, tiersData, policyCode] = await Promise.all([
        api.getOrganizationStatuses(orgId),
        api.getOrganizationAssetTiers(orgId),
        api.getOrganizationPolicyCode(orgId),
      ]);
      setStatuses(statusesData);
      setAssetTiers(tiersData);
      const fullCode = policyCode.status_code?.project_status_code || '';
      const body = extractFunctionBody(fullCode, 'projectStatus') ?? DEFAULT_PROJECT_STATUS_BODY;
      setStatusCodeValue(body);
      setStatusCodeOriginal(body);
    } catch (err) {
      console.error('Failed to load statuses data:', err);
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    changeHistoryLoadedRef.current = false;
    changeRequestsLoadedRef.current = false;
  }, [orgId]);

  useEffect(() => {
    if (selectedRequest) {
      setRequestDetailVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setRequestDetailVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setRequestDetailVisible(false);
    }
  }, [selectedRequest]);

  useEffect(() => {
    if (subTab === 'change_history' && orgId && !changeHistoryLoadedRef.current) {
      setLoadingChanges(true);
      api.getOrganizationPolicyChanges(orgId, 'project_status')
        .then((list) => {
          setChanges(list);
          changeHistoryLoadedRef.current = true;
        })
        .catch(console.error)
        .finally(() => setLoadingChanges(false));
    }
  }, [subTab, orgId]);

  useEffect(() => {
    if (subTab === 'change_requests' && orgId && !changeRequestsLoadedRef.current) {
      setLoadingChangeRequests(true);
      api.getOrganizationPolicyChangeRequests(orgId)
        .then((list) => {
          setChangeRequests(list.filter((r) => r.code_type === 'project_status'));
          changeRequestsLoadedRef.current = true;
        })
        .catch((e) => {
          console.error(e);
          toast({ title: 'Error', description: e?.message || 'Failed to load change requests', variant: 'destructive' });
        })
        .finally(() => setLoadingChangeRequests(false));
    }
  }, [subTab, orgId, toast]);

  const hasManageCompliance = !!(organization?.permissions?.manage_compliance) || organization?.role === 'owner' || organization?.role === 'admin';

  const closeRequestDetail = useCallback(() => {
    setRequestDetailVisible(false);
    if (requestDetailCloseTimeoutRef.current) clearTimeout(requestDetailCloseTimeoutRef.current);
    requestDetailCloseTimeoutRef.current = setTimeout(() => {
      requestDetailCloseTimeoutRef.current = null;
      setSelectedRequest(null);
    }, 150);
  }, []);

  const handleReviewRequest = useCallback(async (changeId: string, action: 'accept' | 'reject') => {
    if (!orgId) return;
    setReviewingRequestId(changeId);
    try {
      await api.reviewProjectPolicyChange(orgId, changeId, action);
      toast({ title: action === 'accept' ? 'Request accepted' : 'Request rejected' });
      setChangeRequests((prev) => prev.filter((r) => r.id !== changeId));
      setSelectedRequest(null);
      setRequestDetailVisible(false);
    } catch (e: any) {
      toast({ title: 'Error', description: e?.message || 'Failed to update request', variant: 'destructive' });
    } finally {
      setReviewingRequestId(null);
    }
  }, [orgId, toast]);

  const handleAddStatus = async () => {
    if (!orgId || !newStatusName.trim()) return;
    setAddingStatus(true);
    try {
      const maxRank = statuses.length > 0 ? Math.max(...statuses.map((s) => s.rank)) : 0;
      const status = await api.createOrganizationStatus(orgId, {
        name: newStatusName.trim(),
        color: newStatusColor.trim() || null,
        is_passing: newStatusPassing,
        rank: maxRank + 10,
      });
      setStatuses((prev) => [...prev, status].sort((a, b) => a.rank - b.rank));
      setNewStatusName('');
      setNewStatusColor('');
      setNewStatusPassing(false);
      setAddStatusOpen(false);
      toast({ title: 'Status created' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    } finally {
      setAddingStatus(false);
    }
  };

  const handleDeleteStatus = async (statusId: string) => {
    if (!orgId) return;
    setDeletingStatusId(statusId);
    try {
      await api.deleteOrganizationStatus(orgId, statusId);
      setStatuses((prev) => prev.filter((s) => s.id !== statusId));
      toast({ title: 'Status deleted' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    } finally {
      setDeletingStatusId(null);
    }
  };

  const handleAddTier = async () => {
    if (!orgId || !newTierName.trim()) return;
    setAddingTier(true);
    try {
      const maxRank = assetTiers.length > 0 ? Math.max(...assetTiers.map((t) => t.rank)) : 0;
      const tier = await api.createOrganizationAssetTier(orgId, {
        name: newTierName.trim(),
        color: newTierColor || '#6b7280',
        environmental_multiplier: parseFloat(newTierMultiplier) || 1.0,
        rank: maxRank + 10,
      });
      setAssetTiers((prev) => [...prev, tier].sort((a, b) => a.rank - b.rank));
      setNewTierName('');
      setNewTierColor('');
      setNewTierMultiplier('1.0');
      setAddTierOpen(false);
      toast({ title: 'Asset tier created' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    } finally {
      setAddingTier(false);
    }
  };

  const handleDeleteTier = async (tierId: string) => {
    if (!orgId) return;
    setDeletingTierId(tierId);
    try {
      await api.deleteOrganizationAssetTier(orgId, tierId);
      setAssetTiers((prev) => prev.filter((t) => t.id !== tierId));
      toast({ title: 'Asset tier deleted' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    } finally {
      setDeletingTierId(null);
    }
  };

  const closeCommitSidebar = useCallback(() => {
    setCommitSidebarVisible(false);
    if (commitSidebarCloseTimeoutRef.current) clearTimeout(commitSidebarCloseTimeoutRef.current);
    commitSidebarCloseTimeoutRef.current = setTimeout(() => {
      commitSidebarCloseTimeoutRef.current = null;
      setShowCommitSidebar(false);
      setCommitMessage('');
    }, 150);
  }, []);

  const handleCommitClick = async () => {
    if (!orgId) return;
    const fullCode = wrapProjectStatusBody(statusCodeValue);
    setValidating(true);
    setValidationResult(null);
    try {
      const validation = await api.validatePolicyCode(orgId, fullCode, 'project_status');
      setValidationResult(validation);
      if (validation.allPassed) {
        setValidationResult(null);
        setCommitMessage('');
        setShowCommitSidebar(true);
      } else {
        toast({ title: 'Validation failed', description: 'Fix the issues below before committing.', variant: 'destructive' });
        setTimeout(() => validationCardRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50);
      }
    } catch (err: any) {
      setValidationResult(null);
      toast({ title: 'Error', description: err.message || 'Validation failed', variant: 'destructive' });
    } finally {
      setValidating(false);
    }
  };

  const handleCommitSubmit = async () => {
    if (!orgId) return;
    const fullCode = wrapProjectStatusBody(statusCodeValue);
    setCommitting(true);
    try {
      await api.updateOrganizationPolicyCode(orgId, 'project_status', fullCode, commitMessage.trim() || undefined);
      setStatusCodeOriginal(statusCodeValue);
      setStatusCodeDirty(false);
      closeCommitSidebar();
      if (orgId) {
        const list = await api.getOrganizationPolicyChanges(orgId, 'project_status');
        setChanges(list);
      }
      toast({ title: 'Status code saved', description: 'Project status code updated successfully.' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message || 'Failed to save', variant: 'destructive' });
    } finally {
      setCommitting(false);
    }
  };

  const closeChangeDetail = useCallback(() => {
    setChangeDetailVisible(false);
    if (changeDetailCloseTimeoutRef.current) clearTimeout(changeDetailCloseTimeoutRef.current);
    changeDetailCloseTimeoutRef.current = setTimeout(() => {
      changeDetailCloseTimeoutRef.current = null;
      setSelectedChange(null);
    }, 150);
  }, []);

  useEffect(() => () => {
    if (commitSidebarCloseTimeoutRef.current) clearTimeout(commitSidebarCloseTimeoutRef.current);
    if (changeDetailCloseTimeoutRef.current) clearTimeout(changeDetailCloseTimeoutRef.current);
  }, []);

  useEffect(() => {
    if (selectedChange) {
      setChangeDetailVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setChangeDetailVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setChangeDetailVisible(false);
    }
  }, [selectedChange]);

  useEffect(() => {
    if (showCommitSidebar) {
      setCommitSidebarVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setCommitSidebarVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setCommitSidebarVisible(false);
    }
  }, [showCommitSidebar]);

  type ValidationCheckItem = { name: string; pass: boolean; error?: string };
  const validationChecksFromResult: ValidationCheckItem[] | null = validationResult
    ? [
        { name: 'syntax', pass: validationResult.syntaxPass, error: validationResult.syntaxError },
        { name: 'shape', pass: validationResult.shapePass, error: validationResult.shapeError },
        { name: 'fetch_resilience', pass: validationResult.fetchResiliencePass, error: validationResult.fetchResilienceError },
      ]
    : null;
  const showValidationFailedCard =
    validationResult && validationChecksFromResult && validationChecksFromResult.some((c) => !c.pass);

  const subTabs: { id: SubTab; label: string }[] = [
    { id: 'statuses', label: 'Statuses' },
    { id: 'asset_tiers', label: 'Asset Tiers' },
    { id: 'status_code', label: 'Status Code' },
    { id: 'change_history', label: 'Change History' },
    { id: 'change_requests', label: 'Change requests' },
  ];

  const pulse = 'bg-muted animate-pulse rounded';

  /** Skeleton for the statuses/asset-tiers list table (same card + rows pattern). */
  const TableSkeleton = ({ title }: { title: string }) => (
    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
      <div className="px-4 py-2 border-b border-border bg-background-card-header text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
        {title}
      </div>
      <div className="divide-y divide-border">
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="px-4 py-3 flex items-center justify-between">
            <div className={`h-4 w-32 ${pulse}`} />
            <div className={`h-6 w-24 ${pulse}`} />
          </div>
        ))}
      </div>
    </div>
  );

  return (
    <div className="space-y-6 pt-8">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">Statuses & Tiers</h2>
        {!loading && subTab === 'statuses' && (
          <Button
            onClick={() => setAddStatusOpen(true)}
            disabled={addingStatus}
            className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
          >
            Add Status
          </Button>
        )}
        {!loading && subTab === 'asset_tiers' && (
          <Button
            onClick={() => setAddTierOpen(true)}
            disabled={addingTier}
            className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
          >
            Add Tier
          </Button>
        )}
      </div>

      {/* Info card – same pattern as Notifications section */}
      <Card className="rounded-lg border border-border bg-background-card/80">
        <CardContent className="p-4 flex gap-3">
          <div className="flex-shrink-0 mt-0.5">
            <Info className="h-5 w-5 text-foreground-muted" />
          </div>
          <div className="min-w-0 space-y-1">
            <p className="text-sm text-foreground-secondary">
              Create and define custom statuses and asset tiers for your organization. Use them in policy to label project health and weight vulnerability scores (Depscore).
            </p>
            <p className="text-sm text-foreground-secondary">
              <span className="font-medium text-foreground">Custom status code</span> — In the Status Code tab, write a <code className="px-1 py-0.5 rounded bg-muted text-foreground text-xs font-mono">projectStatus(context)</code> function that assigns one of your statuses to each project based on policy.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Sub-tabs */}
      <div className="flex gap-1 border-b border-border">
        {subTabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setSubTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              subTab === tab.id
                ? 'border-foreground text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Statuses sub-tab */}
      {subTab === 'statuses' && (
        <div>
          {loading ? (
            <TableSkeleton title="Statuses" />
          ) : (
          <>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-2 border-b border-border bg-background-card-header text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
              Statuses
            </div>
            <div className="divide-y divide-border">
              {statuses.map((status) => (
                <div
                  key={status.id}
                  className="px-4 py-3 flex items-center justify-between group hover:bg-table-hover transition-colors"
                >
                  <div className="flex items-center gap-2 min-w-0 flex-1">
                    <span className="text-sm font-medium text-foreground truncate">
                      {status.name}
                    </span>
                    {status.is_system && <Lock className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />}
                  </div>
                  <div className="flex items-center justify-end flex-shrink-0 w-36 relative">
                    <div className={`flex justify-end transition-opacity ${!status.is_system ? 'group-hover:opacity-0' : ''}`}>
                      <RoleBadge
                        role={status.name}
                        roleDisplayName={status.name}
                        roleColor={status.color || null}
                      />
                    </div>
                    {!status.is_system && (
                      <div className="absolute inset-0 flex items-center justify-end opacity-0 group-hover:opacity-100 transition-opacity">
                        <button
                          onClick={() => handleDeleteStatus(status.id)}
                          disabled={deletingStatusId === status.id}
                          className="h-7 w-7 flex items-center justify-center rounded text-muted-foreground hover:text-destructive transition-colors disabled:opacity-50"
                          title="Delete"
                        >
                          {deletingStatusId === status.id ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <Trash2 className="h-4 w-4" />
                          )}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Add Status Dialog */}
          <Dialog open={addStatusOpen} onOpenChange={(open) => { if (!open) { setAddStatusOpen(false); setNewStatusName(''); setNewStatusColor(''); setNewStatusPassing(false); } }}>
            <DialogContent className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col" hideClose>
              <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
                <DialogTitle>Add Status</DialogTitle>
                <DialogDescription className="mt-1">
                  Create a custom project status that policy code can assign.
                </DialogDescription>
              </div>
              <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0">
                <div>
                  <label className="text-sm font-medium text-foreground block mb-2">Name</label>
                  <Input
                    value={newStatusName}
                    onChange={(e) => setNewStatusName(e.target.value)}
                    placeholder=""
                    className="w-full"
                    onKeyDown={(e) => e.key === 'Enter' && handleAddStatus()}
                  />
                </div>
                <div>
                  <label className="text-sm font-medium text-foreground block mb-2">Color</label>
                  <div className="flex flex-wrap items-center gap-2">
                    {COLOR_PRESETS.map(({ color, name }) => (
                      <Tooltip key={color}>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => setNewStatusColor(color)}
                            disabled={addingStatus}
                            className={`h-8 w-8 rounded-lg border-2 transition-all flex items-center justify-center ${newStatusColor === color ? 'border-white scale-110 shadow-lg' : 'border-transparent hover:scale-105'}`}
                            style={{ backgroundColor: color }}
                          >
                            {newStatusColor === color && <Check className="h-4 w-4 text-white drop-shadow-md" />}
                          </button>
                        </TooltipTrigger>
                        <TooltipContent>{name}</TooltipContent>
                      </Tooltip>
                    ))}
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <div className="relative">
                          <input
                            key={newStatusColor || 'empty'}
                            type="color"
                            value={newStatusColor || '#6b7280'}
                            onChange={(e) => setNewStatusColor(e.target.value)}
                            className="absolute inset-0 opacity-0 cursor-pointer w-full h-full rounded-lg"
                            disabled={addingStatus}
                          />
                          <div
                            className={`h-8 w-8 rounded-lg border-2 cursor-pointer transition-all flex items-center justify-center ${newStatusColor && !PRESET_HEXES.includes(newStatusColor) ? 'border-white scale-110 shadow-lg' : 'border-dashed border-border hover:border-foreground-secondary/50'}`}
                            style={{ backgroundColor: newStatusColor && !PRESET_HEXES.includes(newStatusColor) ? newStatusColor : 'transparent' }}
                          >
                            {(!newStatusColor || PRESET_HEXES.includes(newStatusColor)) && <Plus className="h-4 w-4 text-foreground-secondary" />}
                            {newStatusColor && !PRESET_HEXES.includes(newStatusColor) && <Check className="h-4 w-4 text-white drop-shadow-md" />}
                          </div>
                        </div>
                      </TooltipTrigger>
                      <TooltipContent>Custom color</TooltipContent>
                    </Tooltip>
                    {newStatusColor ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => setNewStatusColor('')}
                            disabled={addingStatus}
                            className="h-8 w-8 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:border-foreground-secondary/50 transition-all flex items-center justify-center"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </TooltipTrigger>
                        <TooltipContent>Clear color</TooltipContent>
                      </Tooltip>
                    ) : null}
                  </div>
                </div>
              </div>
              <DialogFooter className="px-6 py-4 bg-background">
                <Button variant="outline" onClick={() => { setAddStatusOpen(false); setNewStatusName(''); setNewStatusColor(''); setNewStatusPassing(false); }}>
                  Cancel
                </Button>
                <Button
                  onClick={handleAddStatus}
                  disabled={!newStatusName.trim() || addingStatus}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  {addingStatus ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  Create Status
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
          </>
          )}
        </div>
      )}

      {/* Asset Tiers sub-tab */}
      {subTab === 'asset_tiers' && (
        <div>
          {loading ? (
            <TableSkeleton title="Asset Tiers" />
          ) : (
          <>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-2 border-b border-border bg-background-card-header text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
              Asset Tiers
            </div>
            <div className="divide-y divide-border">
              {[...assetTiers]
                .sort((a, b) => b.environmental_multiplier - a.environmental_multiplier)
                .map((tier) => (
                  <div
                    key={tier.id}
                    className="px-4 py-3 flex items-center justify-between group hover:bg-table-hover transition-colors"
                  >
                    <div className="flex items-center gap-2 min-w-0 flex-1">
                      <span className="text-sm font-medium text-foreground truncate">
                        {tier.name}
                      </span>
                      <span className="text-xs font-mono text-muted-foreground flex-shrink-0">{tier.environmental_multiplier}×</span>
                      {tier.is_system && <Lock className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />}
                    </div>
                    <div className="flex items-center justify-end flex-shrink-0 w-36 relative">
                      <div className={`flex justify-end transition-opacity ${!tier.is_system ? 'group-hover:opacity-0' : ''}`}>
                        <RoleBadge
                          role={tier.name}
                          roleDisplayName={tier.name}
                          roleColor={tier.color || null}
                        />
                      </div>
                      {!tier.is_system && (
                        <div className="absolute inset-0 flex items-center justify-end opacity-0 group-hover:opacity-100 transition-opacity">
                          <button
                            onClick={() => handleDeleteTier(tier.id)}
                            disabled={deletingTierId === tier.id}
                            className="h-7 w-7 flex items-center justify-center rounded text-muted-foreground hover:text-destructive transition-colors disabled:opacity-50"
                            title="Delete"
                          >
                            {deletingTierId === tier.id ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <Trash2 className="h-4 w-4" />
                            )}
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
            </div>
          </div>

          {/* Add Tier Dialog */}
          <Dialog open={addTierOpen} onOpenChange={(open) => { if (!open) { setAddTierOpen(false); setNewTierName(''); setNewTierColor(''); setNewTierMultiplier('1.0'); } }}>
            <DialogContent className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col" hideClose>
              <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
                <DialogTitle>Add Asset Tier</DialogTitle>
                <DialogDescription className="mt-1">
                  Create a tier with an environmental multiplier for Depscore calculation.
                </DialogDescription>
              </div>
              <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0">
                <div>
                  <label className="text-sm font-medium text-foreground block mb-2">Name</label>
                  <Input
                    value={newTierName}
                    onChange={(e) => setNewTierName(e.target.value)}
                    placeholder=""
                    className="w-full"
                    onKeyDown={(e) => e.key === 'Enter' && handleAddTier()}
                  />
                </div>
                <div>
                  <label className="text-sm font-medium text-foreground block mb-2">Color</label>
                  <div className="flex flex-wrap items-center gap-2">
                    {COLOR_PRESETS.map(({ color, name }) => (
                      <Tooltip key={color}>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => setNewTierColor(color)}
                            disabled={addingTier}
                            className={`h-8 w-8 rounded-lg border-2 transition-all flex items-center justify-center ${newTierColor === color ? 'border-white scale-110 shadow-lg' : 'border-transparent hover:scale-105'}`}
                            style={{ backgroundColor: color }}
                          >
                            {newTierColor === color && <Check className="h-4 w-4 text-white drop-shadow-md" />}
                          </button>
                        </TooltipTrigger>
                        <TooltipContent>{name}</TooltipContent>
                      </Tooltip>
                    ))}
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <div className="relative">
                          <input
                            key={newTierColor || 'empty'}
                            type="color"
                            value={newTierColor || '#6b7280'}
                            onChange={(e) => setNewTierColor(e.target.value)}
                            className="absolute inset-0 opacity-0 cursor-pointer w-full h-full rounded-lg"
                            disabled={addingTier}
                          />
                          <div
                            className={`h-8 w-8 rounded-lg border-2 cursor-pointer transition-all flex items-center justify-center ${newTierColor && !PRESET_HEXES.includes(newTierColor) ? 'border-white scale-110 shadow-lg' : 'border-dashed border-border hover:border-foreground-secondary/50'}`}
                            style={{ backgroundColor: newTierColor && !PRESET_HEXES.includes(newTierColor) ? newTierColor : 'transparent' }}
                          >
                            {(!newTierColor || PRESET_HEXES.includes(newTierColor)) && <Plus className="h-4 w-4 text-foreground-secondary" />}
                            {newTierColor && !PRESET_HEXES.includes(newTierColor) && <Check className="h-4 w-4 text-white drop-shadow-md" />}
                          </div>
                        </div>
                      </TooltipTrigger>
                      <TooltipContent>Custom color</TooltipContent>
                    </Tooltip>
                    {newTierColor ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => setNewTierColor('')}
                            disabled={addingTier}
                            className="h-8 w-8 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:border-foreground-secondary/50 transition-all flex items-center justify-center"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </TooltipTrigger>
                        <TooltipContent>Clear color</TooltipContent>
                      </Tooltip>
                    ) : null}
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium text-foreground block mb-2">Multiplier</label>
                  <Input
                    value={newTierMultiplier}
                    onChange={(e) => setNewTierMultiplier(e.target.value)}
                    placeholder="1.0"
                    className="h-8 w-24"
                    type="number"
                    step="0.1"
                    min="0.1"
                    max="3.0"
                  />
                </div>
              </div>
              <DialogFooter className="px-6 py-4 bg-background">
                <Button variant="outline" onClick={() => { setAddTierOpen(false); setNewTierName(''); setNewTierColor(''); setNewTierMultiplier('1.0'); }}>
                  Cancel
                </Button>
                <Button
                  onClick={handleAddTier}
                  disabled={!newTierName.trim() || addingTier}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  {addingTier ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  Create Tier
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
          </>
          )}
        </div>
      )}

      {/* Status Code sub-tab: header Project Status + Clear/Commit, body-only in editor */}
      {subTab === 'status_code' && (
        <div className="space-y-4">
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center justify-between">
              <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project Status</span>
              {!loading && statusCodeDirty && (
                <div className="flex items-center gap-1.5">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => { setStatusCodeValue(statusCodeOriginal); setStatusCodeDirty(false); setValidationResult(null); }}
                    disabled={validating}
                    className="h-6 min-h-6 px-1.5 py-0 text-[11px] font-medium"
                  >
                    Clear
                  </Button>
                  <Button
                    size="sm"
                    onClick={handleCommitClick}
                    disabled={validating}
                    className="h-6 min-h-6 px-1.5 py-0 text-[11px] font-medium bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                  >
                    {validating && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                    Commit
                  </Button>
                </div>
              )}
            </div>
            <div className="bg-background-card">
              {loading ? (
                <div className="p-4 space-y-2 min-h-[200px]">
                  {[1, 2, 3, 4, 5, 6, 7, 8].map((i) => (
                    <div key={i} className={`h-4 ${pulse} ${i === 3 ? 'w-3/4' : i === 5 ? 'w-1/2' : 'w-full'}`} />
                  ))}
                </div>
              ) : (
                <PolicyCodeEditor
                  value={statusCodeValue}
                  onChange={(val) => {
                    setStatusCodeValue(val || '');
                    setStatusCodeDirty((val || '') !== statusCodeOriginal);
                    setValidationResult(null);
                  }}
                  fitContent
                />
              )}
            </div>
          </div>
          {showValidationFailedCard && subTab === 'status_code' && validationChecksFromResult && (
            <div
              ref={validationCardRef}
              className="p-4 rounded-lg border border-destructive/30 bg-destructive/10"
            >
              <div className="flex items-center gap-3">
                <div className="rounded-md bg-destructive/20 border border-destructive/40 w-9 h-9 flex items-center justify-center flex-shrink-0 text-destructive">
                  <X className="h-4 w-4" />
                </div>
                <span className="text-base font-medium text-destructive">Validation failed</span>
              </div>
              <div className="mt-3 space-y-2 pl-12">
                {validationChecksFromResult
                  .filter((c) => !c.pass)
                  .map((check, i) => (
                    <div key={i} className="text-sm">
                      <span className="font-medium text-destructive">
                        {check.name === 'syntax' ? 'Syntax' : check.name === 'shape' ? 'Return value' : check.name === 'fetch_resilience' ? 'Fetch handling' : check.name.replace(/_/g, ' ')} failed
                      </span>
                      {check.error && (
                        <p className="text-foreground-secondary mt-0.5">{check.error}</p>
                      )}
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Change History sub-tab – table with header and one empty row when no data */}
      {subTab === 'change_history' && (
        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Change</th>
                <th className="text-right px-4 py-3 w-[120px]" />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loadingChanges ? (
                <tr className="animate-pulse">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-4">
                      <div>
                        <div className="h-4 bg-muted rounded w-48" />
                        <div className="h-3 bg-muted rounded w-28 mt-1" />
                      </div>
                      <div className="h-4 bg-muted rounded w-12 flex-shrink-0" />
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="inline-flex items-center gap-2 justify-end">
                      <div className="h-4 bg-muted rounded w-16" />
                      <div className="h-8 w-8 rounded-full bg-muted flex-shrink-0" />
                    </div>
                  </td>
                </tr>
              ) : changes.length === 0 ? (
                <tr>
                  <td colSpan={2} className="px-4 py-6 text-sm text-muted-foreground">
                    No change history
                  </td>
                </tr>
              ) : (
                changes.map((change) => {
                  const { added, removed } = getDiffLineCounts(change.previous_code ?? '', change.new_code ?? '');
                  return (
                    <tr
                      key={change.id}
                      onClick={() => setSelectedChange(change)}
                      className="hover:bg-table-hover transition-colors cursor-pointer"
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-4 min-w-0">
                          <div className="min-w-0">
                            <p className={cn('text-sm truncate', change.message?.trim() ? 'text-foreground' : 'text-muted-foreground')}>
                              {change.message?.trim() || '—'}
                            </p>
                            <p className="text-xs text-muted-foreground mt-0.5">Project Status</p>
                          </div>
                          {(added > 0 || removed > 0) && (
                            <span className="inline-flex items-center gap-1.5 text-xs font-mono flex-shrink-0">
                              {added > 0 && <span className="text-emerald-600 dark:text-emerald-400">+{added}</span>}
                              {removed > 0 && <span className="text-red-600 dark:text-red-400">-{removed}</span>}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-right align-middle">
                        <div className="inline-flex items-center gap-2 justify-end" title={change.author_display_name || undefined}>
                          <span className="text-xs text-muted-foreground whitespace-nowrap">
                            {formatRelativeTime(change.created_at)}
                          </span>
                          <Avatar className="h-8 w-8 flex-shrink-0 ring-1 ring-border rounded-full">
                            <AvatarImage src={change.author_avatar_url ?? undefined} alt="" />
                            <AvatarFallback className="text-xs bg-muted text-muted-foreground">
                              {(change.author_display_name || 'User').trim().slice(0, 2).toUpperCase() || '?'}
                            </AvatarFallback>
                          </Avatar>
                        </div>
                      </td>
                        </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Change requests sub-tab – pending project status code requests */}
      {subTab === 'change_requests' && (
        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
          <table className="w-full table-fixed">
            <colgroup>
              <col className="w-[180px]" />
              <col className="w-[140px]" />
              <col className="min-w-[120px]" />
              <col className="w-[120px]" />
              <col className="w-[100px]" />
            </colgroup>
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Requested by</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Message</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Date</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loadingChangeRequests ? (
                [1, 2, 3].map((i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-32" /></td>
                    <td className="px-4 py-3"><div className="h-5 bg-muted rounded w-24" /></td>
                    <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-48" /></td>
                    <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-16" /></td>
                    <td className="px-4 py-3"><div className="h-8 bg-muted rounded w-20" /></td>
                  </tr>
                ))
              ) : changeRequests.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-sm text-muted-foreground text-center">
                    No pending change requests for status code.
                  </td>
                </tr>
              ) : (
                changeRequests.map((req) => (
                  <tr key={req.id} className="hover:bg-table-hover transition-colors">
                    <td className="px-4 py-3 text-sm text-foreground font-medium truncate" title={req.project_name}>{req.project_name}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2 min-w-0">
                        <Avatar className="h-6 w-6 flex-shrink-0">
                          <AvatarImage src={req.author_avatar_url ?? undefined} alt="" />
                          <AvatarFallback className="text-[10px] bg-muted text-muted-foreground">
                            {(req.author_display_name || 'User').trim().slice(0, 2).toUpperCase() || '?'}
                          </AvatarFallback>
                        </Avatar>
                        <span className="text-sm text-foreground truncate">{req.author_display_name || 'Unknown'}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-foreground truncate" title={req.message || undefined}>
                      {req.message?.trim() || '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{formatRelativeTime(req.created_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => { setSelectedRequest(req); setRequestDetailVisible(false); requestAnimationFrame(() => requestAnimationFrame(() => setRequestDetailVisible(true))); }}
                        >
                          <Eye className="h-3.5 w-3.5 mr-1" />
                          Review
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Change detail sidebar – diff view */}
      {selectedChange && createPortal(
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              changeDetailVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={closeChangeDetail}
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[560px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              changeDetailVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <h2 className={cn('text-base font-semibold text-foreground', !selectedChange.message?.trim() && 'text-muted-foreground')}>
                    {selectedChange.message?.trim() || '—'}
                  </h2>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    <p className="text-xs text-muted-foreground">Project Status</p>
                    {(() => {
                      const { added, removed } = getDiffLineCounts(selectedChange.previous_code ?? '', selectedChange.new_code ?? '');
                      if (added > 0 || removed > 0) {
                        return (
                          <span className="inline-flex items-center gap-1.5 text-xs font-mono">
                            {added > 0 && <span className="text-emerald-600 dark:text-emerald-400">+{added}</span>}
                            {removed > 0 && <span className="text-red-600 dark:text-red-400">-{removed}</span>}
                          </span>
                        );
                      }
                      return null;
                    })()}
                  </div>
                </div>
                <div className="inline-flex items-center gap-2 flex-shrink-0" title={selectedChange.author_display_name || undefined}>
                  <span className="text-xs text-muted-foreground whitespace-nowrap">
                    {formatRelativeTime(selectedChange.created_at)}
                  </span>
                  <Avatar className="h-8 w-8 flex-shrink-0 ring-1 ring-border rounded-full">
                    <AvatarImage src={selectedChange.author_avatar_url ?? undefined} alt="" />
                    <AvatarFallback className="text-xs bg-muted text-muted-foreground">
                      {(selectedChange.author_display_name || 'User').trim().slice(0, 2).toUpperCase() || '?'}
                    </AvatarFallback>
                  </Avatar>
                </div>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto min-h-0 px-4 pb-4">
              <div className="rounded-lg overflow-hidden border border-border">
                <PolicyDiffViewer
                  baseCode={selectedChange.previous_code}
                  requestedCode={selectedChange.new_code}
                  minHeight="200px"
                  className="text-[11px]"
                />
              </div>
            </div>
            <div className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header flex items-center justify-end">
              <Button variant="outline" size="sm" onClick={closeChangeDetail}>
                Close
              </Button>
            </div>
          </div>
        </div>,
        document.body,
      )}

      {/* Change request detail sidebar – diff and Accept/Reject (status code only) */}
      {selectedRequest && createPortal(
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              requestDetailVisible ? 'opacity-100' : 'opacity-0',
            )}
            onClick={closeRequestDetail}
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[560px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              requestDetailVisible ? 'translate-x-0' : 'translate-x-full',
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0">
              <h2 className="text-xl font-semibold text-foreground">Status code change request</h2>
              <p className="text-sm text-foreground mt-1 font-medium">{selectedRequest.project_name}</p>
              <p className="text-sm text-muted-foreground mt-0.5 truncate">{selectedRequest.message?.trim() || '—'}</p>
              <div className="flex items-center gap-2 mt-2">
                <span className="text-xs text-muted-foreground">{formatRelativeTime(selectedRequest.created_at)}</span>
                {selectedRequest.has_conflict && (
                  <Badge variant="secondary" className="text-amber-600 border-amber-200 bg-amber-50">Conflict</Badge>
                )}
              </div>
              <div className="flex items-center gap-2 mt-3">
                <Avatar className="h-6 w-6 flex-shrink-0">
                  <AvatarImage src={selectedRequest.author_avatar_url ?? undefined} alt="" />
                  <AvatarFallback className="text-[10px] bg-muted text-muted-foreground">
                    {(selectedRequest.author_display_name || 'User').trim().slice(0, 2).toUpperCase() || '?'}
                  </AvatarFallback>
                </Avatar>
                <span className="text-sm text-muted-foreground">Requested by {selectedRequest.author_display_name || 'Unknown'}</span>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto min-h-0 px-4 pb-4">
              <div className="rounded-lg overflow-hidden border border-border">
                <PolicyDiffViewer
                  baseCode={selectedRequest.base_code ?? ''}
                  requestedCode={selectedRequest.proposed_code ?? ''}
                  minHeight="200px"
                  className="text-[11px]"
                />
              </div>
            </div>
            <div className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header flex items-center justify-between">
              <Button variant="outline" size="sm" onClick={closeRequestDetail}>
                Close
              </Button>
              {hasManageCompliance && (
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-destructive hover:text-destructive"
                    disabled={reviewingRequestId === selectedRequest.id}
                    onClick={() => handleReviewRequest(selectedRequest.id, 'reject')}
                  >
                    <X className="h-3 w-3 mr-1" />
                    Reject
                  </Button>
                  <Button
                    size="sm"
                    disabled={reviewingRequestId === selectedRequest.id}
                    onClick={() => handleReviewRequest(selectedRequest.id, 'accept')}
                  >
                    {reviewingRequestId === selectedRequest.id ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Check className="h-3 w-3 mr-1" />}
                    Accept
                  </Button>
                </div>
              )}
            </div>
          </div>
        </div>,
        document.body,
      )}

      {/* Commit sidebar – message + diff, open after validation passes */}
      {showCommitSidebar && createPortal(
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              commitSidebarVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={closeCommitSidebar}
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[560px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              commitSidebarVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0">
              <h2 className="text-xl font-semibold text-foreground">Commit status code change</h2>
              <p className="text-sm text-muted-foreground mt-1">Add a message and review the diff before applying.</p>
            </div>
            <div className="flex-1 overflow-y-auto min-h-0 px-6 py-4">
              <div className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground">Message</label>
                  <textarea
                    value={commitMessage}
                    onChange={(e) => setCommitMessage(e.target.value)}
                    placeholder=""
                    rows={2}
                    className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
                    disabled={committing}
                  />
                </div>
                <div className="space-y-2">
                  <span className="text-sm font-medium text-foreground">Changes</span>
                  <div className="rounded-lg overflow-hidden border border-border bg-[#1a1c1e] shadow-inner">
                    <PolicyDiffViewer
                      baseCode={wrapProjectStatusBody(statusCodeOriginal)}
                      requestedCode={wrapProjectStatusBody(statusCodeValue)}
                      minHeight="200px"
                      className="text-[11px]"
                    />
                  </div>
                </div>
              </div>
            </div>
            <div className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header flex items-center justify-end gap-3">
              <Button variant="outline" size="sm" onClick={closeCommitSidebar} disabled={committing}>
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={handleCommitSubmit}
                disabled={committing || !commitMessage.trim()}
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              >
                {committing && <Loader2 className="h-3 w-3 mr-1.5 animate-spin" />}
                Commit
              </Button>
            </div>
          </div>
        </div>,
        document.body,
      )}
    </div>
  );
}
