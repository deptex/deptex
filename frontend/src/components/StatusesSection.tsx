import { useState, useEffect, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import { Plus, Lock, Trash2, Loader2, Check, X } from 'lucide-react';
import { api, OrganizationStatus, OrganizationAssetTier } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { PolicyCodeEditor } from '@/components/PolicyCodeEditor';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from '@/components/ui/dialog';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { RoleBadge } from '@/components/RoleBadge';

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

type SubTab = 'statuses' | 'asset_tiers' | 'status_code' | 'change_history';

export default function StatusesSection() {
  const { id: orgId } = useParams<{ id: string }>();
  const { toast } = useToast();
  const [subTab, setSubTab] = useState<SubTab>('statuses');
  const [statuses, setStatuses] = useState<OrganizationStatus[]>([]);
  const [assetTiers, setAssetTiers] = useState<OrganizationAssetTier[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusCodeValue, setStatusCodeValue] = useState('');
  const [statusCodeOriginal, setStatusCodeOriginal] = useState('');
  const [statusCodeDirty, setStatusCodeDirty] = useState(false);
  const [saving, setSaving] = useState(false);

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
  const [changes, setChanges] = useState<any[]>([]);
  const [loadingChanges, setLoadingChanges] = useState(false);

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
    if (subTab === 'change_history' && orgId) {
      setLoadingChanges(true);
      api.getOrganizationPolicyChanges(orgId, 'project_status')
        .then(setChanges)
        .catch(console.error)
        .finally(() => setLoadingChanges(false));
    }
  }, [subTab, orgId]);

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

  const handleSaveStatusCode = async () => {
    if (!orgId) return;
    const fullCode = wrapProjectStatusBody(statusCodeValue);
    setSaving(true);
    try {
      const validation = await api.validatePolicyCode(orgId, fullCode, 'project_status');
      if (!validation.allPassed) {
        const errorMsg = validation.syntaxError || validation.shapeError || validation.fetchResilienceError || 'Validation failed';
        toast({ title: 'Validation failed', description: errorMsg, variant: 'destructive' });
        return;
      }
      await api.updateOrganizationPolicyCode(orgId, 'project_status', fullCode, 'Updated project status code');
      setStatusCodeOriginal(statusCodeValue);
      setStatusCodeDirty(false);
      toast({ title: 'Status code saved' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const subTabs: { id: SubTab; label: string }[] = [
    { id: 'statuses', label: 'Statuses' },
    { id: 'asset_tiers', label: 'Asset Tiers' },
    { id: 'status_code', label: 'Status Code' },
    { id: 'change_history', label: 'Change History' },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6 pt-8">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">Statuses & Tiers</h2>
        {subTab === 'statuses' && (
          <Button
            onClick={() => setAddStatusOpen(true)}
            disabled={addingStatus}
            className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
          >
            Add Status
          </Button>
        )}
        {subTab === 'asset_tiers' && (
          <Button
            onClick={() => setAddTierOpen(true)}
            disabled={addingTier}
            className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
          >
            Add Tier
          </Button>
        )}
      </div>

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
        </div>
      )}

      {/* Asset Tiers sub-tab */}
      {subTab === 'asset_tiers' && (
        <div>
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
        </div>
      )}

      {/* Status Code sub-tab: header with function title + Save, body-only in editor */}
      {subTab === 'status_code' && (
        <div className="flex flex-col gap-4 min-h-0">
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center justify-between">
              <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">projectStatus(context)</span>
              <div className="flex items-center gap-1.5">
                {statusCodeDirty && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => { setStatusCodeValue(statusCodeOriginal); setStatusCodeDirty(false); }}
                    disabled={saving}
                    className="h-7 min-h-7 px-2 py-0 text-xs"
                  >
                    Discard
                  </Button>
                )}
                <Button
                  size="sm"
                  onClick={handleSaveStatusCode}
                  disabled={!statusCodeDirty || saving}
                  className="h-7 min-h-7 px-2 py-0 text-xs"
                >
                  {saving && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                  Save
                </Button>
              </div>
            </div>
            <div className="bg-background-card">
              <PolicyCodeEditor
                value={statusCodeValue}
                onChange={(val) => {
                  setStatusCodeValue(val || '');
                  setStatusCodeDirty((val || '') !== statusCodeOriginal);
                }}
                fitContent
              />
            </div>
          </div>
          <p className="text-sm text-muted-foreground">
            This code determines the project status based on dependency policy results and vulnerabilities.
          </p>
        </div>
      )}

      {/* Change History sub-tab */}
      {subTab === 'change_history' && (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            History of status code changes across the organization.
          </p>

          {loadingChanges ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <div className="border border-border rounded-lg overflow-hidden">
              <table className="w-full">
                <thead className="bg-background-card-header border-b border-border">
                  <tr>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Type</th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Message</th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[120px]">Date</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {changes.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="px-4 py-8 text-sm text-muted-foreground text-center">
                        No changes recorded yet.
                      </td>
                    </tr>
                  ) : (
                    changes.map((change: any) => (
                      <tr key={change.id} className="hover:bg-table-hover transition-colors">
                        <td className="px-4 py-3">
                          <Badge variant="outline" className="text-xs">{change.code_type?.replace('_', ' ') ?? '—'}</Badge>
                        </td>
                        <td className="px-4 py-3 text-sm text-foreground truncate max-w-[320px]">{change.message ?? '—'}</td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">{change.created_at ? new Date(change.created_at).toLocaleDateString() : '—'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
