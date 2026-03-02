import { useState, useEffect, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import { GripVertical, Plus, Lock, Pencil, Trash2, Check, X, Loader2 } from 'lucide-react';
import { api, OrganizationStatus, OrganizationAssetTier } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/components/ui/use-toast';
import { PolicyCodeEditor } from '@/components/PolicyCodeEditor';

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

  // Inline add forms
  const [addingStatus, setAddingStatus] = useState(false);
  const [newStatusName, setNewStatusName] = useState('');
  const [newStatusColor, setNewStatusColor] = useState('#6b7280');
  const [newStatusPassing, setNewStatusPassing] = useState(false);

  const [addingTier, setAddingTier] = useState(false);
  const [newTierName, setNewTierName] = useState('');
  const [newTierColor, setNewTierColor] = useState('#6b7280');
  const [newTierMultiplier, setNewTierMultiplier] = useState('1.0');

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
      const code = policyCode.status_code?.project_status_code || '';
      setStatusCodeValue(code);
      setStatusCodeOriginal(code);
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
    try {
      const maxRank = statuses.length > 0 ? Math.max(...statuses.map((s) => s.rank)) : 0;
      const status = await api.createOrganizationStatus(orgId, {
        name: newStatusName.trim(),
        color: newStatusColor,
        is_passing: newStatusPassing,
        rank: maxRank + 10,
      });
      setStatuses((prev) => [...prev, status].sort((a, b) => a.rank - b.rank));
      setNewStatusName('');
      setNewStatusColor('#6b7280');
      setNewStatusPassing(false);
      setAddingStatus(false);
      toast({ title: 'Status created' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    }
  };

  const handleDeleteStatus = async (statusId: string) => {
    if (!orgId) return;
    try {
      await api.deleteOrganizationStatus(orgId, statusId);
      setStatuses((prev) => prev.filter((s) => s.id !== statusId));
      toast({ title: 'Status deleted' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    }
  };

  const handleAddTier = async () => {
    if (!orgId || !newTierName.trim()) return;
    try {
      const maxRank = assetTiers.length > 0 ? Math.max(...assetTiers.map((t) => t.rank)) : 0;
      const tier = await api.createOrganizationAssetTier(orgId, {
        name: newTierName.trim(),
        color: newTierColor,
        environmental_multiplier: parseFloat(newTierMultiplier) || 1.0,
        rank: maxRank + 10,
      });
      setAssetTiers((prev) => [...prev, tier].sort((a, b) => a.rank - b.rank));
      setNewTierName('');
      setNewTierColor('#6b7280');
      setNewTierMultiplier('1.0');
      setAddingTier(false);
      toast({ title: 'Asset tier created' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    }
  };

  const handleDeleteTier = async (tierId: string) => {
    if (!orgId) return;
    try {
      await api.deleteOrganizationAssetTier(orgId, tierId);
      setAssetTiers((prev) => prev.filter((t) => t.id !== tierId));
      toast({ title: 'Asset tier deleted' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    }
  };

  const handleSaveStatusCode = async () => {
    if (!orgId) return;
    setSaving(true);
    try {
      const validation = await api.validatePolicyCode(orgId, statusCodeValue, 'project_status');
      if (!validation.allPassed) {
        const errorMsg = validation.syntaxError || validation.shapeError || validation.fetchResilienceError || 'Validation failed';
        toast({ title: 'Validation failed', description: errorMsg, variant: 'destructive' });
        return;
      }
      await api.updateOrganizationPolicyCode(orgId, 'project_status', statusCodeValue, 'Updated project status code');
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
      <div>
        <h2 className="text-2xl font-bold text-foreground">Statuses & Tiers</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Configure project statuses, asset tiers, and the status evaluation code.
        </p>
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
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Define project statuses that policy code can assign. System statuses cannot be deleted.
            </p>
            <Button size="sm" onClick={() => setAddingStatus(true)} disabled={addingStatus}>
              <Plus className="h-3.5 w-3.5 mr-1.5" />
              Add Status
            </Button>
          </div>

          <div className="border border-border rounded-lg divide-y divide-border">
            {statuses.map((status) => (
              <div key={status.id} className="flex items-center gap-3 px-4 py-3">
                <GripVertical className="h-4 w-4 text-muted-foreground/50 cursor-grab" />
                <div className="h-3 w-3 rounded-full flex-shrink-0" style={{ backgroundColor: status.color }} />
                <span className="text-sm font-medium text-foreground flex-1">{status.name}</span>
                <Badge variant={status.is_passing ? 'default' : 'destructive'} className="text-xs">
                  {status.is_passing ? 'Passing' : 'Failing'}
                </Badge>
                {status.is_system && <Lock className="h-3.5 w-3.5 text-muted-foreground" />}
                {!status.is_system && (
                  <button onClick={() => handleDeleteStatus(status.id)} className="text-muted-foreground hover:text-destructive transition-colors">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            ))}

            {addingStatus && (
              <div className="flex items-center gap-3 px-4 py-3 bg-muted/30">
                <input type="color" value={newStatusColor} onChange={(e) => setNewStatusColor(e.target.value)} className="h-6 w-6 rounded cursor-pointer border-0" />
                <Input
                  value={newStatusName}
                  onChange={(e) => setNewStatusName(e.target.value)}
                  placeholder="Status name..."
                  className="h-8 text-sm flex-1"
                  autoFocus
                  onKeyDown={(e) => e.key === 'Enter' && handleAddStatus()}
                />
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Passing</span>
                  <Switch checked={newStatusPassing} onCheckedChange={setNewStatusPassing} />
                </div>
                <button onClick={handleAddStatus} className="text-green-500 hover:text-green-400"><Check className="h-4 w-4" /></button>
                <button onClick={() => setAddingStatus(false)} className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Asset Tiers sub-tab */}
      {subTab === 'asset_tiers' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Define asset criticality tiers with environmental multipliers for Depscore calculation.
            </p>
            <Button size="sm" onClick={() => setAddingTier(true)} disabled={addingTier}>
              <Plus className="h-3.5 w-3.5 mr-1.5" />
              Add Tier
            </Button>
          </div>

          <div className="border border-border rounded-lg divide-y divide-border">
            {assetTiers.map((tier) => (
              <div key={tier.id} className="flex items-center gap-3 px-4 py-3">
                <GripVertical className="h-4 w-4 text-muted-foreground/50 cursor-grab" />
                <div className="h-3 w-3 rounded-full flex-shrink-0" style={{ backgroundColor: tier.color }} />
                <span className="text-sm font-medium text-foreground flex-1">{tier.name}</span>
                {tier.description && <span className="text-xs text-muted-foreground max-w-[200px] truncate">{tier.description}</span>}
                <Badge variant="outline" className="text-xs font-mono">{tier.environmental_multiplier}x</Badge>
                {tier.is_system && <Lock className="h-3.5 w-3.5 text-muted-foreground" />}
                {!tier.is_system && (
                  <button onClick={() => handleDeleteTier(tier.id)} className="text-muted-foreground hover:text-destructive transition-colors">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            ))}

            {addingTier && (
              <div className="flex items-center gap-3 px-4 py-3 bg-muted/30">
                <input type="color" value={newTierColor} onChange={(e) => setNewTierColor(e.target.value)} className="h-6 w-6 rounded cursor-pointer border-0" />
                <Input
                  value={newTierName}
                  onChange={(e) => setNewTierName(e.target.value)}
                  placeholder="Tier name..."
                  className="h-8 text-sm flex-1"
                  autoFocus
                  onKeyDown={(e) => e.key === 'Enter' && handleAddTier()}
                />
                <Input
                  value={newTierMultiplier}
                  onChange={(e) => setNewTierMultiplier(e.target.value)}
                  placeholder="1.0"
                  className="h-8 text-sm w-20"
                  type="number"
                  step="0.1"
                  min="0.1"
                  max="3.0"
                />
                <span className="text-xs text-muted-foreground">×</span>
                <button onClick={handleAddTier} className="text-green-500 hover:text-green-400"><Check className="h-4 w-4" /></button>
                <button onClick={() => setAddingTier(false)} className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Status Code sub-tab */}
      {subTab === 'status_code' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              This code determines the project status based on dependency policy results and vulnerabilities.
            </p>
            <div className="flex items-center gap-2">
              {statusCodeDirty && (
                <Button size="sm" variant="ghost" onClick={() => { setStatusCodeValue(statusCodeOriginal); setStatusCodeDirty(false); }}>
                  Discard
                </Button>
              )}
              <Button size="sm" onClick={handleSaveStatusCode} disabled={!statusCodeDirty || saving}>
                {saving && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
                Save
              </Button>
            </div>
          </div>

          <div className="border border-border rounded-lg overflow-hidden">
            <PolicyCodeEditor
              value={statusCodeValue}
              onChange={(val) => {
                setStatusCodeValue(val || '');
                setStatusCodeDirty((val || '') !== statusCodeOriginal);
              }}
            />
          </div>
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
          ) : changes.length === 0 ? (
            <div className="text-sm text-muted-foreground text-center py-8 border border-border rounded-lg">
              No changes recorded yet.
            </div>
          ) : (
            <div className="border border-border rounded-lg divide-y divide-border">
              {changes.map((change: any) => (
                <div key={change.id} className="px-4 py-3 flex items-center gap-3">
                  <Badge variant="outline" className="text-xs">{change.code_type.replace('_', ' ')}</Badge>
                  <span className="text-sm text-foreground flex-1 truncate">{change.message}</span>
                  <span className="text-xs text-muted-foreground">{new Date(change.created_at).toLocaleDateString()}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
