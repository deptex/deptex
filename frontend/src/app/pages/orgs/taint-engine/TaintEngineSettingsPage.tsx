/**
 * Taint Engine settings + framework models admin page.
 *
 * Three sections, top-down:
 *   1. Cost cap card — first editable AI cost cap in the codebase. Sets
 *      taint_engine_settings.monthly_ai_cost_cap_usd; reads back the
 *      current month's spend so admins can see remaining headroom.
 *   2. Killswitch status — visible only when killswitch_active=true.
 *      Renders a destructive-tone alert with the engagement reason and
 *      a release button (manage_aegis only).
 *   3. Framework models table — list of org-scoped AI-inferred / user-
 *      edited specs. Add Framework opens a modal that pastes code samples
 *      and triggers POST /framework-models (server runs inference).
 *      Per-row Edit / Refresh / Delete.
 *
 * Engine flows from this page exclusively rely on backend routes added in
 * the same commit. Engine itself runs in shadow mode (no UI surface for
 * the produced flows) until the M8 retirement gates are met.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Loader2, Plus, RefreshCw, Trash2, Pencil, AlertTriangle, Save, X } from 'lucide-react';
import { Button } from '../../../../components/ui/button';
import { Dialog, DialogContent, DialogTitle, DialogDescription, DialogFooter } from '../../../../components/ui/dialog';
import { Input } from '../../../../components/ui/input';
import { Label } from '../../../../components/ui/label';
import { useToast } from '../../../../hooks/use-toast';
import { fetchWithAuth } from '../../../../lib/api';
import { cn } from '../../../../lib/utils';

// ---------------------------------------------------------------------------
// Types — mirror taint-engine spec.ts + spec-cache.ts
// ---------------------------------------------------------------------------

interface TaintEngineSettings {
  organization_id: string;
  enabled: boolean;
  ai_layer_enabled: boolean;
  monthly_ai_cost_cap_usd: number;
  untyped_js_enabled: boolean;
  vuln_classes_enabled: string[];
  killswitch_active: boolean;
  killswitch_reason: string | null;
  killswitch_activated_at: string | null;
}

interface FrameworkModelRow {
  id: string;
  framework_name: string;
  framework_version: string;
  source_type: 'hand_written' | 'ai_inferred' | 'user_edited';
  inferred_at: string | null;
  inferred_by_model: string | null;
  inferred_cost_usd: number | null;
  edited_at: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

interface FrameworkSpec {
  framework: string;
  version: string;
  sources: Array<Record<string, unknown>>;
  sinks: Array<Record<string, unknown>>;
  sanitizers: Array<Record<string, unknown>>;
}

interface FrameworkModelDetail extends FrameworkModelRow {
  spec: FrameworkSpec;
}

interface CostCapState {
  capUsd: number;
  spentUsdThisMonth: number;
  remainingUsd: number;
  exceeded: boolean;
}

const SOURCE_TYPE_LABEL: Record<FrameworkModelRow['source_type'], string> = {
  hand_written: 'Hand-written',
  ai_inferred: 'AI-inferred',
  user_edited: 'Edited',
};

function formatDollars(usd: number): string {
  return `$${usd.toFixed(2)}`;
}

function formatRelative(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString();
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function TaintEngineSettingsPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const { toast } = useToast();

  const [settings, setSettings] = useState<TaintEngineSettings | null>(null);
  const [costCap, setCostCap] = useState<CostCapState | null>(null);
  const [models, setModels] = useState<FrameworkModelRow[]>([]);
  const [loading, setLoading] = useState(true);

  const [editingCap, setEditingCap] = useState(false);
  const [pendingCap, setPendingCap] = useState<string>('');
  const [savingCap, setSavingCap] = useState(false);
  const [releasingKillswitch, setReleasingKillswitch] = useState(false);

  const [addOpen, setAddOpen] = useState(false);
  const [editOpen, setEditOpen] = useState<FrameworkModelDetail | null>(null);

  const reload = async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const [s, c, m] = await Promise.all([
        fetchWithAuth(`/api/orgs/${orgId}/taint-engine/settings`) as Promise<TaintEngineSettings>,
        fetchWithAuth(`/api/orgs/${orgId}/taint-engine/cost`) as Promise<CostCapState>,
        fetchWithAuth(`/api/orgs/${orgId}/taint-engine/framework-models`) as Promise<FrameworkModelRow[]>,
      ]);
      setSettings(s);
      setCostCap(c);
      setModels(m);
    } catch (err: any) {
      toast({ title: 'Failed to load settings', description: err.message ?? 'Unknown error', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId]);

  const beginEditCap = () => {
    setPendingCap(String(settings?.monthly_ai_cost_cap_usd ?? 50));
    setEditingCap(true);
  };

  const saveCap = async () => {
    if (!orgId) return;
    const v = Number(pendingCap);
    if (!Number.isFinite(v) || v < 0) {
      toast({ title: 'Invalid cap', description: 'Must be a non-negative number', variant: 'destructive' });
      return;
    }
    setSavingCap(true);
    try {
      const next = await fetchWithAuth(`/api/orgs/${orgId}/taint-engine/settings`, {
        method: 'PATCH',
        body: JSON.stringify({ monthly_ai_cost_cap_usd: v }),
      });
      setSettings(next);
      setEditingCap(false);
      toast({ title: 'Cost cap updated', description: `New monthly cap: ${formatDollars(next.monthly_ai_cost_cap_usd)}` });
      // Refresh cost state since the cap changed.
      const c = await fetchWithAuth(`/api/orgs/${orgId}/taint-engine/cost`);
      setCostCap(c);
    } catch (err: any) {
      toast({ title: 'Save failed', description: err.message ?? 'Unknown error', variant: 'destructive' });
    } finally {
      setSavingCap(false);
    }
  };

  const releaseKillswitch = async () => {
    if (!orgId) return;
    setReleasingKillswitch(true);
    try {
      await fetchWithAuth(`/api/orgs/${orgId}/taint-engine/killswitch/release`, { method: 'POST' });
      toast({ title: 'Killswitch released', description: 'Engine will resume on the next extraction.' });
      await reload();
    } catch (err: any) {
      toast({ title: 'Release failed', description: err.message ?? 'Unknown error', variant: 'destructive' });
    } finally {
      setReleasingKillswitch(false);
    }
  };

  const handleDelete = async (modelId: string, name: string) => {
    if (!orgId) return;
    if (!window.confirm(`Remove ${name} from the framework models cache? The next extraction will need to re-infer it.`)) return;
    try {
      await fetchWithAuth(`/api/orgs/${orgId}/taint-engine/framework-models/${modelId}`, { method: 'DELETE' });
      toast({ title: 'Removed', description: name });
      await reload();
    } catch (err: any) {
      toast({ title: 'Delete failed', description: err.message ?? 'Unknown error', variant: 'destructive' });
    }
  };

  const openEdit = async (modelId: string) => {
    if (!orgId) return;
    try {
      const detail = (await fetchWithAuth(`/api/orgs/${orgId}/taint-engine/framework-models/${modelId}`)) as FrameworkModelDetail;
      setEditOpen(detail);
    } catch (err: any) {
      toast({ title: 'Failed to load model', description: err.message ?? 'Unknown error', variant: 'destructive' });
    }
  };

  if (!orgId) return null;

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-semibold text-foreground">Taint Engine</h1>
        <p className="mt-1 text-sm text-foreground-secondary">
          Cross-file taint analysis spec management + AI inference budget. Engine runs in shadow mode during the
          phased rollout — flows are written but not yet surfaced in the security UI.
        </p>
      </header>

      {settings?.killswitch_active && (
        <KillswitchBanner
          reason={settings.killswitch_reason}
          activatedAt={settings.killswitch_activated_at}
          onRelease={releaseKillswitch}
          releasing={releasingKillswitch}
        />
      )}

      <CostCapCard
        settings={settings}
        costCap={costCap}
        loading={loading}
        editing={editingCap}
        pendingCap={pendingCap}
        saving={savingCap}
        onBegin={beginEditCap}
        onCancel={() => setEditingCap(false)}
        onChange={setPendingCap}
        onSave={saveCap}
      />

      <FrameworkModelsTable
        models={models}
        loading={loading}
        onAdd={() => setAddOpen(true)}
        onEdit={openEdit}
        onDelete={handleDelete}
      />

      {addOpen && (
        <AddFrameworkModal
          orgId={orgId}
          onClose={() => setAddOpen(false)}
          onAdded={async () => {
            setAddOpen(false);
            await reload();
          }}
        />
      )}

      {editOpen && (
        <EditFrameworkModal
          orgId={orgId}
          model={editOpen}
          onClose={() => setEditOpen(null)}
          onSaved={async () => {
            setEditOpen(null);
            await reload();
          }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Killswitch banner
// ---------------------------------------------------------------------------

function KillswitchBanner({
  reason,
  activatedAt,
  onRelease,
  releasing,
}: {
  reason: string | null;
  activatedAt: string | null;
  onRelease: () => void;
  releasing: boolean;
}) {
  return (
    <section className="rounded-lg border border-destructive/40 bg-destructive/10 p-4">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-5 w-5 flex-shrink-0 text-destructive" />
        <div className="flex-1">
          <h3 className="text-sm font-semibold text-destructive">Killswitch engaged</h3>
          <p className="mt-1 text-sm text-foreground-secondary">
            The taint engine is disabled fleet-wide for this organization.
            {reason ? <> Reason: <span className="text-foreground">{reason}</span></> : null}
            {activatedAt ? <> Engaged at {new Date(activatedAt).toLocaleString()}.</> : null}
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={onRelease} disabled={releasing}>
          {releasing ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Release'}
        </Button>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Cost cap card
// ---------------------------------------------------------------------------

function CostCapCard({
  settings,
  costCap,
  loading,
  editing,
  pendingCap,
  saving,
  onBegin,
  onCancel,
  onChange,
  onSave,
}: {
  settings: TaintEngineSettings | null;
  costCap: CostCapState | null;
  loading: boolean;
  editing: boolean;
  pendingCap: string;
  saving: boolean;
  onBegin: () => void;
  onCancel: () => void;
  onChange: (v: string) => void;
  onSave: () => void;
}) {
  const cap = settings?.monthly_ai_cost_cap_usd ?? 0;
  const spent = costCap?.spentUsdThisMonth ?? 0;
  const pct = cap > 0 ? Math.min(100, Math.round((spent / cap) * 100)) : 0;
  const barColor = pct >= 90 ? 'bg-destructive' : pct >= 75 ? 'bg-amber-500' : 'bg-foreground';

  return (
    <section className="rounded-lg border border-border bg-background-card p-5">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-sm font-semibold text-foreground">Monthly AI cost cap</h2>
          <p className="mt-1 text-xs text-foreground-secondary">
            Caps total AI spend for taint engine spec inference + per-flow false-positive filter (M7).
            Enforced server-side before each AI call.
          </p>
        </div>
        {!editing && (
          <Button size="sm" variant="outline" onClick={onBegin} disabled={loading}>
            <Pencil className="mr-1.5 h-3.5 w-3.5" />
            Edit
          </Button>
        )}
      </div>

      {!editing ? (
        <div className="mt-4 flex items-baseline gap-3">
          <span className="text-2xl font-semibold text-foreground">{formatDollars(cap)}</span>
          <span className="text-sm text-foreground-secondary">/ month</span>
        </div>
      ) : (
        <div className="mt-4 flex items-end gap-2">
          <div className="flex-1 max-w-[200px]">
            <Label htmlFor="cap-input" className="text-xs text-foreground-secondary">USD per month</Label>
            <Input
              id="cap-input"
              type="number"
              step="0.01"
              min="0"
              max="1000"
              value={pendingCap}
              onChange={(e) => onChange(e.target.value)}
              className="mt-1"
              autoFocus
            />
          </div>
          <Button size="sm" onClick={onSave} disabled={saving}>
            {saving ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Save className="mr-1.5 h-3.5 w-3.5" />}
            Save
          </Button>
          <Button size="sm" variant="outline" onClick={onCancel} disabled={saving}>
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>
      )}

      {costCap && (
        <div className="mt-5 space-y-2">
          <div className="flex items-baseline justify-between text-xs">
            <span className="text-foreground-secondary">This month</span>
            <span className={cn('font-medium', costCap.exceeded ? 'text-destructive' : 'text-foreground')}>
              {formatDollars(spent)} of {formatDollars(cap)} ({pct}%)
            </span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-background-subtle">
            <div className={cn('h-full transition-all', barColor)} style={{ width: `${pct}%` }} />
          </div>
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Framework models table
// ---------------------------------------------------------------------------

function FrameworkModelsTable({
  models,
  loading,
  onAdd,
  onEdit,
  onDelete,
}: {
  models: FrameworkModelRow[];
  loading: boolean;
  onAdd: () => void;
  onEdit: (id: string) => void;
  onDelete: (id: string, name: string) => void;
}) {
  return (
    <section className="rounded-lg border border-border bg-background-card overflow-hidden">
      <header className="flex items-center justify-between border-b border-border px-5 py-4">
        <div>
          <h2 className="text-sm font-semibold text-foreground">Framework models</h2>
          <p className="mt-0.5 text-xs text-foreground-secondary">
            AI-inferred + admin-edited specs for frameworks not in the bundled set (Express, Fastify, NestJS, Next.js, Hono).
          </p>
        </div>
        <Button size="sm" onClick={onAdd}>
          <Plus className="mr-1.5 h-3.5 w-3.5" />
          Add framework
        </Button>
      </header>

      {loading ? (
        <div className="flex items-center justify-center p-10 text-foreground-secondary">
          <Loader2 className="h-5 w-5 animate-spin" />
        </div>
      ) : models.length === 0 ? (
        <div className="p-10 text-center">
          <p className="text-sm text-foreground-secondary">
            No org-specific framework models yet. Add one to teach the engine about a framework not in the bundled set.
          </p>
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead className="bg-background-card-header text-foreground-secondary">
            <tr>
              <th className="px-5 py-2.5 text-left font-medium">Framework</th>
              <th className="px-5 py-2.5 text-left font-medium">Version</th>
              <th className="px-5 py-2.5 text-left font-medium">Source</th>
              <th className="px-5 py-2.5 text-left font-medium">Updated</th>
              <th className="px-5 py-2.5 text-left font-medium">Cost (USD)</th>
              <th className="px-5 py-2.5 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {models.map((m) => (
              <tr key={m.id} className="hover:bg-table-hover">
                <td className="px-5 py-3 font-medium text-foreground">{m.framework_name}</td>
                <td className="px-5 py-3 font-mono text-xs text-foreground-secondary">{m.framework_version}</td>
                <td className="px-5 py-3">
                  <span
                    className={cn(
                      'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider',
                      m.source_type === 'hand_written'
                        ? 'border-border bg-background-card text-foreground-secondary'
                        : m.source_type === 'ai_inferred'
                          ? 'border-purple-500/30 bg-purple-500/10 text-purple-300'
                          : 'border-amber-500/30 bg-amber-500/10 text-amber-300',
                    )}
                  >
                    {SOURCE_TYPE_LABEL[m.source_type]}
                  </span>
                </td>
                <td className="px-5 py-3 text-foreground-secondary">{formatRelative(m.updated_at)}</td>
                <td className="px-5 py-3 font-mono text-xs text-foreground-secondary">
                  {m.inferred_cost_usd != null ? `$${Number(m.inferred_cost_usd).toFixed(4)}` : '—'}
                </td>
                <td className="px-5 py-3 text-right">
                  <Button variant="outline" size="sm" className="mr-1.5" onClick={() => onEdit(m.id)}>
                    <Pencil className="h-3.5 w-3.5" />
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => onDelete(m.id, m.framework_name)}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Add framework modal — captures name + version + pasted code samples,
// triggers POST /framework-models which runs AI inference server-side.
// ---------------------------------------------------------------------------

function AddFrameworkModal({
  orgId,
  onClose,
  onAdded,
}: {
  orgId: string;
  onClose: () => void;
  onAdded: () => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [version, setVersion] = useState('*');
  const [samples, setSamples] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const submit = async () => {
    if (!name.trim() || !samples.trim()) {
      toast({ title: 'Missing fields', description: 'Framework name and code samples are both required.', variant: 'destructive' });
      return;
    }
    setSubmitting(true);
    try {
      await fetchWithAuth(`/api/orgs/${orgId}/taint-engine/framework-models`, {
        method: 'POST',
        body: JSON.stringify({
          framework_name: name.trim(),
          framework_version: version.trim() || '*',
          code_samples: [{ path: 'pasted-sample.ts', content: samples }],
        }),
      });
      toast({ title: 'Inference complete', description: `Spec for ${name} cached.` });
      onAdded();
    } catch (err: any) {
      toast({ title: 'Inference failed', description: err.message ?? 'Unknown error', variant: 'destructive' });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogTitle>Add framework</DialogTitle>
        <DialogDescription>
          Paste a representative code sample (route handlers, middleware exports, request-object usage). The engine
          will ask Gemini Flash to infer a taint spec, validate it, and cache the result.
        </DialogDescription>
        <div className="mt-4 grid grid-cols-2 gap-3">
          <div>
            <Label htmlFor="add-name">Framework name</Label>
            <Input id="add-name" placeholder="e.g. trpc, koa" value={name} onChange={(e) => setName(e.target.value)} className="mt-1" />
          </div>
          <div>
            <Label htmlFor="add-version">Version</Label>
            <Input id="add-version" placeholder="* or ^10" value={version} onChange={(e) => setVersion(e.target.value)} className="mt-1" />
          </div>
        </div>
        <div className="mt-3">
          <Label htmlFor="add-samples">Code samples</Label>
          <textarea
            id="add-samples"
            className="mt-1 h-64 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground placeholder:text-foreground-muted focus:outline-none focus:ring-1 focus:ring-ring"
            placeholder="// paste route handlers, middleware exports, request/response types..."
            value={samples}
            onChange={(e) => setSamples(e.target.value)}
          />
          <p className="mt-1 text-[11px] text-foreground-muted">
            Up to ~30 KB. The model only sees what you paste here.
          </p>
        </div>
        <DialogFooter className="mt-4">
          <Button variant="outline" onClick={onClose} disabled={submitting}>Cancel</Button>
          <Button onClick={submit} disabled={submitting}>
            {submitting ? <><Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />Inferring</> : 'Run inference'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Edit framework modal — JSON textarea for spec body. PATCH on save.
// Refresh re-runs inference using a new code sample.
// ---------------------------------------------------------------------------

function EditFrameworkModal({
  orgId,
  model,
  onClose,
  onSaved,
}: {
  orgId: string;
  model: FrameworkModelDetail;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [specText, setSpecText] = useState(() => JSON.stringify(model.spec, null, 2));
  const [refreshSamples, setRefreshSamples] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);

  const save = async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(specText);
    } catch (err: any) {
      setParseError(err.message ?? 'Invalid JSON');
      return;
    }
    setParseError(null);
    setSubmitting(true);
    try {
      await fetchWithAuth(`/api/orgs/${orgId}/taint-engine/framework-models/${model.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ spec: parsed }),
      });
      toast({ title: 'Spec saved', description: `${model.framework_name} marked as user-edited.` });
      onSaved();
    } catch (err: any) {
      toast({ title: 'Save failed', description: err.message ?? 'Unknown error', variant: 'destructive' });
    } finally {
      setSubmitting(false);
    }
  };

  const refresh = async () => {
    if (!refreshSamples.trim()) {
      toast({ title: 'Code samples required', description: 'Paste fresh framework source for re-inference.', variant: 'destructive' });
      return;
    }
    setRefreshing(true);
    try {
      const next = (await fetchWithAuth(`/api/orgs/${orgId}/taint-engine/framework-models/${model.id}/refresh`, {
        method: 'POST',
        body: JSON.stringify({
          code_samples: [{ path: 'pasted-refresh.ts', content: refreshSamples }],
        }),
      })) as FrameworkModelDetail;
      setSpecText(JSON.stringify(next.spec, null, 2));
      toast({ title: 'Re-inference complete', description: `${model.framework_name} spec updated.` });
    } catch (err: any) {
      toast({ title: 'Refresh failed', description: err.message ?? 'Unknown error', variant: 'destructive' });
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-3xl">
        <DialogTitle>
          {model.framework_name} <span className="text-foreground-secondary">@{model.framework_version}</span>
        </DialogTitle>
        <DialogDescription>
          Edit the spec body directly — saving flips it to user-edited. Or paste new framework source code below
          and re-run inference.
        </DialogDescription>

        <div className="mt-4">
          <Label>Spec body (JSON)</Label>
          <textarea
            className="mt-1 h-72 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground"
            value={specText}
            onChange={(e) => setSpecText(e.target.value)}
            spellCheck={false}
          />
          {parseError && <p className="mt-1 text-xs text-destructive">JSON: {parseError}</p>}
        </div>

        <div className="mt-4">
          <Label>Re-inference samples (optional)</Label>
          <textarea
            className="mt-1 h-32 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground placeholder:text-foreground-muted"
            placeholder="// paste new code samples to re-run AI inference..."
            value={refreshSamples}
            onChange={(e) => setRefreshSamples(e.target.value)}
          />
          <Button variant="outline" size="sm" className="mt-2" onClick={refresh} disabled={refreshing || !refreshSamples}>
            {refreshing ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="mr-1.5 h-3.5 w-3.5" />}
            Re-run inference
          </Button>
        </div>

        <DialogFooter className="mt-4">
          <Button variant="outline" onClick={onClose} disabled={submitting}>Cancel</Button>
          <Button onClick={save} disabled={submitting}>
            {submitting ? <><Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />Saving</> : 'Save'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
