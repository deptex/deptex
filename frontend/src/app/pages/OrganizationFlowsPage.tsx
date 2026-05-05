import { useEffect, useState } from 'react';
import { useNavigate, useOutletContext, useParams } from 'react-router-dom';
import { Loader2, Plus, Workflow } from 'lucide-react';
import { api, type Flow, type Organization } from '../../lib/api';
import { Button } from '../../components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from '../../components/ui/dialog';
import { useToast } from '../../hooks/use-toast';
import { cn } from '../../lib/utils';
import PageHeader from '../../components/PageHeader';

interface OutletContext {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

export default function OrganizationFlowsPage() {
  const { id: orgId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { organization } = useOutletContext<OutletContext>();
  const { toast } = useToast();

  const [flows, setFlows] = useState<Flow[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);

  useEffect(() => {
    if (!orgId) return;
    let cancelled = false;
    setLoading(true);
    api
      .listFlows({ organizationId: orgId })
      .then((res) => { if (!cancelled) setFlows(res); })
      .catch((err: unknown) => {
        if (cancelled) return;
        const msg = err instanceof Error ? err.message : String(err);
        toast({ title: 'Error', description: msg || 'Failed to load flows', variant: 'destructive' });
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [orgId, toast]);

  const handleCreated = (flow: Flow) => {
    setFlows((prev) => [flow, ...prev]);
    setCreateOpen(false);
    if (orgId) navigate(`/organizations/${orgId}/flows/${flow.id}`);
  };

  return (
    <>
      <PageHeader
        title="Flows"
        description={`Visual automations for ${organization?.name ?? 'this organization'}.`}
        actions={
          <Button onClick={() => setCreateOpen(true)} className="gap-1.5">
            <Plus className="h-4 w-4" />
            New flow
          </Button>
        }
      />
      <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 py-6">
        {loading ? (
        <div className="flex h-60 items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" />
        </div>
      ) : flows.length === 0 ? (
        <EmptyState onCreate={() => setCreateOpen(true)} />
      ) : (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {flows.map((flow) => (
            <FlowCard
              key={flow.id}
              flow={flow}
              onClick={() => orgId && navigate(`/organizations/${orgId}/flows/${flow.id}`)}
            />
          ))}
        </div>
      )}

      {orgId && (
        <NewFlowDialog
          open={createOpen}
          organizationId={orgId}
          onClose={() => setCreateOpen(false)}
          onCreated={handleCreated}
        />
      )}
      </div>
    </>
  );
}

// ─── Flow card ───────────────────────────────────────────────────────────────

function FlowCard({ flow, onClick }: { flow: Flow; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="group flex flex-col items-stretch rounded-xl border border-border bg-background-card p-4 text-left transition-all hover:border-foreground/30 hover:bg-background-card-header"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg border border-border bg-background-card-header text-foreground-secondary transition-colors group-hover:text-foreground">
          <Workflow className="h-4 w-4" />
        </div>
        <span
          className={cn(
            'inline-flex items-center gap-1 text-[11px] font-medium',
            flow.active ? 'text-emerald-400' : 'text-foreground-secondary',
          )}
        >
          <span
            className={cn(
              'h-1.5 w-1.5 rounded-full',
              flow.active ? 'bg-emerald-400' : 'bg-foreground-secondary/50',
            )}
          />
          {flow.active ? 'Active' : 'Paused'}
        </span>
      </div>

      <div className="mt-4">
        <p className="truncate text-sm font-medium text-foreground">{flow.name}</p>
        <p className="mt-0.5 text-[12px] text-foreground-secondary">
          {flow.graph?.nodes?.length ?? 0} {flow.graph?.nodes?.length === 1 ? 'node' : 'nodes'}
        </p>
      </div>
    </button>
  );
}

// ─── Empty state ─────────────────────────────────────────────────────────────

function EmptyState({ onCreate }: { onCreate: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border bg-background-card/40 px-6 py-16 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-border bg-background-card-header text-foreground-secondary">
        <Workflow className="h-5 w-5" />
      </div>
      <p className="mt-4 text-sm font-medium text-foreground">No flows yet</p>
      <p className="mt-1 max-w-sm text-[13px] text-foreground-secondary">
        Flows automate what happens when events fire in this organization — notifications, PR
        checks, status changes, and more.
      </p>
      <Button onClick={onCreate} className="mt-5 gap-1.5">
        <Plus className="h-4 w-4" />
        Create your first flow
      </Button>
    </div>
  );
}

// ─── New flow dialog ─────────────────────────────────────────────────────────

function NewFlowDialog({
  open,
  organizationId,
  onClose,
  onCreated,
}: {
  open: boolean;
  organizationId: string;
  onClose: () => void;
  onCreated: (flow: Flow) => void;
}) {
  const [name, setName] = useState('');
  const [creating, setCreating] = useState(false);
  const { toast } = useToast();

  const handleCreate = async () => {
    if (!name.trim() || creating) return;
    setCreating(true);
    try {
      const flow = await api.createFlow({
        organization_id: organizationId,
        flow_type: 'notification',
        scope: 'organization',
        scope_id: organizationId,
        name: name.trim(),
        graph: {
          version: 1,
          nodes: [
            { id: 'trigger-1', type: 'trigger', position: { x: 100, y: 200 }, config: { event_type: 'vulnerability_discovered' } },
            { id: 'condition-1', type: 'condition', position: { x: 320, y: 200 }, config: {} },
            { id: 'action-1', type: 'action', position: { x: 540, y: 200 }, config: {} },
          ],
          edges: [
            { id: 'e-trigger-condition', source: 'trigger-1', sourceHandle: 'source-right', target: 'condition-1', targetHandle: 'left' },
            { id: 'e-condition-action', source: 'condition-1', sourceHandle: 'source-right', target: 'action-1', targetHandle: 'left' },
          ],
        },
      });
      onCreated(flow);
      setName('');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      toast({ title: 'Error', description: msg || 'Failed to create flow', variant: 'destructive' });
    } finally {
      setCreating(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) { onClose(); setName(''); } }}>
      <DialogContent className="sm:max-w-[460px]">
        <DialogTitle>New flow</DialogTitle>
        <DialogDescription>
          Give your flow a name. You can configure triggers and actions in the editor.
        </DialogDescription>

        <div className="mt-2">
          <label className="mb-1.5 block text-sm font-medium text-foreground">Name</label>
          <input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleCreate(); }}
            placeholder="e.g. Critical vulnerability alerts"
            className="w-full rounded-md border border-border bg-background-card px-3 py-2 text-sm text-foreground placeholder:text-foreground-secondary/60 focus:border-foreground/40 focus:outline-none"
          />
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => { onClose(); setName(''); }}>
            Cancel
          </Button>
          <Button onClick={handleCreate} disabled={!name.trim() || creating}>
            {creating ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Create'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
