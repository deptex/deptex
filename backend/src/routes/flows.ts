import express from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import type {
  Flow,
  FlowGraph,
  FlowType,
  FlowScope,
  CreateFlowRequest,
  UpdateFlowRequest,
} from '../lib/flows/types';

const router = express.Router();
router.use(authenticateUser);

const VALID_FLOW_TYPES: FlowType[] = ['notification', 'pr_check', 'policy', 'status'];
const VALID_SCOPES: FlowScope[] = ['organization', 'team', 'project'];

// ---------- RBAC ----------

// Permission required to mutate a flow of a given type. Owner/admin always pass.
function permissionsForFlowType(flowType: FlowType): string[] {
  switch (flowType) {
    case 'notification':
      return ['manage_notifications', 'manage_integrations'];
    case 'pr_check':
    case 'policy':
      return ['manage_policies'];
    case 'status':
      return ['manage_statuses'];
  }
}

async function canViewOrg(organizationId: string, userId: string): Promise<boolean> {
  const { data } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .single();
  return !!data;
}

async function canManageFlow(
  organizationId: string,
  userId: string,
  flowType: FlowType,
): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .single();
  if (!membership) return false;
  if (membership.role === 'owner' || membership.role === 'admin') return true;

  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', organizationId)
    .eq('name', membership.role)
    .single();

  const perms = role?.permissions as Record<string, boolean> | undefined;
  if (!perms) return false;
  return permissionsForFlowType(flowType).some((p) => perms[p] === true);
}

// ---------- Validation ----------

function validateGraph(graph: unknown): { ok: true; graph: FlowGraph } | { ok: false; error: string } {
  if (!graph || typeof graph !== 'object') return { ok: false, error: 'graph must be an object' };
  const g = graph as Record<string, unknown>;
  if (g.version !== 1) return { ok: false, error: 'graph.version must be 1' };
  if (!Array.isArray(g.nodes)) return { ok: false, error: 'graph.nodes must be an array' };
  if (!Array.isArray(g.edges)) return { ok: false, error: 'graph.edges must be an array' };

  const nodeIds = new Set<string>();
  for (const [i, raw] of g.nodes.entries()) {
    if (!raw || typeof raw !== 'object') return { ok: false, error: `nodes[${i}] must be an object` };
    const n = raw as Record<string, unknown>;
    if (typeof n.id !== 'string' || !n.id) return { ok: false, error: `nodes[${i}].id required` };
    if (typeof n.type !== 'string' || !n.type) return { ok: false, error: `nodes[${i}].type required` };
    const pos = n.position as { x?: unknown; y?: unknown } | undefined;
    if (!pos || typeof pos.x !== 'number' || typeof pos.y !== 'number') {
      return { ok: false, error: `nodes[${i}].position must be { x: number, y: number }` };
    }
    if (!n.config || typeof n.config !== 'object') {
      return { ok: false, error: `nodes[${i}].config must be an object` };
    }
    if (nodeIds.has(n.id)) return { ok: false, error: `duplicate node id: ${n.id}` };
    nodeIds.add(n.id);
  }

  const edgeIds = new Set<string>();
  for (const [i, raw] of g.edges.entries()) {
    if (!raw || typeof raw !== 'object') return { ok: false, error: `edges[${i}] must be an object` };
    const e = raw as Record<string, unknown>;
    if (typeof e.id !== 'string' || !e.id) return { ok: false, error: `edges[${i}].id required` };
    if (typeof e.source !== 'string' || !nodeIds.has(e.source)) {
      return { ok: false, error: `edges[${i}].source must reference an existing node` };
    }
    if (typeof e.target !== 'string' || !nodeIds.has(e.target)) {
      return { ok: false, error: `edges[${i}].target must reference an existing node` };
    }
    if (typeof e.sourceHandle !== 'string') {
      return { ok: false, error: `edges[${i}].sourceHandle must be a string` };
    }
    if (typeof e.targetHandle !== 'string') {
      return { ok: false, error: `edges[${i}].targetHandle must be a string` };
    }
    if (edgeIds.has(e.id)) return { ok: false, error: `duplicate edge id: ${e.id}` };
    edgeIds.add(e.id);
  }

  return { ok: true, graph: g as unknown as FlowGraph };
}

const EMPTY_GRAPH: FlowGraph = { version: 1, nodes: [], edges: [] };

// ---------- Helpers ----------

async function loadFlow(flowId: string): Promise<Flow | null> {
  const { data } = await supabase.from('flows').select('*').eq('id', flowId).single();
  return (data as Flow | null) ?? null;
}

// ---------- Routes ----------

// GET /api/flows?organization_id=...&flow_type=...&scope=...&scope_id=...
router.get('/', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const organizationId = req.query.organization_id as string | undefined;
    if (!organizationId) {
      return res.status(400).json({ error: 'organization_id is required' });
    }
    if (!(await canViewOrg(organizationId, userId))) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    let q = supabase
      .from('flows')
      .select('*')
      .eq('organization_id', organizationId)
      .order('updated_at', { ascending: false });

    const flowType = req.query.flow_type as string | undefined;
    if (flowType) {
      if (!VALID_FLOW_TYPES.includes(flowType as FlowType)) {
        return res.status(400).json({ error: 'invalid flow_type' });
      }
      q = q.eq('flow_type', flowType);
    }

    const scope = req.query.scope as string | undefined;
    if (scope) {
      if (!VALID_SCOPES.includes(scope as FlowScope)) {
        return res.status(400).json({ error: 'invalid scope' });
      }
      q = q.eq('scope', scope);
    }

    const scopeId = req.query.scope_id as string | undefined;
    if (scopeId) q = q.eq('scope_id', scopeId);

    const { data, error } = await q;
    if (error) throw error;
    res.json(data ?? []);
  } catch (error: any) {
    console.error('Error listing flows:', error);
    res.status(500).json({ error: error.message || 'Failed to list flows' });
  }
});

// GET /api/flows/:id
router.get('/:id', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const flow = await loadFlow(req.params.id);
    if (!flow) return res.status(404).json({ error: 'Flow not found' });
    if (!(await canViewOrg(flow.organization_id, userId))) {
      return res.status(404).json({ error: 'Flow not found' });
    }
    res.json(flow);
  } catch (error: any) {
    console.error('Error fetching flow:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch flow' });
  }
});

// POST /api/flows
router.post('/', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const body = req.body as CreateFlowRequest & { organization_id?: string };
    const { flow_type, scope, scope_id, name, description, graph } = body;
    const organization_id = body.organization_id;

    if (!organization_id) return res.status(400).json({ error: 'organization_id is required' });
    if (!flow_type || !VALID_FLOW_TYPES.includes(flow_type)) {
      return res.status(400).json({ error: 'flow_type must be one of: ' + VALID_FLOW_TYPES.join(', ') });
    }
    if (!scope || !VALID_SCOPES.includes(scope)) {
      return res.status(400).json({ error: 'scope must be one of: ' + VALID_SCOPES.join(', ') });
    }
    if (!scope_id || typeof scope_id !== 'string') {
      return res.status(400).json({ error: 'scope_id is required' });
    }
    if (!name || typeof name !== 'string' || name.length < 1 || name.length > 100) {
      return res.status(400).json({ error: 'name must be 1-100 chars' });
    }
    if (description != null && (typeof description !== 'string' || description.length > 500)) {
      return res.status(400).json({ error: 'description must be ≤500 chars' });
    }

    let validatedGraph: FlowGraph = EMPTY_GRAPH;
    if (graph !== undefined) {
      const v = validateGraph(graph);
      if (v.ok === false) {
        return res.status(400).json({ error: 'Invalid graph: ' + v.error });
      }
      validatedGraph = v.graph;
    }

    if (!(await canManageFlow(organization_id, userId, flow_type))) {
      return res.status(403).json({ error: 'You do not have permission to manage this flow type' });
    }

    const { data, error } = await supabase
      .from('flows')
      .insert({
        flow_type,
        scope,
        scope_id,
        organization_id,
        name,
        description: description ?? null,
        graph: validatedGraph,
        version: 1,
        active: true,
        dry_run: false,
        created_by_user_id: userId,
      })
      .select('*')
      .single();
    if (error) throw error;

    // Seed version history with v1.
    await supabase.from('flow_versions').insert({
      flow_id: (data as Flow).id,
      version: 1,
      graph: validatedGraph,
      name,
      changed_by_user_id: userId,
      change_summary: 'Initial version',
    });

    res.status(201).json(data);
  } catch (error: any) {
    console.error('Error creating flow:', error);
    res.status(500).json({ error: error.message || 'Failed to create flow' });
  }
});

// PUT /api/flows/:id — update name/description/graph; bumps version + writes flow_versions row
router.put('/:id', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const flow = await loadFlow(req.params.id);
    if (!flow) return res.status(404).json({ error: 'Flow not found' });
    if (!(await canManageFlow(flow.organization_id, userId, flow.flow_type))) {
      return res.status(403).json({ error: 'You do not have permission to manage this flow type' });
    }

    const body = req.body as UpdateFlowRequest;
    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    let nextGraph: FlowGraph = flow.graph;
    let graphChanged = false;
    let nextName = flow.name;

    if (body.name !== undefined) {
      if (typeof body.name !== 'string' || body.name.length < 1 || body.name.length > 100) {
        return res.status(400).json({ error: 'name must be 1-100 chars' });
      }
      updates.name = body.name;
      nextName = body.name;
    }
    if (body.description !== undefined) {
      if (body.description !== null) {
        if (typeof body.description !== 'string' || body.description.length > 500) {
          return res.status(400).json({ error: 'description must be ≤500 chars' });
        }
      }
      updates.description = body.description;
    }
    if (body.graph !== undefined) {
      const v = validateGraph(body.graph);
      if (v.ok === false) {
        return res.status(400).json({ error: 'Invalid graph: ' + v.error });
      }
      nextGraph = v.graph;
      updates.graph = nextGraph;
      graphChanged = true;
    }

    // Bump version when graph changes (history is per-graph-state, not per-name-edit).
    if (graphChanged) {
      updates.version = flow.version + 1;
    }

    const { data, error } = await supabase
      .from('flows')
      .update(updates)
      .eq('id', flow.id)
      .select('*')
      .single();
    if (error) throw error;

    if (graphChanged) {
      await supabase.from('flow_versions').insert({
        flow_id: flow.id,
        version: flow.version + 1,
        graph: nextGraph,
        name: nextName,
        changed_by_user_id: userId,
        change_summary: body.change_summary ?? null,
      });
    }

    res.json(data);
  } catch (error: any) {
    console.error('Error updating flow:', error);
    res.status(500).json({ error: error.message || 'Failed to update flow' });
  }
});

// DELETE /api/flows/:id — hard delete (cascades to versions + runs)
router.delete('/:id', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const flow = await loadFlow(req.params.id);
    if (!flow) return res.status(404).json({ error: 'Flow not found' });
    if (!(await canManageFlow(flow.organization_id, userId, flow.flow_type))) {
      return res.status(403).json({ error: 'You do not have permission to manage this flow type' });
    }

    const { error } = await supabase.from('flows').delete().eq('id', flow.id);
    if (error) throw error;
    res.status(204).send();
  } catch (error: any) {
    console.error('Error deleting flow:', error);
    res.status(500).json({ error: error.message || 'Failed to delete flow' });
  }
});

// PATCH /api/flows/:id/active — { active: boolean }
router.patch('/:id/active', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const flow = await loadFlow(req.params.id);
    if (!flow) return res.status(404).json({ error: 'Flow not found' });
    if (!(await canManageFlow(flow.organization_id, userId, flow.flow_type))) {
      return res.status(403).json({ error: 'You do not have permission to manage this flow type' });
    }
    const { active } = req.body as { active?: unknown };
    if (typeof active !== 'boolean') return res.status(400).json({ error: 'active must be a boolean' });

    const { data, error } = await supabase
      .from('flows')
      .update({ active, updated_at: new Date().toISOString() })
      .eq('id', flow.id)
      .select('*')
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error: any) {
    console.error('Error toggling flow active:', error);
    res.status(500).json({ error: error.message || 'Failed to update flow' });
  }
});

// PATCH /api/flows/:id/dry-run — { dry_run: boolean }
router.patch('/:id/dry-run', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const flow = await loadFlow(req.params.id);
    if (!flow) return res.status(404).json({ error: 'Flow not found' });
    if (!(await canManageFlow(flow.organization_id, userId, flow.flow_type))) {
      return res.status(403).json({ error: 'You do not have permission to manage this flow type' });
    }
    const { dry_run } = req.body as { dry_run?: unknown };
    if (typeof dry_run !== 'boolean') return res.status(400).json({ error: 'dry_run must be a boolean' });

    const { data, error } = await supabase
      .from('flows')
      .update({ dry_run, updated_at: new Date().toISOString() })
      .eq('id', flow.id)
      .select('*')
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error: any) {
    console.error('Error toggling flow dry_run:', error);
    res.status(500).json({ error: error.message || 'Failed to update flow' });
  }
});

// PATCH /api/flows/:id/snooze — { snoozed_until: ISO string | null }
router.patch('/:id/snooze', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const flow = await loadFlow(req.params.id);
    if (!flow) return res.status(404).json({ error: 'Flow not found' });
    if (!(await canManageFlow(flow.organization_id, userId, flow.flow_type))) {
      return res.status(403).json({ error: 'You do not have permission to manage this flow type' });
    }
    const { snoozed_until } = req.body as { snoozed_until?: unknown };
    if (snoozed_until !== null && typeof snoozed_until !== 'string') {
      return res.status(400).json({ error: 'snoozed_until must be an ISO string or null' });
    }
    if (typeof snoozed_until === 'string' && Number.isNaN(Date.parse(snoozed_until))) {
      return res.status(400).json({ error: 'snoozed_until must be a valid ISO string' });
    }

    const { data, error } = await supabase
      .from('flows')
      .update({ snoozed_until, updated_at: new Date().toISOString() })
      .eq('id', flow.id)
      .select('*')
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error: any) {
    console.error('Error snoozing flow:', error);
    res.status(500).json({ error: error.message || 'Failed to update flow' });
  }
});

// GET /api/flows/:id/versions — list version history
router.get('/:id/versions', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const flow = await loadFlow(req.params.id);
    if (!flow) return res.status(404).json({ error: 'Flow not found' });
    if (!(await canViewOrg(flow.organization_id, userId))) {
      return res.status(404).json({ error: 'Flow not found' });
    }

    const { data, error } = await supabase
      .from('flow_versions')
      .select('id, flow_id, version, name, change_summary, changed_by_user_id, created_at')
      .eq('flow_id', flow.id)
      .order('version', { ascending: false });
    if (error) throw error;
    res.json(data ?? []);
  } catch (error: any) {
    console.error('Error listing flow versions:', error);
    res.status(500).json({ error: error.message || 'Failed to list versions' });
  }
});

// POST /api/flows/:id/revert — { version: number } — copies that version's graph
// to a new version on top of HEAD.
router.post('/:id/revert', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const flow = await loadFlow(req.params.id);
    if (!flow) return res.status(404).json({ error: 'Flow not found' });
    if (!(await canManageFlow(flow.organization_id, userId, flow.flow_type))) {
      return res.status(403).json({ error: 'You do not have permission to manage this flow type' });
    }

    const { version } = req.body as { version?: unknown };
    if (typeof version !== 'number' || !Number.isInteger(version) || version < 1) {
      return res.status(400).json({ error: 'version must be a positive integer' });
    }

    const { data: target } = await supabase
      .from('flow_versions')
      .select('graph, name')
      .eq('flow_id', flow.id)
      .eq('version', version)
      .single();
    if (!target) return res.status(404).json({ error: 'Version not found' });

    const newVersion = flow.version + 1;
    const { data, error } = await supabase
      .from('flows')
      .update({
        graph: (target as { graph: FlowGraph }).graph,
        name: (target as { name: string }).name,
        version: newVersion,
        updated_at: new Date().toISOString(),
      })
      .eq('id', flow.id)
      .select('*')
      .single();
    if (error) throw error;

    await supabase.from('flow_versions').insert({
      flow_id: flow.id,
      version: newVersion,
      graph: (target as { graph: FlowGraph }).graph,
      name: (target as { name: string }).name,
      changed_by_user_id: userId,
      change_summary: `Reverted to version ${version}`,
    });

    res.json(data);
  } catch (error: any) {
    console.error('Error reverting flow:', error);
    res.status(500).json({ error: error.message || 'Failed to revert flow' });
  }
});

export default router;
