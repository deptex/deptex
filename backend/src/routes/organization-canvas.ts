import express from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { checkRateLimit } from '../lib/rate-limit';

const router = express.Router();
router.use(authenticateUser);

const MAX_POSITION = 1_000_000;
const MAX_BATCH_ITEMS = 100;

function isFiniteNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

function validatePosition(body: unknown): { x: number; y: number } | null {
  if (!body || typeof body !== 'object') return null;
  const { canvas_position_x, canvas_position_y } = body as Record<string, unknown>;
  if (!isFiniteNumber(canvas_position_x) || !isFiniteNumber(canvas_position_y)) return null;
  if (Math.abs(canvas_position_x) > MAX_POSITION || Math.abs(canvas_position_y) > MAX_POSITION) return null;
  return { x: canvas_position_x, y: canvas_position_y };
}

type PermResult = { ok: boolean; status: number; message: string };

/**
 * Canvas write gate. Grants access when the user has owner/admin role on the
 * org, an org-level role carrying `manage_teams_and_projects`, or — for a
 * specific project — team-level `manage_projects` on the project's owning
 * team. Mirrors `checkProjectManagePermission` in lib/project-access.ts so that a
 * team lead can reposition their own team's projects on the org canvas.
 */
async function requireManagePermission(
  userId: string,
  organizationId: string,
  scope?: { kind: 'project'; projectId: string },
): Promise<PermResult> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .single();

  if (!membership) {
    return { ok: false, status: 404, message: 'Organization not found or access denied' };
  }

  if (membership.role === 'owner') {
    return { ok: true, status: 200, message: '' };
  }

  const { data: orgRole } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', organizationId)
    .eq('name', membership.role)
    .single();

  if (orgRole?.permissions?.manage_teams_and_projects === true) {
    return { ok: true, status: 200, message: '' };
  }

  if (scope?.kind === 'project') {
    const { data: projectTeams } = await supabase
      .from('project_teams')
      .select('is_owner, team_id')
      .eq('project_id', scope.projectId);

    const ownerEntry = projectTeams?.find((pt: { is_owner: boolean; team_id: string }) => pt.is_owner);
    const ownerTeamId = ownerEntry?.team_id;

    if (ownerTeamId) {
      const { data: teamMembership } = await supabase
        .from('team_members')
        .select('role')
        .eq('team_id', ownerTeamId)
        .eq('user_id', userId)
        .single();

      if (teamMembership) {
        const { data: teamRole } = await supabase
          .from('team_roles')
          .select('permissions')
          .eq('team_id', ownerTeamId)
          .eq('name', teamMembership.role)
          .single();

        if (teamRole?.permissions?.manage_projects === true) {
          return { ok: true, status: 200, message: '' };
        }
      }
    }
  }

  return { ok: false, status: 403, message: 'You do not have permission to move canvas nodes' };
}

/** Per-user rate limit on canvas write endpoints. Fail-open if Redis is down. */
async function checkCanvasRateLimit(userId: string, res: express.Response): Promise<boolean> {
  const result = await checkRateLimit(`canvas:${userId}`, 120, 60);
  if (!result.allowed) {
    res.status(429).json({
      error: 'Too many canvas updates. Please slow down.',
      retry_after_seconds: result.retryAfterSeconds,
    });
    return false;
  }
  return true;
}

// PATCH /api/organizations/:id/canvas/teams/:teamId/position
router.patch('/:id/canvas/teams/:teamId/position', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: organizationId, teamId } = req.params;

    if (!(await checkCanvasRateLimit(userId, res))) return;

    const position = validatePosition(req.body);
    if (!position) {
      return res.status(400).json({ error: 'canvas_position_x and canvas_position_y must be finite numbers' });
    }

    const perm = await requireManagePermission(userId, organizationId);
    if (!perm.ok) return res.status(perm.status).json({ error: perm.message });

    const { data: updated, error } = await supabase
      .from('teams')
      .update({
        canvas_position_x: position.x,
        canvas_position_y: position.y,
        canvas_position_updated_at: new Date().toISOString(),
        canvas_position_updated_by: userId,
      })
      .eq('id', teamId)
      .eq('organization_id', organizationId)
      .select('id, canvas_position_x, canvas_position_y, canvas_position_updated_at')
      .single();

    if (error || !updated) {
      return res.status(404).json({ error: 'Team not found in this organization' });
    }

    res.json(updated);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'unknown';
    console.error('[org-canvas] team position update failed', { organizationId: req.params.id, userId: req.user?.id, teamId: req.params.teamId, error: msg });
    res.status(500).json({ error: 'Failed to update team position' });
  }
});

// PATCH /api/organizations/:id/canvas/projects/:projectId/position
router.patch('/:id/canvas/projects/:projectId/position', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: organizationId, projectId } = req.params;

    if (!(await checkCanvasRateLimit(userId, res))) return;

    const position = validatePosition(req.body);
    if (!position) {
      return res.status(400).json({ error: 'canvas_position_x and canvas_position_y must be finite numbers' });
    }

    const perm = await requireManagePermission(userId, organizationId, { kind: 'project', projectId });
    if (!perm.ok) return res.status(perm.status).json({ error: perm.message });

    const { data: updated, error } = await supabase
      .from('projects')
      .update({
        canvas_position_x: position.x,
        canvas_position_y: position.y,
        canvas_position_updated_at: new Date().toISOString(),
        canvas_position_updated_by: userId,
      })
      .eq('id', projectId)
      .eq('organization_id', organizationId)
      .select('id, canvas_position_x, canvas_position_y, canvas_position_updated_at')
      .single();

    if (error || !updated) {
      return res.status(404).json({ error: 'Project not found in this organization' });
    }

    res.json(updated);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'unknown';
    console.error('[org-canvas] project position update failed', { organizationId: req.params.id, userId: req.user?.id, projectId: req.params.projectId, error: msg });
    res.status(500).json({ error: 'Failed to update project position' });
  }
});

// PATCH /api/organizations/:id/canvas/batch
// Body: { teams?: [{ id, canvas_position_x, canvas_position_y }], projects?: [...] }
// Used when dragging a team carries its child projects. Authorized by
// org-level manage permission (team drags are an org-admin concern). The
// update itself runs as a single Postgres transaction via an RPC — no
// partial writes on mid-batch failure.
router.patch('/:id/canvas/batch', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: organizationId } = req.params;

    if (!(await checkCanvasRateLimit(userId, res))) return;

    const body = req.body as { teams?: unknown; projects?: unknown };
    const rawTeams = Array.isArray(body?.teams) ? body.teams : [];
    const rawProjects = Array.isArray(body?.projects) ? body.projects : [];

    if (rawTeams.length === 0 && rawProjects.length === 0) {
      return res.status(400).json({ error: 'No updates provided' });
    }

    if (rawTeams.length + rawProjects.length > MAX_BATCH_ITEMS) {
      return res.status(400).json({ error: `Batch exceeds maximum of ${MAX_BATCH_ITEMS} items` });
    }

    type Item = { id: string; x: number; y: number };
    const parse = (raw: unknown[]): Item[] | null => {
      const out: Item[] = [];
      for (const r of raw) {
        if (!r || typeof r !== 'object') return null;
        const { id, canvas_position_x, canvas_position_y } = r as Record<string, unknown>;
        if (typeof id !== 'string' || !id) return null;
        if (!isFiniteNumber(canvas_position_x) || !isFiniteNumber(canvas_position_y)) return null;
        if (Math.abs(canvas_position_x) > MAX_POSITION || Math.abs(canvas_position_y) > MAX_POSITION) return null;
        out.push({ id, x: canvas_position_x, y: canvas_position_y });
      }
      return out;
    };

    const teams = parse(rawTeams);
    const projects = parse(rawProjects);
    if (!teams || !projects) {
      return res.status(400).json({ error: 'Invalid update payload' });
    }

    const perm = await requireManagePermission(userId, organizationId);
    if (!perm.ok) return res.status(perm.status).json({ error: perm.message });

    const { data, error } = await supabase.rpc('update_canvas_positions_batch', {
      _org_id: organizationId,
      _user_id: userId,
      _teams: teams.map((t) => ({ id: t.id, x: t.x, y: t.y })),
      _projects: projects.map((p) => ({ id: p.id, x: p.x, y: p.y })),
    });

    if (error) {
      // RPC raises P0001 when any id doesn't belong to the org — maps to 404.
      if (error.code === 'P0001' || /not found in this organization/i.test(error.message)) {
        return res.status(404).json({ error: error.message });
      }
      throw error;
    }

    res.json(data);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'unknown';
    console.error('[org-canvas] batch position update failed', { organizationId: req.params.id, userId: req.user?.id, error: msg });
    res.status(500).json({ error: 'Failed to update canvas positions' });
  }
});

export default router;
