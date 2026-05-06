// @ts-nocheck
/**
 * Phase 27 IaC + Container v2: project-scoped manually-configured images.
 *
 * Mounted under /api/organizations in src/index.ts. Routes:
 *   GET    /:id/projects/:projectId/configured-images
 *   POST   /:id/projects/:projectId/configured-images
 *   PATCH  /:id/projects/:projectId/configured-images/:imageId
 *   DELETE /:id/projects/:projectId/configured-images/:imageId
 *
 * The DB enforces same-org cred attachment via the composite FK
 *   (credentials_id, organization_id) → organization_registry_credentials(id, organization_id)
 * and re-derives organization_id on every UPDATE via the
 * enforce_project_scoped_org_id() trigger. The route layer pre-validates
 * the cred-org match so cross-org attachments fail with a 400 cred_wrong_org
 * instead of letting the FK trip a 500.
 *
 * 20-enabled-image cap per project keeps a single 90s extraction slot
 * inside CONTAINER_SCAN_TOTAL_BUDGET_MS (Patch 9).
 */

import express from 'express';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { checkProjectAccess, checkProjectManagePermission } from '../lib/project-access';
import { createActivity } from '../lib/activities';
import { validateImageRefHost } from '../lib/image-ref-guard';

const router = express.Router();
router.use(authenticateUser);

// docker-pullable shape, anchored. Allows tag refs (`repo:tag`) and digest
// pins (`repo@sha256:<64-hex>`). Empty / spaces / unsafe chars rejected.
// Length-capped to 512 (real OCI refs cap around 256) to keep the regex linear
// and the DB row bounded.
const IMAGE_REF_REGEX = /^[a-z0-9._\-/:]+(@sha256:[a-f0-9]{64})?$/;
const IMAGE_REF_MAX_LEN = 512;

const ENABLED_IMAGE_CAP = 20;

interface ConfiguredImageRow {
  id: string;
  project_id: string;
  organization_id: string;
  image_reference: string;
  credentials_id: string | null;
  enabled: boolean;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

interface ConfiguredImageResponse extends ConfiguredImageRow {
  credentials_display: { display_name: string; registry_type: string } | null;
}

async function attachCredDisplay(
  rows: ConfiguredImageRow[],
  organizationId: string,
): Promise<ConfiguredImageResponse[]> {
  const credIds = Array.from(
    new Set(rows.map((r) => r.credentials_id).filter((v): v is string => !!v)),
  );
  let credMap: Record<string, { display_name: string; registry_type: string }> = {};
  if (credIds.length > 0) {
    const { data: creds } = await supabase
      .from('organization_registry_credentials')
      .select('id, display_name, registry_type')
      .eq('organization_id', organizationId)
      .in('id', credIds);
    for (const c of creds ?? []) {
      credMap[c.id] = { display_name: c.display_name, registry_type: c.registry_type };
    }
  }
  return rows.map((r) => ({
    ...r,
    credentials_display: r.credentials_id ? credMap[r.credentials_id] ?? null : null,
  }));
}

/**
 * Confirm the cred row belongs to the same org. Returns 400 cred_wrong_org
 * if not — clean UX before the composite FK would trip a 500.
 */
async function validateCredOrgMatch(
  credId: string,
  organizationId: string,
): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  const { data: cred, error } = await supabase
    .from('organization_registry_credentials')
    .select('id, organization_id')
    .eq('id', credId)
    .single();
  if (error || !cred) {
    return { ok: false, status: 400, error: 'cred_not_found' };
  }
  if (cred.organization_id !== organizationId) {
    return { ok: false, status: 400, error: 'cred_wrong_org' };
  }
  return { ok: true };
}

// ============================================================================
// GET /:id/projects/:projectId/configured-images
// ============================================================================
router.get('/:id/projects/:projectId/configured-images', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId } = req.params;

    const access = await checkProjectAccess(userId, orgId, projectId);
    if (!access.hasAccess) {
      return res.status(access.error!.status).json({ error: access.error!.message });
    }

    const { data: rows, error } = await supabase
      .from('project_configured_images')
      .select('id, project_id, organization_id, image_reference, credentials_id, enabled, created_by, created_at, updated_at')
      .eq('project_id', projectId)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const enriched = await attachCredDisplay(rows ?? [], orgId);
    res.json(enriched);
  } catch (error: any) {
    console.error('Error listing configured images:', error);
    res.status(500).json({ error: 'configured_image_operation_failed' });
  }
});

// ============================================================================
// POST /:id/projects/:projectId/configured-images
// ============================================================================
router.post('/:id/projects/:projectId/configured-images', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId } = req.params;

    if (!(await checkProjectManagePermission(userId, orgId, projectId))) {
      return res.status(403).json({ error: 'You do not have permission to manage configured images' });
    }

    const { image_reference, credentials_id, enabled } = req.body ?? {};
    if (typeof image_reference !== 'string') {
      return res.status(400).json({ error: 'image_reference must be a string' });
    }
    const trimmedRef = image_reference.trim();
    if (trimmedRef.length === 0 || trimmedRef.length > IMAGE_REF_MAX_LEN) {
      return res.status(400).json({ error: 'image_reference must be 1-512 chars' });
    }
    if (!IMAGE_REF_REGEX.test(trimmedRef)) {
      return res.status(400).json({ error: 'image_reference must match docker-pullable shape' });
    }
    const refGuard = await validateImageRefHost(trimmedRef);
    if (!refGuard.valid) {
      return res.status(400).json({ error: 'image_reference_host_blocked', reason: refGuard.reason });
    }
    if (credentials_id !== undefined && credentials_id !== null && typeof credentials_id !== 'string') {
      return res.status(400).json({ error: 'credentials_id must be a string or null' });
    }
    if (enabled !== undefined && typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'enabled must be a boolean' });
    }

    if (credentials_id) {
      const credCheck = await validateCredOrgMatch(credentials_id, orgId);
      if (!credCheck.ok) {
        return res.status(credCheck.status).json({ error: credCheck.error });
      }
    }

    const willEnable = enabled !== false;  // undefined → defaults to true

    // Atomic cap-and-insert via RPC. The function does the count + INSERT
    // inside a single transaction with row-level locking on a sentinel,
    // closing the JS-only TOCTOU window where two parallel POSTs both observe
    // count<20 and both insert.
    const { data: inserted, error: insertErr } = await supabase.rpc('insert_configured_image_with_cap', {
      p_project_id: projectId,
      p_organization_id: orgId,
      p_image_reference: trimmedRef,
      p_credentials_id: credentials_id ?? null,
      p_enabled: willEnable,
      p_created_by: userId,
      p_cap: ENABLED_IMAGE_CAP,
    });
    if (insertErr) {
      if (insertErr.message?.includes('image_cap_reached')) {
        return res.status(400).json({
          error: 'image_cap_reached',
          message: `Project limit of ${ENABLED_IMAGE_CAP} enabled configured images reached. Disable or delete entries before adding more.`,
        });
      }
      throw insertErr;
    }
    const data = Array.isArray(inserted) ? inserted[0] : inserted;
    if (!data) throw new Error('insert_configured_image_with_cap returned no row');

    const [enriched] = await attachCredDisplay([data], orgId);

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'configured_image_created',
      description: `added configured image "${data.image_reference}"`,
      metadata: { configured_image_id: data.id, project_id: projectId, credentials_id: data.credentials_id },
    });

    res.status(201).json(enriched);
  } catch (error: any) {
    console.error('Error creating configured image:', error);
    res.status(500).json({ error: 'configured_image_operation_failed' });
  }
});

// ============================================================================
// PATCH /:id/projects/:projectId/configured-images/:imageId
// ============================================================================
router.patch('/:id/projects/:projectId/configured-images/:imageId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId, imageId } = req.params;

    if (!(await checkProjectManagePermission(userId, orgId, projectId))) {
      return res.status(403).json({ error: 'You do not have permission to manage configured images' });
    }

    const body = req.body ?? {};
    const allowed = new Set(['enabled', 'credentials_id']);
    const unknown = Object.keys(body).find((k) => !allowed.has(k));
    if (unknown) {
      return res.status(400).json({ error: 'unknown_field', field: unknown });
    }

    const updates: Record<string, unknown> = {};
    if ('enabled' in body) {
      if (typeof body.enabled !== 'boolean') {
        return res.status(400).json({ error: 'enabled must be a boolean' });
      }
      updates.enabled = body.enabled;
    }
    if ('credentials_id' in body) {
      if (body.credentials_id !== null && typeof body.credentials_id !== 'string') {
        return res.status(400).json({ error: 'credentials_id must be a string or null' });
      }
      updates.credentials_id = body.credentials_id;
    }
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    if (typeof updates.credentials_id === 'string') {
      const credCheck = await validateCredOrgMatch(updates.credentials_id, orgId);
      if (!credCheck.ok) {
        return res.status(credCheck.status).json({ error: credCheck.error });
      }
    }

    // Atomic update via RPC: same cap-recheck-then-update transaction that
    // POST uses, but only when the patch is flipping enabled=true.
    const { data: updated, error: updateErr } = await supabase.rpc('update_configured_image_with_cap', {
      p_image_id: imageId,
      p_project_id: projectId,
      p_organization_id: orgId,
      p_enabled: 'enabled' in updates ? (updates.enabled as boolean) : null,
      p_credentials_id_set: 'credentials_id' in updates,
      p_credentials_id: 'credentials_id' in updates ? (updates.credentials_id as string | null) : null,
      p_cap: ENABLED_IMAGE_CAP,
    });
    if (updateErr) {
      if (updateErr.message?.includes('image_cap_reached')) {
        return res.status(400).json({
          error: 'image_cap_reached',
          message: `Project limit of ${ENABLED_IMAGE_CAP} enabled configured images reached.`,
        });
      }
      throw updateErr;
    }
    const data = Array.isArray(updated) ? updated[0] : updated;
    if (!data) return res.status(404).json({ error: 'Configured image not found' });

    const [enriched] = await attachCredDisplay([data], orgId);

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'configured_image_updated',
      description: `updated configured image "${data.image_reference}"`,
      metadata: { configured_image_id: imageId, project_id: projectId, changed: Object.keys(updates) },
    });

    res.json(enriched);
  } catch (error: any) {
    console.error('Error updating configured image:', error);
    res.status(500).json({ error: 'configured_image_operation_failed' });
  }
});

// ============================================================================
// DELETE /:id/projects/:projectId/configured-images/:imageId
// ============================================================================
router.delete('/:id/projects/:projectId/configured-images/:imageId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId, imageId } = req.params;

    if (!(await checkProjectManagePermission(userId, orgId, projectId))) {
      return res.status(403).json({ error: 'You do not have permission to manage configured images' });
    }

    const { data: existing, error: fetchErr } = await supabase
      .from('project_configured_images')
      .select('id, image_reference')
      .eq('id', imageId)
      .eq('project_id', projectId)
      .single();
    if (fetchErr || !existing) {
      return res.status(404).json({ error: 'Configured image not found' });
    }

    const { error } = await supabase
      .from('project_configured_images')
      .delete()
      .eq('id', imageId)
      .eq('project_id', projectId);

    if (error) throw error;

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'configured_image_deleted',
      description: `deleted configured image "${existing.image_reference}"`,
      metadata: { configured_image_id: imageId, project_id: projectId },
    });

    res.json({ message: 'Configured image deleted' });
  } catch (error: any) {
    console.error('Error deleting configured image:', error);
    res.status(500).json({ error: 'configured_image_operation_failed' });
  }
});

export default router;
