/**
 * Base-image recommendation endpoints (Phase 2, Item J).
 *
 * URL convention follows the security-tab / scanner-findings pattern:
 *   /api/organizations/:id/projects/:projectId/base-image-recommendations
 *
 * Endpoints:
 *   - GET  .../base-image-recommendations              list active cards
 *   - POST .../base-image-recommendations/:recId/dismiss   dismiss a card
 *   - POST .../base-image-suggestions                  log a catalog request
 *
 * Tenant isolation: the GET path is gated by checkProjectAccess (which itself
 * rejects an (orgA, projectB) param-tampering pair). The dismiss path loads
 * the row first, then walks an explicit four-step guard — assertProjectInOrg,
 * URL-projectId match, then the checkProjectManagePermission RBAC check — so
 * a recommendation id from another tenant can never be dismissed. The suggest
 * path mirrors the same manage-permission gate (it is a mutation that writes
 * an activity-log row).
 */

import express from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import {
  checkProjectAccess,
  assertProjectInOrg,
  checkProjectManagePermission,
} from '../lib/project-access';
import { getActiveExtractionId } from '../lib/active-extraction';
import { createActivity } from '../lib/activities';
import { buildBaseImageRecommendationsUnchecked } from '../lib/project-findings';

const router = express.Router();
router.use(authenticateUser);

const SUGGEST_IMAGE_MAX_LEN = 512;

interface RecommendationRow {
  id: string;
  dockerfile_path: string;
  current_image: string;
  current_image_digest: string | null;
  current_image_cve_count: number | null;
  recommended_image: string | null;
  recommended_image_cve_count: number | null;
  cve_delta: number | null;
  alternatives: unknown;
  shell_compat_verdict: string;
  shell_compat_evidence: unknown;
  drop_in_score: number;
  is_dismissed: boolean;
  created_at: string;
}

// Exported so the project findings-bundle builder
// (lib/project-findings.ts) selects the exact same column set the standalone
// GET endpoint returns — single source of truth, no shaping drift.
export const RECOMMENDATION_COLUMNS =
  'id, dockerfile_path, current_image, current_image_digest, current_image_cve_count, ' +
  'recommended_image, recommended_image_cve_count, cve_delta, alternatives, ' +
  'shell_compat_verdict, shell_compat_evidence, drop_in_score, is_dismissed, created_at';

// ============================================================
// GET — active recommendations for the project's latest run
// ============================================================

router.get(
  '/:id/projects/:projectId/base-image-recommendations',
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user!.id;
      const { id, projectId } = req.params;

      const access = await checkProjectAccess(userId, id, projectId);
      if (!access.hasAccess) {
        return res.status(access.error!.status).json({ error: access.error!.message });
      }

      // "Active" = the latest extraction run; older runs' rows are superseded.
      // The query (RECOMMENDATION_COLUMNS + ordering) lives in
      // lib/project-findings.ts so the findings-bundle slice is byte-identical.
      const activeRunId = await getActiveExtractionId(supabase, projectId);
      res.json(await buildBaseImageRecommendationsUnchecked(id, projectId, activeRunId));
    } catch (error: any) {
      console.error('[base-image-recommendations] list error:', error);
      res.status(500).json({ error: 'Failed to fetch base-image recommendations' });
    }
  }
);

// ============================================================
// POST — dismiss a recommendation
// ============================================================

router.post(
  '/:id/projects/:projectId/base-image-recommendations/:recId/dismiss',
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user!.id;
      const { id, projectId, recId } = req.params;

      // (1) Load the row by id alone — tenancy is verified in steps 2-4.
      const { data: row, error: loadError } = await supabase
        .from('project_base_image_recommendations')
        .select('id, project_id, dockerfile_path, recommended_image')
        .eq('id', recId)
        .maybeSingle();
      if (loadError) throw loadError;
      if (!row) {
        return res.status(404).json({ error: 'Recommendation not found' });
      }

      // (2) The row's project must live under the URL's organization.
      const inOrg = await assertProjectInOrg(row.project_id, id);
      if (!inOrg.valid) {
        return res.status(404).json({ error: 'Recommendation not found' });
      }

      // (3) The URL's projectId must be the row's project — closes the
      //     (orgA, projectA, recId-from-projectB) tampering surface.
      if (row.project_id !== projectId) {
        return res.status(404).json({ error: 'Recommendation not found' });
      }

      // (4) RBAC — dismissing a recommendation requires project-manage
      // permission (matches the sibling scanner-findings ignore/risk-accept
      // routes; the previous manage_integrations check was the registry-
      // secrets permission, which is unrelated to per-finding state).
      if (!(await checkProjectManagePermission(userId, id, projectId))) {
        return res
          .status(403)
          .json({ error: 'No permission to dismiss base-image recommendations' });
      }

      const { error: updateError } = await supabase
        .from('project_base_image_recommendations')
        .update({
          is_dismissed: true,
          dismissed_by: userId,
          dismissed_at: new Date().toISOString(),
        })
        .eq('id', recId);
      if (updateError) throw updateError;

      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'base_image_recommendation_dismissed',
        description: `Dismissed base-image recommendation for ${row.dockerfile_path}`,
        metadata: {
          recommendation_id: recId,
          project_id: projectId,
          dockerfile_path: row.dockerfile_path,
          recommended_image: row.recommended_image,
        },
      });

      res.json({ ok: true });
    } catch (error: any) {
      console.error('[base-image-recommendations] dismiss error:', error);
      res.status(500).json({ error: 'Failed to dismiss recommendation' });
    }
  }
);

// ============================================================
// POST — log a catalog-suggestion request (empty-state CTA)
// ============================================================

router.post(
  '/:id/projects/:projectId/base-image-suggestions',
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user!.id;
      const { id, projectId } = req.params;

      const access = await checkProjectAccess(userId, id, projectId);
      if (!access.hasAccess) {
        return res.status(access.error!.status).json({ error: access.error!.message });
      }
      // base-image-suggestions writes an activity-log row — gate it with the
      // same project-manage permission as dismiss so view-only members can't
      // mutate the security tab's state.
      if (!(await checkProjectManagePermission(userId, id, projectId))) {
        return res
          .status(403)
          .json({ error: 'No permission to manage base-image recommendations' });
      }

      const sourceImage = String((req.body ?? {}).source_image ?? '').trim();
      if (!sourceImage || sourceImage.length > SUGGEST_IMAGE_MAX_LEN) {
        return res.status(400).json({ error: 'A valid source_image is required' });
      }

      // No suggestions table — the request is an activity-log row the Slack
      // notifier can surface to the internal feedback channel.
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'base_image_suggestion_logged',
        description: `Requested a hardened base-image alternative for ${sourceImage}`,
        metadata: { source_image: sourceImage, project_id: projectId },
      });

      res.json({ ok: true });
    } catch (error: any) {
      console.error('[base-image-recommendations] suggest error:', error);
      res.status(500).json({ error: 'Failed to log suggestion' });
    }
  }
);

export default router;
