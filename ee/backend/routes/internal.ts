import express from 'express';
import { createBumpPrForProject } from '../lib/create-bump-pr';

const router = express.Router();

const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY?.trim();

function requireInternalKey(req: express.Request, res: express.Response, next: express.NextFunction) {
  const raw = req.headers['x-internal-api-key'] as string || (req.headers.authorization && req.headers.authorization.startsWith('Bearer ') ? req.headers.authorization.slice(7) : undefined);
  const key = raw?.trim();
  if (!INTERNAL_API_KEY || key !== INTERNAL_API_KEY) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
}

router.use(requireInternalKey);

/**
 * POST /api/internal/watchtower/create-bump-pr
 * Body: { organization_id, project_id, name, target_version [, current_version ] }
 * Used by the auto-bump worker to create bump PRs.
 */
router.post('/watchtower/create-bump-pr', async (req, res) => {
  try {
    const { organization_id, project_id, name, target_version, current_version } = req.body;
    if (!organization_id || !project_id || !name || !target_version) {
      res.status(400).json({ error: 'Missing organization_id, project_id, name, or target_version' });
      return;
    }
    const result = await createBumpPrForProject(
      organization_id,
      project_id,
      name,
      target_version,
      current_version
    );
    if ('error' in result) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.json({ pr_url: result.pr_url, pr_number: result.pr_number });
  } catch (error: any) {
    console.error('Error creating bump PR (internal):', error);
    res.status(500).json({ error: error.message || 'Failed to create bump PR' });
  }
});

export default router;
