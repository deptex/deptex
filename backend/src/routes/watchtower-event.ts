import express from 'express';
import { isEeEdition } from '../lib/features';

const router = express.Router();

const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY?.trim();

function requireInternalKey(req: express.Request, res: express.Response, next: express.NextFunction) {
  const raw =
    (req.headers['x-internal-api-key'] as string) ||
    (req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.slice(7)
      : undefined);
  const key = raw?.trim();
  if (!INTERNAL_API_KEY || key !== INTERNAL_API_KEY) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
}

router.use(requireInternalKey);

/**
 * POST /api/internal/watchtower-event
 * Called by watchtower-worker (Fly.io) to emit notification events.
 * In EE mode, calls emitEvent() from the event bus.
 * In CE mode, this is a no-op that returns 200.
 */
router.post('/', async (req, res) => {
  try {
    const { event_type, organization_id, project_id, package_name, payload, priority } = req.body;

    if (!event_type || !organization_id || !package_name) {
      res.status(400).json({ error: 'Missing required fields: event_type, organization_id, package_name' });
      return;
    }

    if (isEeEdition()) {
      try {
        const { emitEvent } = require('../lib/event-bus');
        await emitEvent({
          event_type,
          organization_id,
          project_id: project_id || null,
          payload: {
            package_name,
            ...payload,
          },
          source: 'watchtower',
          priority: priority || 'normal',
        });
      } catch (err: any) {
        console.warn('[watchtower-event] Failed to emit event:', err?.message);
      }
    }

    res.json({ ok: true });
  } catch (error: any) {
    console.error('[watchtower-event] Error:', error);
    res.status(500).json({ error: error.message || 'Failed to process event' });
  }
});

export default router;
