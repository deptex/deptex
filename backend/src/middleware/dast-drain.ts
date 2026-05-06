import type express from 'express';

// Phase 24a drain mode — blocks new DAST scan submissions while a deploy is
// rolling out the v2.1a/b worker shim swap. Only the POST scan trigger is
// blocked; reads, target CRUD, and credential CRUD continue to pass through
// so the UI can still surface state and operators can clean up. See
// docs/runbooks/dast-v2-1a-deploy.md for the full deploy DAG.
//
// Lives in its own module so tests can import the named middleware without
// pulling in the whole app's load-time side effects (route registrations,
// supabase init, etc.). The dast-routes test asserts this exact function
// rejects POST /:projectId/dast/scan when INTERNAL_DAST_PAUSED=true — any
// regression to the path regex or method check fails the gate.

export const DAST_SCAN_DRAIN_PATH = /^\/[^/]+\/dast\/scan\/?$/;

export function dastDrainMiddleware(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  if (
    process.env.INTERNAL_DAST_PAUSED === 'true' &&
    req.method === 'POST' &&
    DAST_SCAN_DRAIN_PATH.test(req.path)
  ) {
    return res.status(503).json({ error: 'dast_queue_paused' });
  }
  next();
}
