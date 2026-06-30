import express from 'express';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { userHasOrgPermission } from '../lib/permissions';
import {
  acceptTask,
  declineTask,
  ensureTaskThread,
  findOpenTaskForFinding,
  getTask,
  listTasks,
  proposeTaskFromFinding,
} from '../lib/aegis-v3/tasks';
import { runTaskAgent } from '../lib/aegis-v3/task-runner';
import { isQStashConfigured, queueTaskRun } from '../lib/qstash';
import { AEGIS_TASK_FINDING_TYPES, type AegisTaskFindingType } from '../lib/aegis-v3/task-types';

const router = express.Router();
router.use(authenticateUser);

// Map the lib's thrown messages onto HTTP status codes.
function statusForError(message: string): number {
  if (message === 'Task not found' || message === 'Task not in current organization') return 404;
  if (message.includes('cannot be accepted') || message.includes('cannot be declined')) return 409;
  return 500;
}

/**
 * Send-to-Aegis: create a task from a fixable finding. Returns {taskId, threadId}
 * for a confirm-in-task-chat (consistent consent — the task is created in
 * `proposed` state; the user accepts in the task-chat). Dedups to an existing
 * open task for the same finding.
 */
router.post('/', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { organizationId, projectId, findingType, findingKey, osvId, findingHandle, label } = req.body ?? {};

  if (!organizationId || !projectId || !findingType || !findingKey) {
    return res
      .status(400)
      .json({ error: 'organizationId, projectId, findingType, and findingKey are required' });
  }
  if (!AEGIS_TASK_FINDING_TYPES.includes(findingType)) {
    return res
      .status(400)
      .json({ error: `findingType must be one of ${AEGIS_TASK_FINDING_TYPES.join(', ')}` });
  }
  // semgrep/secret need the location handle (their finding_key is per-rule).
  if ((findingType === 'semgrep' || findingType === 'secret') && !findingHandle) {
    return res.status(400).json({ error: 'findingHandle (file:line) is required for semgrep/secret findings' });
  }
  if (!(await userHasOrgPermission(userId, organizationId, 'trigger_fix'))) {
    return res.status(403).json({ error: 'You do not have permission to trigger fixes' });
  }

  try {
    const handle = typeof findingHandle === 'string' ? findingHandle : undefined;
    const existing = await findOpenTaskForFinding({
      orgId: organizationId,
      projectId,
      findingType,
      findingKey,
      findingHandle: handle,
    });
    if (existing) {
      return res.status(200).json({ taskId: existing.taskId, threadId: existing.threadId, deduped: true });
    }

    const targetLabel = (typeof label === 'string' && label.trim()) || String(findingKey);
    const { taskId, threadId } = await proposeTaskFromFinding({
      orgId: organizationId,
      projectId,
      createdBy: userId,
      description: `Fix ${targetLabel}`,
      target: {
        findingType: findingType as AegisTaskFindingType,
        findingKey,
        osvId: typeof osvId === 'string' ? osvId : undefined,
        findingHandle: handle,
        projectId,
        label: targetLabel,
      },
    });
    return res.status(201).json({ taskId, threadId });
  } catch (err: any) {
    const message = err?.message ?? 'Failed to create task';
    return res.status(statusForError(message)).json({ error: message });
  }
});

/** The sidebar pile, newest first. Tenant-scoped by organizationId. */
router.get('/', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const organizationId = (req.query.organizationId as string | undefined) ?? '';
  if (!organizationId) return res.status(400).json({ error: 'organizationId is required' });
  if (!(await userHasOrgPermission(userId, organizationId, 'interact_with_aegis'))) {
    return res.status(403).json({ error: 'You do not have permission to view Aegis' });
  }
  const limit = req.query.limit ? Number(req.query.limit) : undefined;
  const offset = req.query.offset ? Number(req.query.offset) : undefined;
  try {
    const tasks = await listTasks(organizationId, { limit, offset });
    return res.json({ tasks });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message ?? 'Failed to list tasks' });
  }
});

/** A single task. Asserts the task belongs to a caller org. */
router.get('/:taskId', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const organizationId = (req.query.organizationId as string | undefined) ?? '';
  if (!organizationId) return res.status(400).json({ error: 'organizationId is required' });
  if (!(await userHasOrgPermission(userId, organizationId, 'interact_with_aegis'))) {
    return res.status(403).json({ error: 'You do not have permission to view Aegis' });
  }
  const task = await getTask(req.params.taskId, organizationId);
  if (!task) return res.status(404).json({ error: 'Task not found' });
  return res.json({ task });
});

/** Accept a proposed task — authorizes the whole fix job. */
router.patch('/:taskId/accept', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { organizationId } = req.body ?? {};
  if (!organizationId) return res.status(400).json({ error: 'organizationId is required' });
  if (!(await userHasOrgPermission(userId, organizationId, 'trigger_fix'))) {
    return res.status(403).json({ error: 'You do not have permission to trigger fixes' });
  }
  try {
    const { threadId } = await acceptTask({ taskId: req.params.taskId, userId, organizationId });
    return res.json({ threadId });
  } catch (err: any) {
    const message = err?.message ?? 'Failed to accept task';
    return res.status(statusForError(message)).json({ error: message });
  }
});

/**
 * Run the task agent loop. Ensures the task's chat thread, returns its id
 * immediately, then drives the agent so the caller can navigate to the thread
 * and watch narration land live.
 *
 * The loop runs for ~1–2 minutes (investigate → apply_fix → the fix pipeline
 * narrates its own steps). When a job backend is configured it's dispatched
 * durably (it runs inside the delivered worker request, which a serverless host
 * won't kill); locally — where the backend is a persistent process and QStash
 * can't reach it anyway — it runs in-process.
 */
router.post('/:taskId/run', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const organizationId = (req.body?.organizationId as string | undefined) ?? '';
  if (!organizationId) return res.status(400).json({ error: 'organizationId is required' });
  if (!(await userHasOrgPermission(userId, organizationId, 'trigger_fix'))) {
    return res.status(403).json({ error: 'You do not have permission to run tasks' });
  }
  const task = await getTask(req.params.taskId, organizationId);
  if (!task) return res.status(404).json({ error: 'Task not found' });

  try {
    // Create the thread up front so we can hand the caller a destination to
    // watch before the (slow) loop runs.
    const threadId = await ensureTaskThread(req.params.taskId);
    res.json({ threadId });

    if (isQStashConfigured()) {
      await queueTaskRun(req.params.taskId);
    } else {
      // Local dev: persistent process, no reachable job backend — run inline.
      void runTaskAgent(req.params.taskId).catch((e: any) =>
        console.error('[aegis-tasks] runTaskAgent failed', req.params.taskId, e?.message),
      );
    }
  } catch (err: any) {
    // The response is already sent in the happy path; only the pre-response
    // ensureTaskThread can land here.
    if (!res.headersSent) {
      const message = err?.message ?? 'Failed to run task';
      return res.status(statusForError(message)).json({ error: message });
    }
    console.error('[aegis-tasks] dispatch failed', req.params.taskId, err?.message);
  }
});

/** Decline a proposed task. */
router.patch('/:taskId/decline', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { organizationId } = req.body ?? {};
  if (!organizationId) return res.status(400).json({ error: 'organizationId is required' });
  if (!(await userHasOrgPermission(userId, organizationId, 'trigger_fix'))) {
    return res.status(403).json({ error: 'You do not have permission to trigger fixes' });
  }
  try {
    await declineTask({ taskId: req.params.taskId, userId, organizationId });
    return res.json({ success: true });
  } catch (err: any) {
    const message = err?.message ?? 'Failed to decline task';
    return res.status(statusForError(message)).json({ error: message });
  }
});

export default router;
