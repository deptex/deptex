/**
 * 8J: Bitbucket Webhook Handler
 * Handles repo:push and pullrequest:* events from Bitbucket.
 */

// @ts-nocheck
import express from 'express';
import * as crypto from 'crypto';
import { supabase } from '../lib/supabase';
import { queueExtractionJob } from '../lib/extraction-jobs';
import { invalidateProjectCaches } from '../lib/cache';
import { detectAffectedWorkspaces, isFileInWorkspace } from '../lib/manifest-registry';
import { checkRateLimit } from '../lib/rate-limit';

const router = express.Router();

const MAX_EXTRACTION_PER_PUSH = 10;

async function verifyBitbucketSignatureForRepo(req: express.Request, repoFullName: string): Promise<boolean> {
  const signature = req.headers['x-hub-signature'] as string | undefined;
  const rawBody = (req as any).rawBody;

  if (typeof rawBody !== 'string') return false;
  if (!signature) {
    if (process.env.NODE_ENV === 'production') return false;
    return true;
  }

  const { data, error } = await supabase
    .from('project_repositories')
    .select('webhook_secret')
    .eq('repo_full_name', repoFullName)
    .eq('provider', 'bitbucket');

  // If the lookup itself errored we cannot verify — fail closed.
  if (error) return false;

  // No matching repo OR no configured secret on any matching row =>
  // no trust anchor exists, so we MUST reject. Previously this path
  // returned true, which let an attacker skip verification by pointing
  // at a repo we don't track.
  const rows = data ?? [];
  if (rows.length === 0) return false;
  const rowsWithSecret = rows.filter((r: any) => !!r.webhook_secret);
  if (rowsWithSecret.length === 0) return false;

  for (const row of rowsWithSecret) {
    const expected = 'sha256=' + crypto.createHmac('sha256', row.webhook_secret).update(rawBody).digest('hex');
    const sigBuf = Buffer.from(signature, 'utf8');
    const expBuf = Buffer.from(expected, 'utf8');
    if (sigBuf.length !== expBuf.length) continue;
    try {
      if (crypto.timingSafeEqual(sigBuf, expBuf)) return true;
    } catch { /* length mismatch → not equal */ }
  }

  return false;
}

async function deduplicateDelivery(deliveryId: string | undefined): Promise<boolean> {
  if (!deliveryId) return false;
  try {
    const { Redis } = await import('@upstash/redis');
    const redis = new Redis({
      url: process.env.UPSTASH_REDIS_URL!,
      token: process.env.UPSTASH_REDIS_TOKEN!,
    });
    const key = `webhook-delivery:${deliveryId}`;
    const existing = await redis.get(key);
    if (existing) return true;
    await redis.set(key, '1', { ex: 3600 });
    return false;
  } catch {
    return false;
  }
}

async function recordWebhookDelivery(
  deliveryId: string | undefined,
  eventType: string,
  action: string | undefined,
  repoFullName: string | null,
  payloadSize: number,
  status: string = 'received'
) {
  // See backend/src/routes/integrations.ts:recordWebhookDelivery for the
  // rationale: collapsing missing-header deliveries onto the literal
  // 'unknown' silently breaks dedup once the UNIQUE (delivery_id, provider)
  // index is in place. Synthetic UUID + warning preserves the audit row.
  let resolvedDeliveryId = deliveryId;
  if (!resolvedDeliveryId) {
    resolvedDeliveryId = crypto.randomUUID();
    console.warn(
      `[bitbucket webhook] missing x-request-uuid header; assigned synthetic id ${resolvedDeliveryId}`
    );
  }
  try {
    await supabase.from('webhook_deliveries').insert({
      delivery_id: resolvedDeliveryId,
      provider: 'bitbucket',
      event_type: eventType,
      action,
      repo_full_name: repoFullName,
      processing_status: status,
      payload_size_bytes: payloadSize,
    });
  } catch {}
}

async function getBitbucketOAuthToken(repoFullName: string): Promise<string | null> {
  const { data: repos } = await supabase
    .from('project_repositories')
    .select('project_id, projects(organization_id)')
    .eq('repo_full_name', repoFullName)
    .eq('provider', 'bitbucket')
    .limit(1);

  if (!repos?.length) return null;
  const orgId = Array.isArray((repos[0] as any).projects)
    ? (repos[0] as any).projects[0]?.organization_id
    : (repos[0] as any).projects?.organization_id;
  if (!orgId) return null;

  const { data: integration } = await supabase
    .from('organization_integrations')
    .select('access_token')
    .eq('organization_id', orgId)
    .eq('provider', 'bitbucket')
    .single();

  return integration?.access_token ?? null;
}

async function getBitbucketChangedFiles(
  accessToken: string,
  workspace: string,
  repoSlug: string,
  spec: string
): Promise<string[]> {
  try {
    const res = await fetch(
      `https://api.bitbucket.org/2.0/repositories/${workspace}/${repoSlug}/diffstat/${spec}`,
      { headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'Deptex-App' } }
    );
    if (!res.ok) return [];
    const data = (await res.json()) as { values?: Array<{ new?: { path: string }; old?: { path: string } }> };
    const files = new Set<string>();
    for (const d of data.values ?? []) {
      if (d.new?.path) files.add(d.new.path);
      if (d.old?.path) files.add(d.old.path);
    }
    return Array.from(files);
  } catch {
    return [];
  }
}
async function handleBitbucketPushEvent(payload: any): Promise<void> {
  const repoFullName = payload?.repository?.full_name;
  if (!repoFullName) return;

  const changes = payload?.push?.changes ?? [];
  if (changes.length === 0) return;

  const { data: rows } = await supabase
    .from('project_repositories')
    .select('project_id, repo_full_name, default_branch, package_json_path, scan_on_commit, sync_frequency, status, integration_id, ecosystem, projects(organization_id)')
    .eq('repo_full_name', repoFullName)
    .eq('provider', 'bitbucket');

  if (!rows?.length) return;

  for (const change of changes) {
    const branchName = change?.new?.name;
    if (!branchName) continue;
    if (change?.new?.type !== 'branch') continue;

    const projects = (rows as any[]).filter(r => r.default_branch === branchName);
    if (projects.length === 0) continue;

    const before = change?.old?.target?.hash;
    const after = change?.new?.target?.hash;
    if (!after) continue;

    const accessToken = await getBitbucketOAuthToken(repoFullName);
    let changedFiles: string[] = [];

    if (accessToken && before) {
      const [ws, slug] = repoFullName.split('/');
      changedFiles = await getBitbucketChangedFiles(accessToken, ws, slug, `${before}..${after}`);
    }

    const affectedWorkspaces = detectAffectedWorkspaces(changedFiles);
    const forceFullExtraction = changedFiles.length === 0;
    let extractionCount = 0;

    for (const row of projects) {
      const activeStatuses = ['pending', 'initializing', 'ready', 'error', 'cancelled'];
      if (!activeStatuses.includes(row.status)) continue;

      const orgId = Array.isArray(row.projects) ? row.projects[0]?.organization_id : row.projects?.organization_id;
      if (!orgId) continue;

      const workspace = (row.package_json_path ?? '').trim();
      const rootChanged = affectedWorkspaces.has('');
      const workspaceChanged = affectedWorkspaces.has(workspace);
      const isAffected = forceFullExtraction || workspaceChanged || (rootChanged && workspace !== '');

      if (isAffected && row.scan_on_commit && extractionCount < MAX_EXTRACTION_PER_PUSH) {
        try {
          const commitInfo = change?.new?.target;
          const meta = {
            trigger_type: 'webhook' as const,
            commit_sha: commitInfo?.hash ?? after,
            commit_message: commitInfo?.message ? (commitInfo.message as string).slice(0, 500) : undefined,
            branch: branchName,
            commit_author: commitInfo?.author
              ? {
                  username: commitInfo.author.raw?.split('<')[0]?.trim() ?? commitInfo.author.user?.display_name,
                  avatar_url: commitInfo.author.user?.links?.avatar?.href,
                }
              : undefined,
          };
          const repoRecord = {
            repo_full_name: row.repo_full_name ?? repoFullName,
            installation_id: '',
            default_branch: row.default_branch,
            package_json_path: row.package_json_path ?? '',
            ecosystem: row.ecosystem ?? 'npm',
            provider: 'bitbucket',
            integration_id: row.integration_id ?? undefined,
          };
          const result = await queueExtractionJob(row.project_id, orgId, repoRecord, meta);
          if (result.success) extractionCount++;
        } catch (err: any) {
          console.error(`[bitbucket-webhook] Extraction queue failed:`, err?.message);
        }
      }

      const commitInfo = change?.new?.target;
      if (commitInfo?.hash) {
        await supabase.from('project_commits').upsert({
          project_id: row.project_id,
          sha: commitInfo.hash,
          message: (commitInfo.message || '').slice(0, 10000),
          author_name: commitInfo.author?.raw?.split('<')[0]?.trim(),
          author_email: commitInfo.author?.raw?.match(/<(.+)>/)?.[1],
          committed_at: commitInfo.date,
          manifest_changed: isAffected,
          extraction_triggered: isAffected && row.scan_on_commit,
          provider: 'bitbucket',
          provider_url: commitInfo.links?.html?.href,
        }, { onConflict: 'project_id,sha' }).then(() => {}, () => {});
      }

      await supabase.from('project_repositories').update({
        last_webhook_at: new Date().toISOString(),
        last_webhook_event: 'push',
        webhook_status: 'active',
      }).eq('project_id', row.project_id).eq('provider', 'bitbucket');

      await invalidateProjectCaches(orgId, row.project_id).catch(() => {});
    }
  }
}

async function handleBitbucketPullRequestEvent(payload: any, action: string): Promise<void> {
  const repoFullName = payload?.repository?.full_name;
  const pr = payload?.pullrequest;
  if (!repoFullName || !pr) return;

  const prId = pr.id;
  const targetBranch = pr.destination?.branch?.name;
  const sourceBranch = pr.source?.branch?.name;
  const headSha = pr.source?.commit?.hash;

  const { data: projectRows } = await supabase
    .from('project_repositories')
    .select('project_id, default_branch, package_json_path, pull_request_comments_enabled, projects(name, organization_id)')
    .eq('repo_full_name', repoFullName)
    .eq('provider', 'bitbucket');

  if (!projectRows?.length) return;

  const matchingProjects = (projectRows as any[]).filter(r => r.default_branch === targetBranch);
  if (matchingProjects.length === 0) return;

  if (action === 'fulfilled') {
    for (const row of matchingProjects) {
      await supabase.from('project_pull_requests').upsert({
        project_id: row.project_id,
        pr_number: prId,
        title: pr.title,
        author_login: pr.author?.display_name || pr.author?.username,
        author_avatar_url: pr.author?.links?.avatar?.href,
        status: 'merged',
        provider: 'bitbucket',
        provider_url: pr.links?.html?.href,
        base_branch: targetBranch,
        head_branch: sourceBranch,
        head_sha: headSha,
        merged_at: pr.updated_on || new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }, { onConflict: 'project_id,pr_number,provider' });

      await supabase.from('project_security_fixes')
        .update({ status: 'merged', completed_at: new Date().toISOString() })
        .eq('project_id', row.project_id)
        .eq('pr_number', prId)
        .eq('pr_provider', 'bitbucket')
        .in('status', ['completed']);

      try {
        const { updateOutcomeOnMerge } = await import('../lib/learning/outcome-recorder');
        await updateOutcomeOnMerge(row.project_id, prId, 'bitbucket', true, pr.updated_on);
      } catch { /* non-fatal */ }
    }
    return;
  }

  if (action === 'rejected') {
    for (const row of matchingProjects) {
      await supabase.from('project_pull_requests').upsert({
        project_id: row.project_id,
        pr_number: prId,
        title: pr.title,
        author_login: pr.author?.display_name || pr.author?.username,
        status: 'closed',
        provider: 'bitbucket',
        provider_url: pr.links?.html?.href,
        base_branch: targetBranch,
        head_branch: sourceBranch,
        head_sha: headSha,
        closed_at: pr.updated_on || new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }, { onConflict: 'project_id,pr_number,provider' });

      await supabase.from('project_security_fixes')
        .update({ status: 'pr_closed', completed_at: new Date().toISOString() })
        .eq('project_id', row.project_id)
        .eq('pr_number', prId)
        .eq('pr_provider', 'bitbucket')
        .in('status', ['completed']);

      try {
        const { updateOutcomeOnMerge } = await import('../lib/learning/outcome-recorder');
        await updateOutcomeOnMerge(row.project_id, prId, 'bitbucket', false);
      } catch { /* non-fatal */ }
    }
    return;
  }
}

router.post('/webhooks/bitbucket', async (req: express.Request, res: express.Response) => {
  try {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const rl = await checkRateLimit(`webhook:bitbucket:${ip}`, 100, 60);
    if (!rl.allowed) {
      return res.status(429).json({ error: 'Rate limit exceeded' });
    }

    const eventKey = req.headers['x-event-key'] as string || 'unknown';
    const repoFullName = req.body?.repository?.full_name;

    // Reject any payload without a repo identifier — without it we cannot
    // resolve the per-repo secret, and skipping verification would let an
    // attacker pump arbitrary payloads through this endpoint.
    if (!repoFullName) {
      return res.status(400).json({ error: 'Missing repository.full_name' });
    }

    const sigValid = await verifyBitbucketSignatureForRepo(req, repoFullName);
    if (!sigValid) {
      return res.status(401).json({ error: 'Invalid webhook signature' });
    }

    const deliveryId = req.headers['x-request-uuid'] as string | undefined;
    const payloadSize = Buffer.byteLength(JSON.stringify(req.body));

    // Dedup BEFORE recording — retried deliveries shouldn't accumulate rows.
    if (await deduplicateDelivery(deliveryId)) {
      return res.json({ received: true, skipped: 'duplicate' });
    }

    const startMs = Date.now();
    await recordWebhookDelivery(deliveryId, eventKey, undefined, repoFullName, payloadSize);

    res.json({ received: true });

    try {
      switch (eventKey) {
        case 'repo:push':
          await handleBitbucketPushEvent(req.body);
          break;
        case 'pullrequest:created':
          await handleBitbucketPullRequestEvent(req.body, 'created');
          break;
        case 'pullrequest:updated':
          await handleBitbucketPullRequestEvent(req.body, 'updated');
          break;
        case 'pullrequest:fulfilled':
          await handleBitbucketPullRequestEvent(req.body, 'fulfilled');
          break;
        case 'pullrequest:rejected':
          await handleBitbucketPullRequestEvent(req.body, 'rejected');
          break;
        default:
          console.log('[bitbucket-webhook] Unhandled event:', eventKey);
      }

      const durationMs = Date.now() - startMs;
      await supabase.from('webhook_deliveries').update({
        processing_status: 'processed',
        processing_duration_ms: durationMs,
      }).eq('delivery_id', deliveryId || '').eq('provider', 'bitbucket');
    } catch (err: any) {
      console.error('[bitbucket-webhook] Processing error:', err?.message);
      await supabase.from('webhook_deliveries').update({
        processing_status: 'error',
        error_message: err?.message?.slice(0, 500),
        processing_duration_ms: Date.now() - startMs,
      }).eq('delivery_id', deliveryId || '').eq('provider', 'bitbucket');
    }
  } catch (error: any) {
    console.error('[bitbucket-webhook] Error:', error);
    if (!res.headersSent) {
      res.status(200).json({ received: true, error: error.message });
    }
  }
});

export default router;
