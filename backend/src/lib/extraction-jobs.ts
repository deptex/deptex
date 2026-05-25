import crypto from 'crypto';
import { supabase } from './supabase';
import { startExtractionMachine, stopFlyMachine, DEPSCANNER_CONFIG } from './fly-machines';

// Extraction job queue — Supabase-based job persistence.
// Jobs stored in the scan_jobs table (type='extraction'); survives machine crashes.

export interface ExtractionJob {
  projectId: string;
  organizationId: string;
  repo_full_name: string;
  installation_id: string;
  default_branch: string;
  package_json_path?: string;
  ecosystem?: string;
  provider?: string;
  integration_id?: string;
}

/** Optional metadata for extraction run display (trigger, commit, who started it). */
export type ExtractionJobMeta = {
  trigger_type?: 'initial' | 'webhook' | 'manual' | 'scheduled';
  started_by_user_id?: string;
  commit_sha?: string;
  commit_message?: string;
  branch?: string;
  commit_author?: { username?: string; avatar_url?: string };
  /**
   * Phase 33: optional per-scan AI cost cap (USD). When set, the depscanner
   * worker aborts the next AI call once scan_jobs.ai_total_cost_usd plus the
   * projected next-call cost would exceed it, emits an ai_cost_cap_exceeded
   * extraction_step_errors row, and lets the offending step degrade to its
   * deterministic-only fallback. NULL/undefined = no per-scan cap (org-level
   * monthly cap still applies via organization_reachability_settings).
   */
  ai_cost_cap_usd?: number | null;
};

/**
 * Queue an extraction job by inserting into Supabase scan_jobs (type='extraction')
 * and starting a Fly.io machine to process it.
 */
export async function queueExtractionJob(
  projectId: string,
  organizationId: string,
  repoRecord: {
    repo_full_name: string;
    installation_id: string;
    default_branch: string;
    package_json_path?: string;
    ecosystem?: string;
    provider?: string;
    integration_id?: string;
  },
  meta?: ExtractionJobMeta
): Promise<{ success: boolean; error?: string; run_id?: string }> {
  try {
    const runId = crypto.randomUUID();

    const { data: existingJob } = await supabase
      .from('scan_jobs')
      .select('id, status')
      .eq('project_id', projectId)
      .eq('type', 'extraction')
      .in('status', ['queued', 'processing'])
      .maybeSingle();

    if (existingJob) {
      return { success: false, error: 'Extraction already in progress for this project' };
    }

    // Plan limit check: syncs
    try {
      const { getOrgPlan, getResolvedLimits } = require('./plan-limits');
      const plan = await getOrgPlan(organizationId);
      const limits = getResolvedLimits(plan.plan_tier, plan.custom_limits);
      const syncLimit = limits.syncs;

      const { data: rpcResult } = await supabase.rpc('increment_sync_usage', {
        p_org_id: organizationId,
        p_sync_limit: syncLimit,
      });

      if (rpcResult && rpcResult.length > 0 && !rpcResult[0].was_allowed) {
        return { success: false, error: 'Monthly sync limit reached. Upgrade your plan for more syncs.' };
      }
    } catch (e: any) {
      console.warn('[EXTRACT] Plan limit check failed (allowing):', e.message);
    }

    const payload: Record<string, unknown> = {
      repo_full_name: repoRecord.repo_full_name,
      installation_id: repoRecord.installation_id,
      default_branch: repoRecord.default_branch,
      package_json_path: repoRecord.package_json_path ?? '',
      ecosystem: repoRecord.ecosystem ?? 'npm',
      provider: repoRecord.provider ?? 'github',
      integration_id: repoRecord.integration_id,
    };
    if (meta) {
      if (meta.trigger_type) payload.trigger_type = meta.trigger_type;
      if (meta.started_by_user_id) payload.started_by_user_id = meta.started_by_user_id;
      if (meta.commit_sha) payload.commit_sha = meta.commit_sha;
      if (meta.commit_message) payload.commit_message = meta.commit_message;
      if (meta.branch) payload.branch = meta.branch;
      if (meta.commit_author) payload.commit_author = meta.commit_author;
    }

    // Phase 33: surface the optional per-scan AI cost cap onto the
    // scan_jobs row so the depscanner worker reads it directly via the
    // ai_cost_cap_usd column. We DON'T also stash it inside payload; the
    // top-level column is the canonical place (the worker's
    // checkScanJobCostCap helper reads it).
    const row: Record<string, unknown> = {
      project_id: projectId,
      organization_id: organizationId,
      type: 'extraction',
      status: 'queued',
      run_id: runId,
      payload,
    };
    if (meta?.ai_cost_cap_usd != null && Number.isFinite(meta.ai_cost_cap_usd) && meta.ai_cost_cap_usd > 0) {
      // Cap to a sane ceiling so an operator typo (e.g. $10000) can't disable
      // the cap entirely — anything above $1000/scan is treated as 1000.
      row.ai_cost_cap_usd = Math.min(1000, Number(meta.ai_cost_cap_usd));
    }
    const { error: insertError } = await supabase.from('scan_jobs').insert(row);

    if (insertError) {
      console.error('[EXTRACT] Failed to insert extraction job:', insertError);
      return { success: false, error: insertError.message };
    }

    console.log(
      `[${new Date().toISOString()}] Queued extraction job for project ${projectId}, repo ${repoRecord.repo_full_name} (run_id: ${runId})`
    );

    // Write initial log entry so the frontend shows a timestamp immediately
    try {
      await supabase.from('extraction_logs').insert({
        project_id: projectId,
        run_id: runId,
        step: 'cloning',
        level: 'info',
        message: 'Extraction queued — starting worker machine…',
        duration_ms: null,
        metadata: null,
      });
    } catch {
      // Fire-and-forget: log write failure must not block extraction
    }

    // Start a Fly machine (best-effort — job is safe in Supabase if this fails)
    try {
      const machineId = await startExtractionMachine();
      if (!machineId) {
        console.warn(`[EXTRACT] Failed to start Fly machine (job stays queued for recovery)`);
        // Write machine failure to extraction_logs so frontend can display it
        try {
          await supabase.from('extraction_logs').insert({
            project_id: projectId,
            run_id: runId,
            step: 'cloning',
            level: 'warning',
            message: 'Failed to start worker machine — job queued for automatic retry',
            duration_ms: null,
            metadata: null,
          });
        } catch {
          // Fire-and-forget
        }
      }
    } catch (e: any) {
      console.warn(`[EXTRACT] Failed to start Fly machine (job stays queued for recovery): ${e.message}`);
      try {
        await supabase.from('extraction_logs').insert({
          project_id: projectId,
          run_id: runId,
          step: 'cloning',
          level: 'error',
          message: `Failed to start extraction machine: ${e.message}`,
          duration_ms: null,
          metadata: null,
        });
      } catch {
        // Fire-and-forget
      }
    }

    return { success: true, run_id: runId };
  } catch (error: any) {
    console.error('Failed to queue extraction job:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Cancel an active extraction job for a project. Also stops the Fly
 * machine claimed by the job (if any) so cancel isn't purely cosmetic
 * — the previous behaviour let the worker run to completion burning
 * billable time after a user clicked Cancel. Refunds the sync slot
 * since no extraction completed.
 */
export async function cancelExtractionJob(
  projectId: string
): Promise<{ success: boolean; error?: string }> {
  const { data: job } = await supabase
    .from('scan_jobs')
    .select('id, status, machine_id, organization_id')
    .eq('project_id', projectId)
    .eq('type', 'extraction')
    .in('status', ['queued', 'processing'])
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!job) {
    const { data: latest } = await supabase
      .from('scan_jobs')
      .select('status')
      .eq('project_id', projectId)
      .eq('type', 'extraction')
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (latest?.status === 'completed') {
      return { success: false, error: 'Extraction already completed' };
    }
    if (latest?.status === 'cancelled') {
      return { success: false, error: 'Extraction already cancelled' };
    }
    return { success: false, error: 'No active extraction found' };
  }

  const { error } = await supabase
    .from('scan_jobs')
    .update({
      status: 'cancelled',
      completed_at: new Date().toISOString(),
    })
    .eq('id', job.id);

  if (error) {
    return { success: false, error: error.message };
  }

  await supabase
    .from('project_repositories')
    .update({
      status: 'cancelled',
      extraction_step: null,
      extraction_error: 'Cancelled by user',
      updated_at: new Date().toISOString(),
    })
    .eq('project_id', projectId);

  if (job.machine_id) {
    try {
      await stopFlyMachine(DEPSCANNER_CONFIG.app, job.machine_id);
    } catch (e: any) {
      console.warn(`[EXTRACT] Failed to stop Fly machine ${job.machine_id} on cancel:`, e?.message ?? e);
    }
  }

  if (job.organization_id) {
    try {
      await supabase.rpc('refund_sync_usage', { p_org_id: job.organization_id });
    } catch (e: any) {
      console.warn('[EXTRACT] Failed to refund sync usage on cancel:', e?.message ?? e);
    }
  }

  return { success: true };
}
