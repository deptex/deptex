import { supabase } from '../../../backend/src/lib/supabase';
import { startWatchtowerMachine } from './fly-machines';

export interface WatchtowerJobInput {
  type?: 'full_analysis' | 'new_version' | 'batch_version_analysis' | 'poll_sweep';
  priority?: number;
  payload: Record<string, any>;
  organizationId?: string;
  projectId?: string;
  dependencyId?: string;
  packageName: string;
}

export async function queueWatchtowerJob(job: WatchtowerJobInput): Promise<{ success: boolean; jobId?: string; error?: string }> {
  try {
    const { data, error } = await supabase
      .from('watchtower_jobs')
      .insert({
        job_type: job.type || 'full_analysis',
        priority: job.priority || 10,
        payload: job.payload,
        organization_id: job.organizationId || null,
        project_id: job.projectId || null,
        dependency_id: job.dependencyId || null,
        package_name: job.packageName,
      })
      .select('id')
      .single();

    if (error) {
      console.error('[watchtower-queue] Failed to insert job:', error.message);
      return { success: false, error: error.message };
    }

    startWatchtowerMachine().catch(() => {});

    console.log(`[watchtower-queue] Queued ${job.type || 'full_analysis'} job for ${job.packageName} (id: ${data.id})`);
    return { success: true, jobId: data.id };
  } catch (error: any) {
    console.error('[watchtower-queue] Failed to queue job:', error.message);
    return { success: false, error: error.message };
  }
}

export async function queueWatchtowerJobs(jobs: WatchtowerJobInput[]): Promise<{ success: boolean; count: number }> {
  if (jobs.length === 0) return { success: true, count: 0 };

  try {
    const rows = jobs.map((job) => ({
      job_type: job.type || 'full_analysis',
      priority: job.priority || 10,
      payload: job.payload,
      organization_id: job.organizationId || null,
      project_id: job.projectId || null,
      dependency_id: job.dependencyId || null,
      package_name: job.packageName,
    }));

    const { error } = await supabase.from('watchtower_jobs').insert(rows);

    if (error) {
      console.error('[watchtower-queue] Failed to insert batch:', error.message);
      return { success: false, count: 0 };
    }

    startWatchtowerMachine().catch(() => {});

    console.log(`[watchtower-queue] Queued ${jobs.length} watchtower jobs`);
    return { success: true, count: jobs.length };
  } catch (error: any) {
    console.error('[watchtower-queue] Failed to queue batch:', error.message);
    return { success: false, count: 0 };
  }
}
