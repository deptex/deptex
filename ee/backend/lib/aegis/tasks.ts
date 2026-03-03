import { supabase } from '../../../../backend/src/lib/supabase';
import type { ToolContext } from './tools';

export interface TaskPlan {
  title: string;
  description: string;
  steps: TaskStep[];
  estimatedCost: number;
  estimatedTimeMinutes: number;
}

export interface TaskStep {
  title: string;
  toolName: string;
  toolParams: Record<string, any>;
  estimatedCost?: number;
}

export async function createTask(
  organizationId: string,
  userId: string,
  threadId: string | null,
  plan: TaskPlan,
): Promise<string> {
  const { data: task, error } = await supabase
    .from('aegis_tasks')
    .insert({
      organization_id: organizationId,
      user_id: userId,
      thread_id: threadId,
      title: plan.title,
      description: plan.description,
      mode: 'plan',
      status: 'awaiting_approval',
      plan_json: plan,
      total_steps: plan.steps.length,
    })
    .select('id')
    .single();

  if (error) throw error;

  const stepInserts = plan.steps.map((step, idx) => ({
    task_id: task.id,
    step_number: idx + 1,
    title: step.title,
    tool_name: step.toolName,
    tool_params: step.toolParams,
    status: 'pending',
  }));

  await supabase.from('aegis_task_steps').insert(stepInserts);

  return task.id;
}

export async function approveTask(taskId: string): Promise<void> {
  await supabase
    .from('aegis_tasks')
    .update({ status: 'running', started_at: new Date().toISOString() })
    .eq('id', taskId);

  const firstStepId = await getNextPendingStep(taskId);
  if (firstStepId) {
    const qstashToken = process.env.QSTASH_TOKEN;
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';
    if (qstashToken) {
      try {
        await fetch(
          'https://qstash.upstash.io/v2/publish/' +
            encodeURIComponent(`${backendUrl}/api/internal/aegis/execute-task-step`),
          {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${qstashToken}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ taskId, stepId: firstStepId }),
          },
        );
      } catch (err) {
        console.error('[Aegis Task] Failed to queue first step via QStash:', err);
      }
    }
  }
}

export async function cancelTask(taskId: string): Promise<void> {
  await supabase
    .from('aegis_tasks')
    .update({ status: 'cancelled', completed_at: new Date().toISOString() })
    .eq('id', taskId);

  await supabase
    .from('aegis_task_steps')
    .update({ status: 'skipped' })
    .eq('task_id', taskId)
    .in('status', ['pending', 'running']);
}

export async function pauseTask(taskId: string): Promise<void> {
  await supabase
    .from('aegis_tasks')
    .update({ status: 'paused' })
    .eq('id', taskId);
}

export async function getTaskStatus(taskId: string) {
  const { data: task } = await supabase
    .from('aegis_tasks')
    .select('*')
    .eq('id', taskId)
    .single();

  if (!task) return null;

  const { data: steps } = await supabase
    .from('aegis_task_steps')
    .select('*')
    .eq('task_id', taskId)
    .order('step_number', { ascending: true });

  return { ...task, steps: steps || [] };
}

export async function executeTaskStep(taskId: string, stepId: string): Promise<{
  success: boolean;
  hasMore: boolean;
  taskCompleted: boolean;
}> {
  const { data: step } = await supabase
    .from('aegis_task_steps')
    .select('*')
    .eq('id', stepId)
    .eq('task_id', taskId)
    .single();

  if (!step || step.status !== 'pending') {
    return { success: false, hasMore: false, taskCompleted: false };
  }

  await supabase
    .from('aegis_task_steps')
    .update({ status: 'running', started_at: new Date().toISOString() })
    .eq('id', stepId);

  const { data: task } = await supabase
    .from('aegis_tasks')
    .select('organization_id, user_id, thread_id, total_steps, completed_steps, failed_steps, total_cost')
    .eq('id', taskId)
    .single();

  if (!task) return { success: false, hasMore: false, taskCompleted: false };

  try {
    const { buildToolSet } = await import('./tools');
    const toolContext: ToolContext = {
      organizationId: task.organization_id,
      userId: task.user_id,
      threadId: task.thread_id,
      taskId,
      operatingMode: 'autopilot',
    };

    const tools = buildToolSet(toolContext);
    const toolFn = tools[step.tool_name];

    if (!toolFn) throw new Error(`Tool ${step.tool_name} not found`);

    const startTime = Date.now();
    const result = await (toolFn as any).execute(step.tool_params);
    const durationMs = Date.now() - startTime;

    await supabase
      .from('aegis_task_steps')
      .update({
        status: 'completed',
        result_json: typeof result === 'string' ? JSON.parse(result) : result,
        completed_at: new Date().toISOString(),
      })
      .eq('id', stepId);

    const newCompleted = (task.completed_steps || 0) + 1;
    await supabase
      .from('aegis_tasks')
      .update({ completed_steps: newCompleted })
      .eq('id', taskId);

    // Check if task is done
    const totalDone = newCompleted + (task.failed_steps || 0);
    if (totalDone >= task.total_steps) {
      await supabase
        .from('aegis_tasks')
        .update({ status: 'completed', completed_at: new Date().toISOString() })
        .eq('id', taskId);
      return { success: true, hasMore: false, taskCompleted: true };
    }

    // Check circuit breaker: >50% failures with min 3 steps
    const failRate = (task.failed_steps || 0) / Math.max(totalDone, 1);
    if (totalDone >= 3 && failRate > 0.5) {
      await supabase
        .from('aegis_tasks')
        .update({ status: 'paused' })
        .eq('id', taskId);
      return { success: true, hasMore: false, taskCompleted: false };
    }

    return { success: true, hasMore: true, taskCompleted: false };
  } catch (err: any) {
    await supabase
      .from('aegis_task_steps')
      .update({
        status: 'failed',
        error_message: err.message,
        completed_at: new Date().toISOString(),
      })
      .eq('id', stepId);

    const newFailed = (task.failed_steps || 0) + 1;
    await supabase
      .from('aegis_tasks')
      .update({ failed_steps: newFailed })
      .eq('id', taskId);

    const totalDone = (task.completed_steps || 0) + newFailed;
    if (totalDone >= task.total_steps) {
      await supabase
        .from('aegis_tasks')
        .update({ status: 'completed', completed_at: new Date().toISOString() })
        .eq('id', taskId);
      return { success: false, hasMore: false, taskCompleted: true };
    }

    return { success: false, hasMore: true, taskCompleted: false };
  }
}

export async function getNextPendingStep(taskId: string): Promise<string | null> {
  const { data } = await supabase
    .from('aegis_task_steps')
    .select('id')
    .eq('task_id', taskId)
    .eq('status', 'pending')
    .order('step_number', { ascending: true })
    .limit(1)
    .single();

  return data?.id || null;
}
