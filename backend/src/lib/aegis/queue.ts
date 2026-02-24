import { supabase } from '../supabase';
import { executeMessage, ExecutionContext } from './executor';

/**
 * Parse natural language schedule to next run time
 * Examples:
 * - "every Monday morning" -> next Monday 8 AM
 * - "daily at 8 AM" -> tomorrow 8 AM
 * - "weekly on Monday" -> next Monday
 * - "every Monday at 9 AM" -> next Monday 9 AM
 */
export function parseScheduleToNextRun(schedule: string): Date | null {
  const now = new Date();
  const lowerSchedule = schedule.toLowerCase().trim();

  // Extract time if present (e.g., "8 AM", "9:30 PM", "14:00")
  let hour = 8; // Default to 8 AM
  let minute = 0;

  const timeMatch = lowerSchedule.match(/(\d{1,2})(?::(\d{2}))?\s*(am|pm)?/i);
  if (timeMatch) {
    hour = parseInt(timeMatch[1], 10);
    if (timeMatch[3]) {
      // AM/PM format
      if (timeMatch[3].toLowerCase() === 'pm' && hour !== 12) {
        hour += 12;
      } else if (timeMatch[3].toLowerCase() === 'am' && hour === 12) {
        hour = 0;
      }
    }
    if (timeMatch[2]) {
      minute = parseInt(timeMatch[2], 10);
    }
  }

  // Parse day of week
  const dayNames = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
  let targetDay: number | null = null;

  for (let i = 0; i < dayNames.length; i++) {
    if (lowerSchedule.includes(dayNames[i])) {
      targetDay = i;
      break;
    }
  }

  const nextRun = new Date(now);
  nextRun.setHours(hour, minute, 0, 0);

  if (lowerSchedule.includes('daily') || lowerSchedule.includes('every day')) {
    // Daily: if time has passed today, schedule for tomorrow
    if (nextRun <= now) {
      nextRun.setDate(nextRun.getDate() + 1);
    }
    return nextRun;
  }

  if (lowerSchedule.includes('weekly') || lowerSchedule.includes('every week')) {
    if (targetDay !== null) {
      // Weekly on specific day
      const daysUntilTarget = (targetDay - now.getDay() + 7) % 7;
      if (daysUntilTarget === 0 && nextRun <= now) {
        // If it's today but time has passed, schedule for next week
        nextRun.setDate(nextRun.getDate() + 7);
      } else {
        nextRun.setDate(nextRun.getDate() + daysUntilTarget);
      }
      return nextRun;
    }
    // Weekly without day specified, default to same day next week
    nextRun.setDate(nextRun.getDate() + 7);
    return nextRun;
  }

  if (targetDay !== null) {
    // Specific day of week (e.g., "every Monday")
    const daysUntilTarget = (targetDay - now.getDay() + 7) % 7;
    if (daysUntilTarget === 0 && nextRun <= now) {
      // If it's today but time has passed, schedule for next week
      nextRun.setDate(nextRun.getDate() + 7);
    } else {
      nextRun.setDate(nextRun.getDate() + daysUntilTarget);
    }
    return nextRun;
  }

  // Default: if time has passed today, schedule for tomorrow
  if (nextRun <= now) {
    nextRun.setDate(nextRun.getDate() + 1);
  }
  return nextRun;
}

/**
 * Process pending automation jobs
 */
export async function processAutomationJobs(): Promise<void> {
  try {
    const now = new Date().toISOString();

    // Get all pending jobs that are due
    const { data: jobs, error: jobsError } = await supabase
      .from('aegis_automation_jobs')
      .select('*, aegis_automations(*)')
      .eq('status', 'pending')
      .lte('scheduled_for', now)
      .order('scheduled_for', { ascending: true })
      .limit(10); // Process up to 10 jobs at a time

    if (jobsError) {
      console.error('Error fetching automation jobs:', jobsError);
      return;
    }

    if (!jobs || jobs.length === 0) {
      return; // No jobs to process
    }

    // Process each job
    for (const job of jobs) {
      const automation = (job as any).aegis_automations;
      if (!automation || !automation.enabled) {
        // Skip if automation is disabled
        await supabase
          .from('aegis_automation_jobs')
          .update({ status: 'failed', error_message: 'Automation is disabled' })
          .eq('id', job.id);
        continue;
      }

      // Mark job as running
      await supabase
        .from('aegis_automation_jobs')
        .update({
          status: 'running',
          started_at: new Date().toISOString(),
        })
        .eq('id', job.id);

      try {
        // Get organization name
        const { data: org } = await supabase
          .from('organizations')
          .select('name')
          .eq('id', automation.organization_id)
          .single();

        if (!org) {
          throw new Error('Organization not found');
        }

        // Execute automation
        // For now, we'll use the automation description as the message
        // In the future, this could be more sophisticated
        const context: ExecutionContext = {
          organizationId: automation.organization_id,
          userId: automation.organization_id, // Use org ID as a placeholder
          organizationName: org.name,
        };

        const message = automation.description || `Run automation: ${automation.name}`;
        const result = await executeMessage(message, context);

        // Mark job as completed
        await supabase
          .from('aegis_automation_jobs')
          .update({
            status: 'completed',
            completed_at: new Date().toISOString(),
            result_json: result,
          })
          .eq('id', job.id);

        // Update automation last_run_at
        await supabase
          .from('aegis_automations')
          .update({ last_run_at: new Date().toISOString() })
          .eq('id', automation.id);

        // Schedule next run if automation is still enabled
        if (automation.enabled) {
          const nextRun = parseScheduleToNextRun(automation.schedule);
          if (nextRun) {
            await supabase
              .from('aegis_automations')
              .update({ next_run_at: nextRun.toISOString() })
              .eq('id', automation.id);

            // Create next job
            await supabase
              .from('aegis_automation_jobs')
              .insert({
                automation_id: automation.id,
                organization_id: automation.organization_id,
                status: 'pending',
                scheduled_for: nextRun.toISOString(),
              });
          }
        }
      } catch (error: any) {
        console.error(`Error processing automation job ${job.id}:`, error);
        
        // Mark job as failed
        await supabase
          .from('aegis_automation_jobs')
          .update({
            status: 'failed',
            completed_at: new Date().toISOString(),
            error_message: error.message || 'Unknown error',
          })
          .eq('id', job.id);
      }
    }
  } catch (error: any) {
    console.error('Error processing automation jobs:', error);
  }
}

/**
 * Schedule automations (create initial jobs for enabled automations)
 */
export async function scheduleAutomations(): Promise<void> {
  try {
    // Get all enabled automations that don't have a next job scheduled
    const { data: automations, error } = await supabase
      .from('aegis_automations')
      .select('*')
      .eq('enabled', true)
      .is('next_run_at', null);

    if (error) {
      console.error('Error fetching automations:', error);
      return;
    }

    if (!automations || automations.length === 0) {
      return;
    }

    // Schedule each automation
    for (const automation of automations) {
      const nextRun = parseScheduleToNextRun(automation.schedule);
      if (nextRun) {
        // Update automation with next_run_at
        await supabase
          .from('aegis_automations')
          .update({ next_run_at: nextRun.toISOString() })
          .eq('id', automation.id);

        // Create job
        await supabase
          .from('aegis_automation_jobs')
          .insert({
            automation_id: automation.id,
            organization_id: automation.organization_id,
            status: 'pending',
            scheduled_for: nextRun.toISOString(),
          });
      }
    }
  } catch (error: any) {
    console.error('Error scheduling automations:', error);
  }
}

/**
 * Start queue processor (call this periodically, e.g., every minute)
 */
export function startQueueProcessor(intervalMs: number = 60000): NodeJS.Timeout {
  // Schedule initial automations
  scheduleAutomations().catch(console.error);

  // Process jobs periodically
  return setInterval(() => {
    processAutomationJobs().catch(console.error);
  }, intervalMs);
}

