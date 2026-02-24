import { supabase } from './supabase';

export interface CreateActivityParams {
  organization_id: string;
  user_id: string;
  activity_type: string;
  description: string;
  metadata?: Record<string, any>;
}

/**
 * Create an activity log entry
 */
export async function createActivity(params: CreateActivityParams): Promise<void> {
  try {
    const { error } = await supabase
      .from('activities')
      .insert({
        organization_id: params.organization_id,
        user_id: params.user_id,
        activity_type: params.activity_type,
        description: params.description,
        metadata: params.metadata || {},
      });

    if (error) {
      console.error('Error creating activity:', error);
      // Don't throw - activities are non-critical, we don't want to break the main operation
    }
  } catch (error) {
    console.error('Error creating activity:', error);
    // Silently fail - activities are non-critical
  }
}

