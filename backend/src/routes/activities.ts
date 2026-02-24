import express from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';

const router = express.Router();

// All routes require authentication
router.use(authenticateUser);

// GET /api/organizations/:id/activities - Get activities for an organization with filters
router.get('/:id/activities', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const {
      start_date,
      end_date,
      activity_type,
      team_id,
      limit = '100',
      offset = '0'
    } = req.query;

    // Check if user is a member
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Build query
    let query = supabase
      .from('activities')
      .select(`
        id,
        organization_id,
        user_id,
        activity_type,
        description,
        metadata,
        created_at
      `)
      .eq('organization_id', id)
      .order('created_at', { ascending: false })
      .limit(parseInt(limit as string, 10))
      .range(parseInt(offset as string, 10), parseInt(offset as string, 10) + parseInt(limit as string, 10) - 1);

    // Apply date filters
    if (start_date) {
      query = query.gte('created_at', start_date as string);
    }
    if (end_date) {
      query = query.lte('created_at', end_date as string);
    }

    // Apply activity type filter
    if (activity_type) {
      const types = Array.isArray(activity_type) ? activity_type : [activity_type];
      query = query.in('activity_type', types);
    }

    const { data: activities, error: activitiesError } = await query;

    if (activitiesError) {
      throw activitiesError;
    }

    // Filter by team_id in metadata if specified (client-side filtering since metadata is JSONB)
    let filteredActivities = activities || [];
    if (team_id) {
      filteredActivities = filteredActivities.filter((activity: any) =>
        activity.metadata?.team_id === team_id
      );
    }

    // Get unique user IDs from filtered activities
    const userIds = [...new Set(filteredActivities.map((a: any) => a.user_id))];

    // Fetch user profiles and auth data
    const userDataMap = new Map<string, { email: string; full_name: string | null; avatar_url: string | null }>();

    for (const userId of userIds) {
      try {
        // Get user from auth
        const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(userId);

        // Get user profile
        const { data: profile } = await supabase
          .from('user_profiles')
          .select('avatar_url, full_name')
          .eq('user_id', userId)
          .single();

        const email = user?.email || '';
        const fullName = profile?.full_name || user?.user_metadata?.full_name || null;
        const avatarUrl = profile?.avatar_url || user?.user_metadata?.picture || user?.user_metadata?.avatar_url || null;

        userDataMap.set(userId, { email, full_name: fullName, avatar_url: avatarUrl });
      } catch (error) {
        console.error(`Error fetching user ${userId}:`, error);
        userDataMap.set(userId, { email: '', full_name: null, avatar_url: null });
      }
    }

    // Format the response
    const formattedActivities = filteredActivities.map((activity: any) => {
      const userData = userDataMap.get(activity.user_id);
      return {
        id: activity.id,
        organization_id: activity.organization_id,
        user_id: activity.user_id,
        activity_type: activity.activity_type,
        description: activity.description,
        metadata: activity.metadata || {},
        created_at: activity.created_at,
        user: userData ? {
          email: userData.email,
          full_name: userData.full_name,
          avatar_url: userData.avatar_url,
        } : null,
      };
    });

    res.json(formattedActivities);
  } catch (error: any) {
    console.error('Error fetching activities:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch activities' });
  }
});

export default router;

