import { registerAction, ActionResult, ActionContext } from './index';
import { supabase } from '../../../../../backend/src/lib/supabase';

// Register listMembers action
registerAction(
  {
    name: 'listMembers',
    description: 'List all members in the organization',
    parameters: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  async (params: any, context: ActionContext): Promise<ActionResult> => {
    try {
      // Get all members
      const { data: members, error: membersError } = await supabase
        .from('organization_members')
        .select('user_id, role, created_at')
        .eq('organization_id', context.organizationId)
        .order('created_at', { ascending: false });

      if (membersError) {
        return {
          success: false,
          error: membersError.message || 'Failed to fetch members',
        };
      }

      if (!members || members.length === 0) {
        return {
          success: true,
          data: [],
        };
      }

      // Get all teams for this organization
      const { data: orgTeams } = await supabase
        .from('teams')
        .select('id, name')
        .eq('organization_id', context.organizationId);

      // Get all team memberships for this organization
      const teamIds = (orgTeams || []).map(t => t.id);
      const { data: allTeamMembers } = teamIds.length > 0 ? await supabase
        .from('team_members')
        .select('user_id, team_id, teams!inner(id, name)')
        .in('team_id', teamIds) : { data: [] };

      // Create a map of user_id -> teams
      const userTeamsMap = new Map<string, Array<{ id: string; name: string }>>();
      (allTeamMembers || []).forEach((tm: any) => {
        if (!userTeamsMap.has(tm.user_id)) {
          userTeamsMap.set(tm.user_id, []);
        }
        userTeamsMap.get(tm.user_id)!.push({
          id: tm.teams.id,
          name: tm.teams.name,
        });
      });

      // Get user data for each member
      const formattedMembers = await Promise.all(
        members.map(async (m: any) => {
          try {
            const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(m.user_id);
            
            const teams = userTeamsMap.get(m.user_id) || [];

            if (userError || !user) {
              return {
                user_id: m.user_id,
                role: m.role,
                created_at: m.created_at,
                email: '',
                full_name: '',
                avatar_url: null,
                teams: teams,
              };
            }

            // Get user profile
            const { data: profile } = await supabase
              .from('user_profiles')
              .select('avatar_url, full_name')
              .eq('user_id', m.user_id)
              .single();

            const avatarUrl = profile?.avatar_url 
              || user.user_metadata?.picture 
              || user.user_metadata?.avatar_url 
              || null;
            const fullName = profile?.full_name || user.user_metadata?.full_name || null;

            return {
              user_id: m.user_id,
              role: m.role,
              created_at: m.created_at,
              email: user.email || '',
              full_name: fullName,
              avatar_url: avatarUrl,
              teams: teams,
            };
          } catch (error) {
            console.error(`Error fetching user ${m.user_id}:`, error);
            return {
              user_id: m.user_id,
              role: m.role,
              created_at: m.created_at,
              email: '',
              full_name: '',
              avatar_url: null,
              teams: [],
            };
          }
        })
      );

      return {
        success: true,
        data: formattedMembers,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Unknown error occurred',
      };
    }
  }
);

