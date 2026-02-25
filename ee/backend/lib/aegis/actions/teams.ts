import { registerAction, ActionResult, ActionContext } from './index';
import { supabase } from '../../../../../backend/src/lib/supabase';

// Register listTeams action
registerAction(
  {
    name: 'listTeams',
    description: 'List all teams in the organization',
    parameters: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  async (params: any, context: ActionContext): Promise<ActionResult> => {
    try {
      const { data: teams, error } = await supabase
        .from('teams')
        .select('*')
        .eq('organization_id', context.organizationId)
        .order('created_at', { ascending: false });

      if (error) {
        return {
          success: false,
          error: error.message || 'Failed to fetch teams',
        };
      }

      // Get member counts for each team
      const teamsWithCounts = await Promise.all(
        (teams || []).map(async (team) => {
          const { count } = await supabase
            .from('team_members')
            .select('*', { count: 'exact', head: true })
            .eq('team_id', team.id);

          return {
            ...team,
            member_count: count || 0,
          };
        })
      );

      return {
        success: true,
        data: teamsWithCounts,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Unknown error occurred',
      };
    }
  }
);

// Register addMemberToTeam action
registerAction(
  {
    name: 'addMemberToTeam',
    description: 'Add a member to a team. Requires teamId and userId.',
    parameters: {
      type: 'object',
      properties: {
        teamId: {
          type: 'string',
          description: 'The ID of the team to add the member to',
        },
        userId: {
          type: 'string',
          description: 'The ID of the user to add to the team',
        },
      },
      required: ['teamId', 'userId'],
    },
  },
  async (params: { teamId: string; userId: string }, context: ActionContext): Promise<ActionResult> => {
    try {
      // Verify the team belongs to the organization
      const { data: team, error: teamError } = await supabase
        .from('teams')
        .select('id, name')
        .eq('id', params.teamId)
        .eq('organization_id', context.organizationId)
        .single();

      if (teamError || !team) {
        return {
          success: false,
          error: 'Team not found or does not belong to this organization',
        };
      }

      // Verify the user is a member of the organization
      const { data: orgMember } = await supabase
        .from('organization_members')
        .select('id')
        .eq('organization_id', context.organizationId)
        .eq('user_id', params.userId)
        .single();

      if (!orgMember) {
        return {
          success: false,
          error: 'User is not a member of this organization',
        };
      }

      // Add member to team
      const { data: teamMember, error: addError } = await supabase
        .from('team_members')
        .insert({
          team_id: params.teamId,
          user_id: params.userId,
        })
        .select()
        .single();

      if (addError) {
        if (addError.code === '23505' || addError.message?.includes('duplicate key')) {
          return {
            success: false,
            error: 'User is already a member of this team',
          };
        }
        return {
          success: false,
          error: addError.message || 'Failed to add member to team',
        };
      }

      return {
        success: true,
        data: {
          team: team.name,
          message: `Successfully added user to team "${team.name}"`,
        },
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Unknown error occurred',
      };
    }
  }
);

// Register moveAllMembers action
registerAction(
  {
    name: 'moveAllMembers',
    description: 'Move all members from one team to another. Requires sourceTeamId and targetTeamId.',
    parameters: {
      type: 'object',
      properties: {
        sourceTeamId: {
          type: 'string',
          description: 'The ID of the source team to move members from',
        },
        targetTeamId: {
          type: 'string',
          description: 'The ID of the target team to move members to',
        },
      },
      required: ['sourceTeamId', 'targetTeamId'],
    },
  },
  async (params: { sourceTeamId: string; targetTeamId: string }, context: ActionContext): Promise<ActionResult> => {
    try {
      // Verify both teams belong to the organization
      const { data: teams, error: teamsError } = await supabase
        .from('teams')
        .select('id, name')
        .eq('organization_id', context.organizationId)
        .in('id', [params.sourceTeamId, params.targetTeamId]);

      if (teamsError || !teams || teams.length !== 2) {
        return {
          success: false,
          error: 'One or both teams not found or do not belong to this organization',
        };
      }

      const sourceTeam = teams.find(t => t.id === params.sourceTeamId);
      const targetTeam = teams.find(t => t.id === params.targetTeamId);

      if (!sourceTeam || !targetTeam) {
        return {
          success: false,
          error: 'Could not find both teams',
        };
      }

      // Get all members from source team
      const { data: sourceMembers, error: membersError } = await supabase
        .from('team_members')
        .select('user_id')
        .eq('team_id', params.sourceTeamId);

      if (membersError) {
        return {
          success: false,
          error: membersError.message || 'Failed to fetch source team members',
        };
      }

      if (!sourceMembers || sourceMembers.length === 0) {
        return {
          success: true,
          data: {
            message: `No members to move from "${sourceTeam.name}"`,
            moved_count: 0,
          },
        };
      }

      // Move each member to target team
      let movedCount = 0;
      let skippedCount = 0;

      for (const member of sourceMembers) {
        // Check if member is already in target team
        const { data: existing } = await supabase
          .from('team_members')
          .select('id')
          .eq('team_id', params.targetTeamId)
          .eq('user_id', member.user_id)
          .single();

        if (existing) {
          skippedCount++;
          continue;
        }

        // Add to target team
        const { error: addError } = await supabase
          .from('team_members')
          .insert({
            team_id: params.targetTeamId,
            user_id: member.user_id,
          });

        if (!addError) {
          movedCount++;
        }
      }

      // Remove all members from source team
      const { error: removeError } = await supabase
        .from('team_members')
        .delete()
        .eq('team_id', params.sourceTeamId);

      if (removeError) {
        return {
          success: false,
          error: `Moved ${movedCount} members but failed to remove them from source team: ${removeError.message}`,
        };
      }

      return {
        success: true,
        data: {
          message: `Moved ${movedCount} member(s) from "${sourceTeam.name}" to "${targetTeam.name}"${skippedCount > 0 ? ` (${skippedCount} already in target team)` : ''}`,
          moved_count: movedCount,
          skipped_count: skippedCount,
        },
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Unknown error occurred',
      };
    }
  }
);

