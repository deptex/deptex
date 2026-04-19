import express from 'express';
import { authenticateUser, AuthRequest, optionalAuth } from '../../../backend/src/middleware/auth';
import { supabase } from '../../../backend/src/lib/supabase';

const router = express.Router();

// All routes require authentication
router.use(authenticateUser);

// GET /api/invitations - Get user's pending invitations
router.get('/', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;

    // Get user's email - use the token from the request
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing authorization header' });
    }

    const token = authHeader.substring(7);
    const { data: userData, error: userError } = await supabase.auth.getUser(token);
    
    if (userError || !userData.user?.email) {
      console.error('Error getting user email:', userError);
      return res.status(401).json({ error: 'User not found' });
    }

    const userEmail = userData.user.email.toLowerCase().trim();
    console.log('Fetching invitations for user email:', userEmail);

    // Get pending invitations for this user's email (case-insensitive comparison)
    // Note: Supabase .eq() is case-sensitive, so we need to fetch all pending and filter
    const { data: allInvitations, error: invitationsError } = await supabase
      .from('organization_invitations')
      .select('*')
      .eq('status', 'pending')
      .gt('expires_at', new Date().toISOString());

    if (invitationsError) {
      throw invitationsError;
    }

    // Filter by email (case-insensitive) and log for debugging
    const invitations = (allInvitations || []).filter(inv => {
      const invEmail = (inv.email || '').toLowerCase().trim();
      const matches = invEmail === userEmail;
      if (!matches) {
        console.log(`Invitation email mismatch: DB="${inv.email}" vs User="${userEmail}"`);
      }
      return matches;
    });

    console.log(`Found ${invitations.length} invitations for ${userEmail} out of ${allInvitations?.length || 0} total pending`);

    if (!invitations || invitations.length === 0) {
      console.log('No invitations found for user:', userEmail);
      return res.json([]);
    }

    // Get organization names for the invitations
    const organizationIds = invitations.map(inv => inv.organization_id);
    const { data: organizations, error: orgError } = await supabase
      .from('organizations')
      .select('id, name')
      .in('id', organizationIds);

    if (orgError) {
      throw orgError;
    }

    // Create a map of organization IDs to names
    const orgMap = new Map(organizations?.map(org => [org.id, org.name]) || []);

    // Get team names for invitations that have team_id
    const teamIds = invitations.filter(inv => inv.team_id).map(inv => inv.team_id);
    let teamMap = new Map();
    if (teamIds.length > 0) {
      const { data: teams } = await supabase
        .from('teams')
        .select('id, name')
        .in('id', teamIds);
      teamMap = new Map(teams?.map(team => [team.id, team.name]) || []);
    }

    // Format the response to include organization name and team name
    const formattedInvitations = invitations.map((inv) => ({
      id: inv.id,
      organization_id: inv.organization_id,
      organization_name: orgMap.get(inv.organization_id) || 'Organization',
      email: inv.email,
      role: inv.role,
      status: inv.status,
      created_at: inv.created_at,
      expires_at: inv.expires_at,
      team_id: inv.team_id || null,
      team_name: inv.team_id ? teamMap.get(inv.team_id) || null : null,
    }));

    res.json(formattedInvitations);
  } catch (error: any) {
    console.error('Error fetching invitations:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch invitations' });
  }
});

export default router;

