import express from 'express';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';

const router = express.Router();

// All routes require authentication
router.use(authenticateUser);

// GET /api/user-profile - Get the user's app-domain profile.
// Identity fields (display name, avatar URL) live on auth.users.user_metadata
// and ride along with the JWT — they're NOT returned here. This route is
// scoped to data that genuinely needs a relational home (currently just the
// default_organization_id, which has an FK into organizations).
router.get('/', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;

    const { data: profile, error } = await supabase
      .from('user_profiles')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (error && error.code !== 'PGRST116') { // PGRST116 = no rows returned
      throw error;
    }

    res.json(profile || { user_id: userId, default_organization_id: null });
  } catch (error: any) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

// PUT /api/user-profile - Update the user's default organization. Validates
// membership before persisting.
router.put('/', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { default_organization_id } = req.body;

    if (default_organization_id === undefined) {
      return res.status(400).json({ error: 'Nothing to update' });
    }

    if (default_organization_id !== null) {
      const { data: member, error: memberError } = await supabase
        .from('organization_members')
        .select('id')
        .eq('organization_id', default_organization_id)
        .eq('user_id', userId)
        .maybeSingle();

      if (memberError) {
        throw memberError;
      }
      if (!member) {
        return res.status(400).json({
          error: 'You must be a member of that organization to set it as default',
        });
      }
    }

    const { data: profile, error } = await supabase
      .from('user_profiles')
      .upsert({
        user_id: userId,
        default_organization_id,
        updated_at: new Date().toISOString(),
      }, {
        onConflict: 'user_id'
      })
      .select()
      .single();

    if (error) {
      throw error;
    }

    res.json(profile);
  } catch (error: any) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ error: 'Failed to update user profile' });
  }
});

// DELETE /api/user-profile/self - Permanently delete the authenticated user.
// For each org where the user is the sole owner: if there are no other members,
// the org is auto-deleted (it belongs to no one else); if there are other
// members, the request is refused so ownership can be transferred first.
router.delete('/self', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;

    const { data: ownerMemberships, error: ownerError } = await supabase
      .from('organization_members')
      .select('organization_id, organizations(id, name)')
      .eq('user_id', userId)
      .eq('role', 'owner');
    if (ownerError) throw ownerError;

    const orgsToAutoDelete: string[] = [];
    const blockingOrgs: { id: string; name: string }[] = [];

    for (const m of ownerMemberships ?? []) {
      const { count: totalMembers, error: totalErr } = await supabase
        .from('organization_members')
        .select('id', { count: 'exact', head: true })
        .eq('organization_id', m.organization_id);
      if (totalErr) throw totalErr;

      const { count: otherOwners, error: otherErr } = await supabase
        .from('organization_members')
        .select('id', { count: 'exact', head: true })
        .eq('organization_id', m.organization_id)
        .eq('role', 'owner')
        .neq('user_id', userId);
      if (otherErr) throw otherErr;

      if ((totalMembers ?? 0) <= 1) {
        orgsToAutoDelete.push(m.organization_id);
      } else if ((otherOwners ?? 0) === 0) {
        const org = (m as any).organizations as { id: string; name: string } | null;
        if (org) blockingOrgs.push(org);
      }
      // else: another owner exists, leaving is safe
    }

    if (blockingOrgs.length > 0) {
      return res.status(400).json({
        error: 'You are the only owner of one or more organizations with other members. Transfer ownership or delete the organization before deleting your account.',
        organizations: blockingOrgs,
      });
    }

    // Auto-delete orgs where the user is the sole member. CASCADE FKs on
    // organization_id will clean up projects, members, invitations, etc.
    for (const orgId of orgsToAutoDelete) {
      const { error: orgDeleteError } = await supabase
        .from('organizations')
        .delete()
        .eq('id', orgId);
      if (orgDeleteError) throw orgDeleteError;
    }

    const { error: deleteError } = await supabase.auth.admin.deleteUser(userId);
    if (deleteError) throw deleteError;

    res.status(204).send();
  } catch (error: any) {
    console.error('Error deleting user account:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

export default router;
