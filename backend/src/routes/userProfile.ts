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
// Refuses if the user is the sole owner of any organization (to prevent
// orphaning shared resources). Otherwise, calls Supabase's admin deleteUser
// which cascades through user_profiles and organization_members via FK.
router.delete('/self', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;

    // 1. Find every org where this user is an owner.
    const { data: ownerMemberships, error: ownerError } = await supabase
      .from('organization_members')
      .select('organization_id, organizations(id, name)')
      .eq('user_id', userId)
      .eq('role', 'owner');

    if (ownerError) {
      throw ownerError;
    }

    // 2. For each, check if there's at least one other owner.
    const soleOwnerOrgs: { id: string; name: string }[] = [];
    for (const m of ownerMemberships ?? []) {
      const { count, error: countError } = await supabase
        .from('organization_members')
        .select('id', { count: 'exact', head: true })
        .eq('organization_id', m.organization_id)
        .eq('role', 'owner');
      if (countError) {
        throw countError;
      }
      if ((count ?? 0) <= 1) {
        const org = (m as any).organizations as { id: string; name: string } | null;
        if (org) soleOwnerOrgs.push(org);
      }
    }

    if (soleOwnerOrgs.length > 0) {
      return res.status(400).json({
        error: 'You are the only owner of one or more organizations. Transfer ownership or delete the organization before deleting your account.',
        organizations: soleOwnerOrgs,
      });
    }

    // 3. Delete the auth user. CASCADE on user_profiles.user_id and
    //    organization_members.user_id removes app-domain rows automatically.
    const { error: deleteError } = await supabase.auth.admin.deleteUser(userId);
    if (deleteError) {
      throw deleteError;
    }

    res.status(204).send();
  } catch (error: any) {
    console.error('Error deleting user account:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

export default router;
