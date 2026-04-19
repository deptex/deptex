import express from 'express';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';

const router = express.Router();

// All routes require authentication
router.use(authenticateUser);

// GET /api/user-profile - Get current user's profile
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

    // If no profile exists, return empty profile
    res.json(profile || { user_id: userId, avatar_url: null, full_name: null });
  } catch (error: any) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch user profile' });
  }
});

// PUT /api/user-profile - Update current user's profile
router.put('/', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { avatar_url, full_name } = req.body;

    const updateData: any = { updated_at: new Date().toISOString() };
    if (avatar_url !== undefined) updateData.avatar_url = avatar_url;
    if (full_name !== undefined) updateData.full_name = full_name;

    // Upsert the profile
    const { data: profile, error } = await supabase
      .from('user_profiles')
      .upsert({
        user_id: userId,
        ...updateData,
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
    res.status(500).json({ error: error.message || 'Failed to update user profile' });
  }
});

export default router;

