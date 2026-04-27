// @ts-nocheck
import express from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import '../lib/aegis/actions/init';

const router = express.Router();

router.use(authenticateUser);

async function isAegisEnabled(organizationId: string): Promise<boolean> {
  const { data } = await supabase
    .from('aegis_config')
    .select('enabled')
    .eq('organization_id', organizationId)
    .single();
  
  return data?.enabled === true;
}

async function hasAegisPermission(orgId: string, userId: string): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();
  if (!membership) return false;

  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', membership.role)
    .single();

  // Support both old and new permission names during migration
  return role?.permissions?.interact_with_aegis === true ||
    role?.permissions?.interact_with_security_agent === true;
}

async function hasPermission(orgId: string, userId: string, permission: string): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();
  if (!membership) return false;

  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', membership.role)
    .single();

  return role?.permissions?.[permission] === true;
}

// GET /api/aegis/status/:organizationId - Check if Aegis is enabled
router.get('/status/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const enabled = await isAegisEnabled(organizationId);
    res.json({ enabled });
  } catch (error: any) {
    console.error('Error checking Aegis status:', error);
    res.status(500).json({ error: error.message || 'Failed to check Aegis status' });
  }
});

// POST /api/aegis/enable/:organizationId - Enable Aegis for organization
router.post('/enable/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;

    // Check if user is admin or owner
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins and owners can enable Aegis' });
    }

    // Check if config already exists
    const { data: existing } = await supabase
      .from('aegis_config')
      .select('id')
      .eq('organization_id', organizationId)
      .single();

    if (existing) {
      // Update existing config
      const { error } = await supabase
        .from('aegis_config')
        .update({ enabled: true })
        .eq('organization_id', organizationId);

      if (error) throw error;
    } else {
      // Create new config
      const { error } = await supabase
        .from('aegis_config')
        .insert({
          organization_id: organizationId,
          enabled: true,
        });

      if (error) throw error;
    }

    res.json({ enabled: true });
  } catch (error: any) {
    console.error('Error enabling Aegis:', error);
    res.status(500).json({ error: error.message || 'Failed to enable Aegis' });
  }
});


// GET /api/aegis/threads/:organizationId - List chat threads
router.get('/threads/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const { data: threads, error } = await supabase
      .from('aegis_chat_threads')
      .select('*')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .order('updated_at', { ascending: false });

    if (error) throw error;

    res.json(threads || []);
  } catch (error: any) {
    console.error('Error fetching threads:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch threads' });
  }
});

// GET /api/aegis/threads/:threadId/messages - Get thread messages
router.get('/threads/:threadId/messages', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { threadId } = req.params;

    // Verify thread belongs to user
    const { data: thread } = await supabase
      .from('aegis_chat_threads')
      .select('organization_id, user_id')
      .eq('id', threadId)
      .single();

    if (!thread || thread.user_id !== userId) {
      return res.status(404).json({ error: 'Thread not found or access denied' });
    }

    const { data: messages, error } = await supabase
      .from('aegis_chat_messages')
      .select('*')
      .eq('thread_id', threadId)
      .order('created_at', { ascending: true });

    if (error) throw error;

    res.json(messages || []);
  } catch (error: any) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch messages' });
  }
});

// POST /api/aegis/threads - Create new thread
router.post('/threads', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId, title } = req.body;

    if (!organizationId) {
      return res.status(400).json({ error: 'organizationId is required' });
    }

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const { data: thread, error } = await supabase
      .from('aegis_chat_threads')
      .insert({
        organization_id: organizationId,
        user_id: userId,
        title: title || 'New Conversation',
      })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json(thread);
  } catch (error: any) {
    console.error('Error creating thread:', error);
    res.status(500).json({ error: error.message || 'Failed to create thread' });
  }
});

// GET /api/aegis/activity/:organizationId - Get activity logs
router.get('/activity/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;
    const { start_date, end_date, limit = '100', offset = '0' } = req.query;

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    let query = supabase
      .from('aegis_activity_logs')
      .select('*')
      .eq('organization_id', organizationId)
      .order('timestamp', { ascending: false })
      .limit(parseInt(limit as string, 10))
      .range(parseInt(offset as string, 10), parseInt(offset as string, 10) + parseInt(limit as string, 10) - 1);

    if (start_date) {
      query = query.gte('timestamp', start_date as string);
    }
    if (end_date) {
      query = query.lte('timestamp', end_date as string);
    }

    const { data: logs, error } = await query;

    if (error) throw error;

    res.json(logs || []);
  } catch (error: any) {
    console.error('Error fetching activity logs:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch activity logs' });
  }
});

// GET /api/aegis/automations/:organizationId - List automations
router.get('/automations/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const { data: automations, error } = await supabase
      .from('aegis_automations')
      .select('*')
      .eq('organization_id', organizationId)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json(automations || []);
  } catch (error: any) {
    console.error('Error fetching automations:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch automations' });
  }
});

// POST /api/aegis/automations - Create automation
router.post('/automations', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId, name, description, schedule } = req.body;

    if (!organizationId || !name || !schedule) {
      return res.status(400).json({ error: 'organizationId, name, and schedule are required' });
    }

    // Check if user is admin or owner
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins and owners can create automations' });
    }

    // TODO: Parse schedule and calculate next_run_at
    const { data: automation, error } = await supabase
      .from('aegis_automations')
      .insert({
        organization_id: organizationId,
        name,
        description,
        schedule,
        enabled: true,
      })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json(automation);
  } catch (error: any) {
    console.error('Error creating automation:', error);
    res.status(500).json({ error: error.message || 'Failed to create automation' });
  }
});

// PUT /api/aegis/automations/:id - Update automation
router.put('/automations/:id', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { name, description, schedule, enabled } = req.body;

    // Get automation to check ownership
    const { data: automation } = await supabase
      .from('aegis_automations')
      .select('organization_id')
      .eq('id', id)
      .single();

    if (!automation) {
      return res.status(404).json({ error: 'Automation not found' });
    }

    // Check if user is admin or owner
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', automation.organization_id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins and owners can update automations' });
    }

    const updateData: any = {};
    if (name !== undefined) updateData.name = name;
    if (description !== undefined) updateData.description = description;
    if (schedule !== undefined) updateData.schedule = schedule;
    if (enabled !== undefined) updateData.enabled = enabled;

    const { data: updated, error } = await supabase
      .from('aegis_automations')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    res.json(updated);
  } catch (error: any) {
    console.error('Error updating automation:', error);
    res.status(500).json({ error: error.message || 'Failed to update automation' });
  }
});

// DELETE /api/aegis/automations/:id - Delete automation
router.delete('/automations/:id', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    // Get automation to check ownership
    const { data: automation } = await supabase
      .from('aegis_automations')
      .select('organization_id')
      .eq('id', id)
      .single();

    if (!automation) {
      return res.status(404).json({ error: 'Automation not found' });
    }

    // Check if user is admin or owner
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', automation.organization_id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins and owners can delete automations' });
    }

    const { error } = await supabase
      .from('aegis_automations')
      .delete()
      .eq('id', id);

    if (error) throw error;

    res.json({ message: 'Automation deleted' });
  } catch (error: any) {
    console.error('Error deleting automation:', error);
    res.status(500).json({ error: error.message || 'Failed to delete automation' });
  }
});

// POST /api/aegis/automations/:id/run - Run automation now
router.post('/automations/:id/run', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    // Get automation
    const { data: automation } = await supabase
      .from('aegis_automations')
      .select('*')
      .eq('id', id)
      .single();

    if (!automation) {
      return res.status(404).json({ error: 'Automation not found' });
    }

    // Check if user is admin or owner
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', automation.organization_id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins and owners can run automations' });
    }

    // Create a job to run immediately
    const { data: job, error: jobError } = await supabase
      .from('aegis_automation_jobs')
      .insert({
        automation_id: id,
        organization_id: automation.organization_id,
        status: 'pending',
        scheduled_for: new Date().toISOString(),
      })
      .select()
      .single();

    if (jobError) throw jobError;

    // TODO: Trigger queue processor to run this job immediately

    res.json({ message: 'Automation queued to run', job });
  } catch (error: any) {
    console.error('Error running automation:', error);
    res.status(500).json({ error: error.message || 'Failed to run automation' });
  }
});

// GET /api/aegis/inbox/:organizationId - Get inbox messages
router.get('/inbox/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const { data: messages, error } = await supabase
      .from('aegis_inbox')
      .select('*')
      .eq('organization_id', organizationId)
      .or(`user_id.is.null,user_id.eq.${userId}`)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json(messages || []);
  } catch (error: any) {
    console.error('Error fetching inbox:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch inbox' });
  }
});

// PUT /api/aegis/inbox/:id/read - Mark message as read
router.put('/inbox/:id/read', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    // Get message to verify access
    const { data: message } = await supabase
      .from('aegis_inbox')
      .select('organization_id, user_id')
      .eq('id', id)
      .single();

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', message.organization_id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Check if message is for this user or org-wide
    if (message.user_id && message.user_id !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const { data: updated, error } = await supabase
      .from('aegis_inbox')
      .update({ read: true })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    res.json(updated);
  } catch (error: any) {
    console.error('Error marking message as read:', error);
    res.status(500).json({ error: error.message || 'Failed to mark message as read' });
  }
});


// ============================================================
// Task System Endpoints
// ============================================================

// GET /api/aegis/tasks/:organizationId -- list tasks
router.get('/tasks/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;
    const { status: statusFilter } = req.query;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();
    if (!membership) return res.status(404).json({ error: 'Not found' });

    let query = supabase
      .from('aegis_tasks')
      .select('*')
      .eq('organization_id', organizationId)
      .order('created_at', { ascending: false })
      .limit(50);

    if (statusFilter) query = query.eq('status', statusFilter as string);

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aegis/tasks/:organizationId/:taskId -- task detail with steps
router.get('/tasks/:organizationId/:taskId', async (req: AuthRequest, res) => {
  try {
    const { getTaskStatus } = await import('../lib/aegis/tasks');
    const task = await getTaskStatus(req.params.taskId);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    res.json(task);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/tasks/:taskId/approve -- approve a task
router.post('/tasks/:taskId/approve', async (req: AuthRequest, res) => {
  try {
    const { approveTask } = await import('../lib/aegis/tasks');
    await approveTask(req.params.taskId);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/tasks/:taskId/cancel -- cancel a task
router.post('/tasks/:taskId/cancel', async (req: AuthRequest, res) => {
  try {
    const { cancelTask } = await import('../lib/aegis/tasks');
    await cancelTask(req.params.taskId);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/tasks/:taskId/pause -- pause a task
router.post('/tasks/:taskId/pause', async (req: AuthRequest, res) => {
  try {
    const { pauseTask } = await import('../lib/aegis/tasks');
    await pauseTask(req.params.taskId);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// Approval Endpoints
// ============================================================

// GET /api/aegis/approvals/:organizationId -- list pending approvals
router.get('/approvals/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { data } = await supabase
      .from('aegis_approval_requests')
      .select('*')
      .eq('organization_id', req.params.organizationId)
      .eq('status', 'pending')
      .order('created_at', { ascending: false });
    res.json(data || []);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/approvals/:id/approve
router.post('/approvals/:id/approve', async (req: AuthRequest, res) => {
  try {
    const { error } = await supabase
      .from('aegis_approval_requests')
      .update({ status: 'approved', reviewed_by: req.user!.id, reviewed_at: new Date().toISOString() })
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/approvals/:id/reject
router.post('/approvals/:id/reject', async (req: AuthRequest, res) => {
  try {
    const { error } = await supabase
      .from('aegis_approval_requests')
      .update({ status: 'rejected', reviewed_by: req.user!.id, reviewed_at: new Date().toISOString() })
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// Memory Endpoints
// ============================================================

// GET /api/aegis/memory/:organizationId -- list memories
router.get('/memory/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { category, search, limit = '20', offset = '0' } = req.query;
    let query = supabase
      .from('aegis_memory')
      .select('id, category, key, content, created_at, created_by, metadata', { count: 'exact' })
      .eq('organization_id', req.params.organizationId)
      .order('created_at', { ascending: false })
      .range(parseInt(offset as string), parseInt(offset as string) + parseInt(limit as string) - 1);

    if (category) query = query.eq('category', category as string);
    if (search) query = query.or(`key.ilike.%${search}%,content.ilike.%${search}%`);

    const { data, count, error } = await query;
    if (error) throw error;
    res.json({ total: count || 0, memories: data || [] });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/memory -- create a manual memory (Teach Aegis)
router.post('/memory', async (req: AuthRequest, res) => {
  try {
    const { organizationId, category, key, content } = req.body;
    const { data, error } = await supabase
      .from('aegis_memory')
      .insert({
        organization_id: organizationId,
        category: category || 'knowledge',
        key,
        content,
        created_by: req.user!.id,
      })
      .select()
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/aegis/memory/:id -- update memory
router.put('/memory/:id', async (req: AuthRequest, res) => {
  try {
    const { key, content, category } = req.body;
    const updateData: any = {};
    if (key) updateData.key = key;
    if (content) updateData.content = content;
    if (category) updateData.category = category;
    const { data, error } = await supabase
      .from('aegis_memory')
      .update(updateData)
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/aegis/memory/:id -- delete memory
router.delete('/memory/:id', async (req: AuthRequest, res) => {
  try {
    await supabase.from('aegis_memory').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/aegis/memory/clear/:organizationId -- clear all memories
router.delete('/memory/clear/:organizationId', async (req: AuthRequest, res) => {
  try {
    await supabase.from('aegis_memory').delete().eq('organization_id', req.params.organizationId);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// Management Console Endpoints (Org Settings)
// ============================================================

// GET /api/aegis/settings/:organizationId -- get Aegis org settings
router.get('/settings/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { data } = await supabase
      .from('aegis_org_settings')
      .select('*')
      .eq('organization_id', req.params.organizationId)
      .single();
    res.json(data || {
      operating_mode: 'propose',
      monthly_budget: null,
      daily_budget: null,
      per_task_budget: 25,
      tool_permissions: {},
      pr_review_mode: 'advisory',
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/aegis/settings/:organizationId -- update settings
router.put('/settings/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { operating_mode, monthly_budget, daily_budget, per_task_budget, tool_permissions, default_delivery_channel, preferred_provider, preferred_model, pr_review_mode } = req.body;
    const updateData: any = { updated_at: new Date().toISOString() };
    if (operating_mode !== undefined) updateData.operating_mode = operating_mode;
    if (monthly_budget !== undefined) updateData.monthly_budget = monthly_budget;
    if (daily_budget !== undefined) updateData.daily_budget = daily_budget;
    if (per_task_budget !== undefined) updateData.per_task_budget = per_task_budget;
    if (tool_permissions !== undefined) updateData.tool_permissions = tool_permissions;
    if (default_delivery_channel !== undefined) updateData.default_delivery_channel = default_delivery_channel;
    if (preferred_provider !== undefined) updateData.preferred_provider = preferred_provider;
    if (preferred_model !== undefined) updateData.preferred_model = preferred_model;
    if (pr_review_mode !== undefined) updateData.pr_review_mode = pr_review_mode;

    const { data: existing } = await supabase
      .from('aegis_org_settings')
      .select('id')
      .eq('organization_id', req.params.organizationId)
      .single();

    let result;
    if (existing) {
      const { data, error } = await supabase
        .from('aegis_org_settings')
        .update(updateData)
        .eq('organization_id', req.params.organizationId)
        .select()
        .single();
      if (error) throw error;
      result = data;
    } else {
      const { data, error } = await supabase
        .from('aegis_org_settings')
        .insert({ organization_id: req.params.organizationId, ...updateData })
        .select()
        .single();
      if (error) throw error;
      result = data;
    }
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aegis/tool-executions/:organizationId -- audit log
router.get('/tool-executions/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { limit = '50', offset = '0', user_id, category, tool_name, start_date, end_date } = req.query;
    let query = supabase
      .from('aegis_tool_executions')
      .select('*', { count: 'exact' })
      .eq('organization_id', req.params.organizationId)
      .order('created_at', { ascending: false })
      .range(parseInt(offset as string), parseInt(offset as string) + parseInt(limit as string) - 1);

    if (user_id) query = query.eq('user_id', user_id as string);
    if (category) query = query.eq('tool_category', category as string);
    if (tool_name) query = query.eq('tool_name', tool_name as string);
    if (start_date) query = query.gte('created_at', start_date as string);
    if (end_date) query = query.lte('created_at', end_date as string);

    const { data, count, error } = await query;
    if (error) throw error;
    res.json({ total: count || 0, executions: data || [] });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aegis/spending/:organizationId -- spending data
router.get('/spending/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { data: settings } = await supabase
      .from('aegis_org_settings')
      .select('monthly_budget, daily_budget, per_task_budget')
      .eq('organization_id', req.params.organizationId)
      .single();

    // Get monthly spending from ai_usage_logs
    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);

    const { data: monthlyLogs } = await supabase
      .from('ai_usage_logs')
      .select('estimated_cost, feature, created_at')
      .eq('organization_id', req.params.organizationId)
      .gte('created_at', monthStart.toISOString());

    const monthlySpend = (monthlyLogs || []).reduce((sum, l) => sum + (l.estimated_cost || 0), 0);

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const dailySpend = (monthlyLogs || [])
      .filter(l => new Date(l.created_at) >= todayStart)
      .reduce((sum, l) => sum + (l.estimated_cost || 0), 0);

    // Spending by category
    const byCategory: Record<string, number> = {};
    for (const log of monthlyLogs || []) {
      byCategory[log.feature] = (byCategory[log.feature] || 0) + (log.estimated_cost || 0);
    }

    res.json({
      monthly: { spent: monthlySpend, budget: settings?.monthly_budget || null },
      daily: { spent: dailySpend, budget: settings?.daily_budget || null },
      perTask: { limit: settings?.per_task_budget || 25 },
      byCategory,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aegis/usage-stats/:organizationId -- usage analytics
router.get('/usage-stats/:organizationId', async (req: AuthRequest, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();

    const { data: messages } = await supabase
      .from('aegis_chat_messages')
      .select('created_at, role')
      .eq('role', 'user')
      .gte('created_at', thirtyDaysAgo);

    const { data: toolExecs } = await supabase
      .from('aegis_tool_executions')
      .select('tool_name, success, created_at')
      .eq('organization_id', req.params.organizationId)
      .gte('created_at', thirtyDaysAgo);

    const { data: fixes } = await supabase
      .from('project_security_fixes')
      .select('status')
      .eq('organization_id', req.params.organizationId)
      .gte('created_at', thirtyDaysAgo);

    const totalMessages = messages?.length || 0;
    const fixSuccessRate = fixes?.length
      ? fixes.filter(f => f.status === 'completed' || f.status === 'merged').length / fixes.length
      : 0;

    // Most used tools
    const toolCounts: Record<string, number> = {};
    for (const exec of toolExecs || []) {
      toolCounts[exec.tool_name] = (toolCounts[exec.tool_name] || 0) + 1;
    }
    const topTools = Object.entries(toolCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, count]) => ({ name, count }));

    res.json({
      messagesThisMonth: totalMessages,
      avgMessagesPerDay: Math.round(totalMessages / 30),
      fixSuccessRate: Math.round(fixSuccessRate * 100),
      topTools,
      totalToolExecutions: toolExecs?.length || 0,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// Security Debt Endpoints
// ============================================================

// ============================================================
// Sprint Orchestration
// ============================================================

// POST /api/aegis/sprints/:organizationId -- create a security sprint
router.post('/sprints/:organizationId', async (req: AuthRequest, res) => {
  try {
    if (!req.user?.id) return res.status(401).json({ error: 'Unauthorized' });
    const orgId = req.params.organizationId;
    const canTrigger = await hasPermission(orgId, req.user.id, 'trigger_fix');
    if (!canTrigger) return res.status(403).json({ error: 'Requires trigger_fix permission' });

    const { createSecuritySprint } = await import('../lib/aegis/sprint-orchestrator');
    const result = await createSecuritySprint({
      ...req.body,
      organizationId: orgId,
      userId: req.user.id,
    });

    if (result.error) return res.status(400).json({ error: result.error });
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/aegis/sprints/:organizationId/confirm -- confirm interactive sprint
router.post('/sprints/:organizationId/confirm', async (req: AuthRequest, res) => {
  try {
    if (!req.user?.id) return res.status(401).json({ error: 'Unauthorized' });
    const orgId = req.params.organizationId;
    const canTrigger = await hasPermission(orgId, req.user.id, 'trigger_fix');
    if (!canTrigger) return res.status(403).json({ error: 'Requires trigger_fix permission' });

    const { confirmInteractiveSprint } = await import('../lib/aegis/sprint-orchestrator');
    const result = await confirmInteractiveSprint(orgId, req.user.id, req.body.candidates);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aegis/sprints/:organizationId/:taskId/summary -- sprint results
router.get('/sprints/:organizationId/:taskId/summary', async (req: AuthRequest, res) => {
  try {
    const { getSprintSummary } = await import('../lib/aegis/sprint-orchestrator');
    const summary = await getSprintSummary(req.params.taskId);
    if (!summary) return res.status(404).json({ error: 'Sprint not found' });
    res.json(summary);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aegis/debt/:organizationId -- debt score + history
router.get('/debt/:organizationId', async (req: AuthRequest, res) => {
  try {
    const { projectId, days = '30' } = req.query;
    const { computeDebtScore, getDebtHistory, getDebtVelocity } = await import('../lib/aegis/security-debt');

    const [score, history, velocity] = await Promise.all([
      computeDebtScore(req.params.organizationId, projectId as string | undefined),
      getDebtHistory(req.params.organizationId, projectId as string | undefined, parseInt(days as string)),
      getDebtVelocity(req.params.organizationId, projectId as string | undefined),
    ]);

    res.json({ score, history, velocity });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// Slack Bot Endpoints
// ============================================================

// POST /api/aegis/slack/events -- Slack Events API
router.post('/slack/events', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;

    // URL verification challenge
    if (body.type === 'url_verification') {
      return res.json({ challenge: body.challenge });
    }

    // Ack immediately (Slack 3-second requirement)
    res.status(200).send();

    // Process async
    const { handleSlackEvent } = await import('../lib/aegis/slack-bot');
    await handleSlackEvent(body, '', {
      signature: req.headers['x-slack-signature'] as string,
      timestamp: req.headers['x-slack-request-timestamp'] as string,
    }).catch(err => console.error('[Aegis Slack] Event error:', err));
  } catch (error: any) {
    console.error('[Aegis Slack] Error:', error);
    if (!res.headersSent) res.status(500).send();
  }
});

// POST /api/aegis/slack/interactions -- Slack Interactive Components
router.post('/slack/interactions', express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const payload = JSON.parse(req.body.payload);
    res.status(200).send();

    const { handleSlackInteraction } = await import('../lib/aegis/slack-bot');
    await handleSlackInteraction(payload, '', {
      signature: req.headers['x-slack-signature'] as string,
      timestamp: req.headers['x-slack-request-timestamp'] as string,
    }).catch(err => console.error('[Aegis Slack] Interaction error:', err));
  } catch (error: any) {
    console.error('[Aegis Slack] Interaction error:', error);
    if (!res.headersSent) res.status(500).send();
  }
});

// GET /api/aegis/threads-by-project/:organizationId -- threads filtered by project
router.get('/threads-by-project/:organizationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId } = req.params;
    const projectId = req.query.projectId as string;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();
    if (!membership) return res.status(404).json({ error: 'Not found' });

    let query = supabase
      .from('aegis_chat_threads')
      .select('*')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .order('updated_at', { ascending: false });

    if (projectId) {
      query = query.eq('project_id', projectId);
    }

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (error: any) {
    console.error('Error fetching threads by project:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch threads' });
  }
});

export default router;

