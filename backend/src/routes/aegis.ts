import express from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { executeMessage, ExecutionContext } from '../lib/aegis/executor';
import '../lib/aegis/actions/init'; // Initialize all actions

const router = express.Router();

// All routes require authentication
router.use(authenticateUser);

// Helper to check if Aegis is enabled for an organization
async function isAegisEnabled(organizationId: string): Promise<boolean> {
  const { data } = await supabase
    .from('aegis_config')
    .select('enabled')
    .eq('organization_id', organizationId)
    .single();
  
  return data?.enabled === true;
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

// POST /api/aegis/handle - Handle chat message
router.post('/handle', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { organizationId, threadId, message } = req.body;

    if (!organizationId || !message) {
      return res.status(400).json({ error: 'organizationId and message are required' });
    }

    // Check if Aegis is enabled
    const enabled = await isAegisEnabled(organizationId);
    if (!enabled) {
      return res.status(403).json({ error: 'Aegis is not enabled for this organization' });
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

    // Get organization name
    const { data: org } = await supabase
      .from('organizations')
      .select('name')
      .eq('id', organizationId)
      .single();

    if (!org) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Get conversation history if threadId is provided
    let conversationHistory: Array<{ role: 'user' | 'assistant'; content: string }> = [];
    if (threadId) {
      const { data: messages } = await supabase
        .from('aegis_chat_messages')
        .select('role, content')
        .eq('thread_id', threadId)
        .order('created_at', { ascending: true });

      if (messages) {
        conversationHistory = messages.map(m => ({
          role: m.role as 'user' | 'assistant',
          content: m.content,
        }));
      }
    }

    // Execute message
    const context: ExecutionContext = {
      organizationId,
      userId,
      organizationName: org.name,
      threadId,
    };

    const result = await executeMessage(message, context, conversationHistory);

    // Save user message
    let currentThreadId = threadId;
    if (!currentThreadId) {
      // Create new thread
      const title = message.substring(0, 50) + (message.length > 50 ? '...' : '');
      const { data: newThread, error: threadError } = await supabase
        .from('aegis_chat_threads')
        .insert({
          organization_id: organizationId,
          user_id: userId,
          title,
        })
        .select()
        .single();

      if (threadError) throw threadError;
      currentThreadId = newThread.id;
    } else {
      // Update thread updated_at
      await supabase
        .from('aegis_chat_threads')
        .update({ updated_at: new Date().toISOString() })
        .eq('id', currentThreadId);
    }

    // Save user message
    await supabase
      .from('aegis_chat_messages')
      .insert({
        thread_id: currentThreadId,
        role: 'user',
        content: message,
      });

    // Save assistant response
    // The executor now always returns a natural language message, even for actions
    const assistantContent = result.message || 'I apologize, but I could not generate a response.';

    await supabase
      .from('aegis_chat_messages')
      .insert({
        thread_id: currentThreadId,
        role: 'assistant',
        content: assistantContent,
        metadata: result.type === 'action' ? { action: result.action, result: result.result } : {},
      });

    res.json({
      threadId: currentThreadId,
      type: result.type,
      message: assistantContent, // Always return the formatted message content
      action: result.type === 'action' ? result.action : undefined,
      result: result.type === 'action' ? result.result : undefined,
    });
  } catch (error: any) {
    console.error('Error handling Aegis message:', error);
    res.status(500).json({ error: error.message || 'Failed to handle message' });
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

export default router;

