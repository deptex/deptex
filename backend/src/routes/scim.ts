import { Router, Request, Response, NextFunction } from 'express';
import { createHash, randomBytes } from 'crypto';
import { supabase } from '../lib/supabase';

const router = Router();

interface SCIMRequest extends Request {
  scimOrg?: { id: string; configId: string };
}

async function authenticateSCIM(req: SCIMRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      detail: 'Missing or invalid authorization',
      status: '401',
    });
  }

  const token = authHeader.substring(7);
  const hash = createHash('sha256').update(token).digest('hex');

  const { data: config } = await supabase
    .from('organization_scim_configs')
    .select('id, organization_id, is_active')
    .eq('scim_token_hash', hash)
    .eq('is_active', true)
    .single();

  if (!config) {
    return res.status(401).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      detail: 'Invalid or inactive SCIM token',
      status: '401',
    });
  }

  req.scimOrg = { id: config.organization_id, configId: config.id };
  next();
}

router.get('/ServiceProviderConfig', (_req, res) => {
  res.json({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 200 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      { type: 'oauthbearertoken', name: 'OAuth Bearer Token', description: 'SCIM bearer token authentication' },
    ],
  });
});

router.get('/Schemas', (_req, res) => {
  res.json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: 1,
    Resources: [
      {
        id: 'urn:ietf:params:scim:schemas:core:2.0:User',
        name: 'User',
        description: 'User resource',
        attributes: [
          { name: 'userName', type: 'string', required: true, mutability: 'readWrite' },
          { name: 'displayName', type: 'string', required: false, mutability: 'readWrite' },
          { name: 'active', type: 'boolean', required: false, mutability: 'readWrite' },
        ],
      },
    ],
  });
});

router.get('/Users', authenticateSCIM, async (req: SCIMRequest, res) => {
  try {
    const orgId = req.scimOrg!.id;
    const startIndex = parseInt(req.query.startIndex as string) || 1;
    const count = Math.min(parseInt(req.query.count as string) || 100, 200);
    const filter = req.query.filter as string;

    let query = supabase
      .from('scim_user_mappings')
      .select('*', { count: 'exact' })
      .eq('organization_id', orgId)
      .range(startIndex - 1, startIndex - 1 + count - 1)
      .order('provisioned_at', { ascending: false });

    if (filter) {
      const emailMatch = filter.match(/userName\s+eq\s+"([^"]+)"/i);
      if (emailMatch) {
        query = query.eq('email', emailMatch[1]);
      }
    }

    const { data: mappings, count: totalCount, error } = await query;

    if (error) {
      return res.status(500).json({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'Failed to list users',
        status: '500',
      });
    }

    res.json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: totalCount || 0,
      startIndex,
      itemsPerPage: count,
      Resources: (mappings || []).map(toSCIMUser),
    });
  } catch (error) {
    res.status(500).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], detail: 'Internal error', status: '500' });
  }
});

router.post('/Users', authenticateSCIM, async (req: SCIMRequest, res) => {
  try {
    const orgId = req.scimOrg!.id;
    const { userName, displayName, externalId, active } = req.body;

    if (!userName) {
      return res.status(400).json({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'userName is required',
        status: '400',
      });
    }

    const email = userName.toLowerCase();
    const extId = externalId || email;

    const { data: existing } = await supabase
      .from('scim_user_mappings')
      .select('id')
      .eq('organization_id', orgId)
      .eq('scim_external_id', extId)
      .single();

    if (existing) {
      return res.status(409).json({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'User already exists',
        status: '409',
      });
    }

    const { data: existingUsers } = await supabase.auth.admin.listUsers();
    let user = existingUsers?.users?.find((u: any) => u.email?.toLowerCase() === email);

    if (!user) {
      const { data: newUser, error: createErr } = await supabase.auth.admin.createUser({
        email,
        email_confirm: true,
        user_metadata: { full_name: displayName, scim_provisioned: true },
      });
      if (createErr || !newUser?.user) {
        return res.status(500).json({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
          detail: 'Failed to create user',
          status: '500',
        });
      }
      user = newUser.user;
    }

    await supabase.from('organization_members').upsert({
      organization_id: orgId,
      user_id: user.id,
      role: 'member',
    }, { onConflict: 'organization_id,user_id' });

    const { data: mapping, error: mapErr } = await supabase
      .from('scim_user_mappings')
      .insert({
        organization_id: orgId,
        scim_external_id: extId,
        user_id: user.id,
        email,
        display_name: displayName || null,
        is_active: active !== false,
      })
      .select()
      .single();

    if (mapErr) {
      return res.status(500).json({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'Failed to create SCIM mapping',
        status: '500',
      });
    }

    try {
      const { logSecurityEvent } = require('../lib/security-audit');
      await logSecurityEvent({
        organizationId: orgId,
        action: 'scim_user_provisioned',
        targetType: 'user',
        targetId: user.id,
        req,
        metadata: { email, external_id: extId },
      });
    } catch {}

    res.status(201).json(toSCIMUser(mapping));
  } catch (error) {
    res.status(500).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], detail: 'Internal error', status: '500' });
  }
});

router.get('/Users/:id', authenticateSCIM, async (req: SCIMRequest, res) => {
  try {
    const orgId = req.scimOrg!.id;
    const { data: mapping } = await supabase
      .from('scim_user_mappings')
      .select('*')
      .eq('organization_id', orgId)
      .eq('id', req.params.id)
      .single();

    if (!mapping) {
      return res.status(404).json({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'User not found',
        status: '404',
      });
    }

    res.json(toSCIMUser(mapping));
  } catch (error) {
    res.status(500).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], detail: 'Internal error', status: '500' });
  }
});

router.patch('/Users/:id', authenticateSCIM, async (req: SCIMRequest, res) => {
  try {
    const orgId = req.scimOrg!.id;

    const { data: mapping } = await supabase
      .from('scim_user_mappings')
      .select('*')
      .eq('organization_id', orgId)
      .eq('id', req.params.id)
      .single();

    if (!mapping) {
      return res.status(404).json({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'User not found',
        status: '404',
      });
    }

    const updates: Record<string, unknown> = {};
    const ops = req.body.Operations || [];

    for (const op of ops) {
      if (op.op === 'Replace' || op.op === 'replace') {
        if (op.path === 'active' || op.value?.active !== undefined) {
          const newActive = op.path === 'active' ? op.value : op.value.active;
          updates.is_active = newActive;

          if (!newActive && mapping.user_id) {
            await supabase
              .from('organization_members')
              .delete()
              .eq('organization_id', orgId)
              .eq('user_id', mapping.user_id);

            updates.deprovisioned_at = new Date().toISOString();

            try {
              const { logSecurityEvent } = require('../lib/security-audit');
              await logSecurityEvent({
                organizationId: orgId,
                action: 'scim_user_deprovisioned',
                targetType: 'user',
                targetId: mapping.user_id,
                req,
                metadata: { email: mapping.email, external_id: mapping.scim_external_id },
              });
            } catch {}
          }
        }
        if (op.path === 'displayName' || op.value?.displayName) {
          updates.display_name = op.path === 'displayName' ? op.value : op.value.displayName;
        }
      }
    }

    if (Object.keys(updates).length > 0) {
      await supabase
        .from('scim_user_mappings')
        .update(updates)
        .eq('id', req.params.id);
    }

    const { data: updated } = await supabase
      .from('scim_user_mappings')
      .select('*')
      .eq('id', req.params.id)
      .single();

    res.json(toSCIMUser(updated || mapping));
  } catch (error) {
    res.status(500).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], detail: 'Internal error', status: '500' });
  }
});

router.delete('/Users/:id', authenticateSCIM, async (req: SCIMRequest, res) => {
  try {
    const orgId = req.scimOrg!.id;

    const { data: mapping } = await supabase
      .from('scim_user_mappings')
      .select('*')
      .eq('organization_id', orgId)
      .eq('id', req.params.id)
      .single();

    if (!mapping) {
      return res.status(404).json({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: 'User not found',
        status: '404',
      });
    }

    if (mapping.user_id) {
      await supabase
        .from('organization_members')
        .delete()
        .eq('organization_id', orgId)
        .eq('user_id', mapping.user_id);
    }

    await supabase
      .from('scim_user_mappings')
      .update({ is_active: false, deprovisioned_at: new Date().toISOString() })
      .eq('id', req.params.id);

    try {
      const { logSecurityEvent } = require('../lib/security-audit');
      await logSecurityEvent({
        organizationId: orgId,
        action: 'scim_user_deprovisioned',
        targetType: 'user',
        targetId: mapping.user_id || req.params.id,
        req,
        metadata: { email: mapping.email },
      });
    } catch {}

    res.status(204).send();
  } catch (error) {
    res.status(500).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], detail: 'Internal error', status: '500' });
  }
});

function toSCIMUser(mapping: any) {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: mapping.id,
    externalId: mapping.scim_external_id,
    userName: mapping.email,
    displayName: mapping.display_name || mapping.email,
    active: mapping.is_active,
    meta: {
      resourceType: 'User',
      created: mapping.provisioned_at,
      lastModified: mapping.deprovisioned_at || mapping.provisioned_at,
    },
  };
}

export default router;
