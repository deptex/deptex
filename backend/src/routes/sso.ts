import { Router, Request, Response } from 'express';
import { createHash, randomBytes } from 'crypto';
import { supabase } from '../lib/supabase';

const router = Router();

router.get('/login', async (req: Request, res: Response) => {
  try {
    const email = req.query.email as string;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    const domain = email.split('@')[1].toLowerCase();

    const { data: ssoProvider } = await supabase
      .from('organization_sso_providers')
      .select('*')
      .eq('domain', domain)
      .eq('is_active', true)
      .eq('domain_verified', true)
      .single();

    if (!ssoProvider) {
      return res.status(404).json({ error: 'No SSO configured for this domain' });
    }

    try {
      const { SAML } = require('@node-saml/node-saml');
      const saml = new SAML({
        callbackUrl: `${process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 3001}`}/api/sso/callback`,
        entryPoint: ssoProvider.sso_url,
        issuer: 'deptex-app',
        cert: ssoProvider.certificate,
        wantAssertionsSigned: true,
        wantAuthnResponseSigned: true,
      });

      const loginUrl = await saml.getAuthorizeUrlAsync('', req.headers.host || '', {});
      return res.redirect(loginUrl);
    } catch (samlErr: any) {
      console.error('[SSO] SAML redirect error:', samlErr);
      return res.status(500).json({ error: 'Failed to initiate SSO login' });
    }
  } catch (error: any) {
    console.error('[SSO] Login error:', error);
    return res.status(500).json({ error: 'SSO login failed' });
  }
});

router.post('/callback', async (req: Request, res: Response) => {
  try {
    const samlResponse = req.body.SAMLResponse;
    if (!samlResponse) {
      return res.status(400).json({ error: 'Missing SAML response' });
    }

    const relayState = req.body.RelayState;
    let ssoProvider: any = null;

    const { data: providers } = await supabase
      .from('organization_sso_providers')
      .select('*')
      .eq('is_active', true)
      .eq('domain_verified', true);

    if (!providers || providers.length === 0) {
      return res.status(400).json({ error: 'No active SSO providers found' });
    }

    let profile: any = null;

    for (const provider of providers) {
      try {
        const { SAML } = require('@node-saml/node-saml');
        const saml = new SAML({
          callbackUrl: `${process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 3001}`}/api/sso/callback`,
          entryPoint: provider.sso_url,
          issuer: 'deptex-app',
          cert: provider.certificate,
          wantAssertionsSigned: true,
          wantAuthnResponseSigned: true,
        });

        const result = await saml.validatePostResponseAsync(req.body);
        if (result && result.profile) {
          profile = result.profile;
          ssoProvider = provider;
          break;
        }
      } catch {
        continue;
      }
    }

    if (!profile || !ssoProvider) {
      return res.status(401).json({ error: 'Invalid SAML assertion' });
    }

    const email = (profile.email || profile.nameID || '').toLowerCase();
    if (!email) {
      return res.status(400).json({ error: 'No email in SAML assertion' });
    }

    const { data: existingUsers } = await supabase.auth.admin.listUsers();
    let user = existingUsers?.users?.find((u: any) => u.email?.toLowerCase() === email);

    if (!user && ssoProvider.jit_provisioning) {
      const { data: newUser, error: createErr } = await supabase.auth.admin.createUser({
        email,
        email_confirm: true,
        user_metadata: {
          full_name: profile.displayName || profile.firstName
            ? `${profile.firstName || ''} ${profile.lastName || ''}`.trim()
            : undefined,
          sso_provider: ssoProvider.provider_type,
        },
      });
      if (createErr || !newUser?.user) {
        console.error('[SSO] JIT provisioning failed:', createErr);
        return res.status(500).json({ error: 'Failed to provision user' });
      }
      user = newUser.user;

      const defaultRoleId = ssoProvider.default_role_id;
      let roleName = 'member';
      if (defaultRoleId) {
        const { data: role } = await supabase
          .from('organization_roles')
          .select('name')
          .eq('id', defaultRoleId)
          .single();
        if (role) roleName = role.name;
      }

      await supabase.from('organization_members').upsert({
        organization_id: ssoProvider.organization_id,
        user_id: user.id,
        role: roleName,
      }, { onConflict: 'organization_id,user_id' });
    } else if (!user) {
      return res.status(403).json({ error: 'Account not provisioned and JIT is disabled' });
    }

    const groups: string[] = profile.groups || profile['memberOf'] || [];
    if (groups.length > 0 && ssoProvider.group_role_mapping) {
      const mapping = ssoProvider.group_role_mapping as Record<string, string>;
      for (const group of groups) {
        const roleId = mapping[group];
        if (roleId) {
          const { data: role } = await supabase
            .from('organization_roles')
            .select('name')
            .eq('id', roleId)
            .single();
          if (role) {
            await supabase
              .from('organization_members')
              .update({ role: role.name })
              .eq('organization_id', ssoProvider.organization_id)
              .eq('user_id', user.id);
            break;
          }
        }
      }
    }

    const { data: linkData, error: linkErr } = await supabase.auth.admin.generateLink({
      type: 'magiclink',
      email,
    });

    if (linkErr || !linkData) {
      console.error('[SSO] Magic link generation failed:', linkErr);
      return res.status(500).json({ error: 'Failed to create session' });
    }

    const linkUrl = new URL(linkData.properties?.action_link || '');
    const token = linkUrl.searchParams.get('token') || linkUrl.hash?.replace('#', '');

    try {
      const { logSecurityEvent } = require('../../../ee/backend/lib/security-audit');
      await logSecurityEvent({
        organizationId: ssoProvider.organization_id,
        actorId: user.id,
        action: 'sso_login',
        req,
        metadata: { provider_type: ssoProvider.provider_type, email, domain: ssoProvider.domain },
      });
    } catch {}

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const redirectUrl = `${frontendUrl}/sso-callback?token=${encodeURIComponent(token || '')}&type=magiclink`;
    return res.redirect(redirectUrl);
  } catch (error: any) {
    console.error('[SSO] Callback error:', error);
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    return res.redirect(`${frontendUrl}/login?sso_error=callback_failed`);
  }
});

router.get('/metadata', async (_req: Request, res: Response) => {
  const callbackUrl = `${process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 3001}`}/api/sso/callback`;
  const metadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="deptex-app">
  <SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${callbackUrl}"
      index="0" isDefault="true"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
  </SPSSODescriptor>
</EntityDescriptor>`;

  res.set('Content-Type', 'application/xml');
  res.send(metadata);
});

router.post('/bypass', async (req: Request, res: Response) => {
  try {
    const { token, email } = req.body;
    if (!token || !email) {
      return res.status(400).json({ error: 'Token and email are required' });
    }

    const tokenHash = createHash('sha256').update(token).digest('hex');

    const { data: bypassRow } = await supabase
      .from('organization_sso_bypass_tokens')
      .select('*, organizations!inner(id)')
      .eq('token_hash', tokenHash)
      .is('used_at', null)
      .gt('expires_at', new Date().toISOString())
      .single();

    if (!bypassRow) {
      return res.status(401).json({ error: 'Invalid or expired bypass token' });
    }

    await supabase
      .from('organization_sso_bypass_tokens')
      .update({ used_at: new Date().toISOString() })
      .eq('id', bypassRow.id);

    const { data: linkData, error: linkErr } = await supabase.auth.admin.generateLink({
      type: 'magiclink',
      email,
    });

    if (linkErr || !linkData) {
      return res.status(500).json({ error: 'Failed to generate login link' });
    }

    const linkUrl = new URL(linkData.properties?.action_link || '');
    const magicToken = linkUrl.searchParams.get('token') || '';

    try {
      const { logSecurityEvent } = require('../../../ee/backend/lib/security-audit');
      await logSecurityEvent({
        organizationId: bypassRow.organization_id,
        action: 'sso_bypass_used',
        req,
        metadata: { email },
        severity: 'warning',
      });
    } catch {}

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.json({
      redirect: `${frontendUrl}/sso-callback?token=${encodeURIComponent(magicToken)}&type=magiclink`,
    });
  } catch (error: any) {
    console.error('[SSO] Bypass error:', error);
    return res.status(500).json({ error: 'Bypass login failed' });
  }
});

router.get('/check', async (req: Request, res: Response) => {
  try {
    const email = req.query.email as string;
    if (!email || !email.includes('@')) {
      return res.json({ has_sso: false });
    }

    const domain = email.split('@')[1].toLowerCase();
    const { data: ssoProvider } = await supabase
      .from('organization_sso_providers')
      .select('id, provider_type, display_name, enforce_sso')
      .eq('domain', domain)
      .eq('is_active', true)
      .eq('domain_verified', true)
      .single();

    if (!ssoProvider) {
      return res.json({ has_sso: false });
    }

    res.json({
      has_sso: true,
      provider_type: ssoProvider.provider_type,
      display_name: ssoProvider.display_name,
      enforce_sso: ssoProvider.enforce_sso,
    });
  } catch {
    return res.json({ has_sso: false });
  }
});

export default router;
