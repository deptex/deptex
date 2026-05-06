// @ts-nocheck
/**
 * Phase 27 IaC + Container v2: organization-scoped registry credentials.
 *
 * Mounted under /api/organizations in src/index.ts. Routes:
 *   GET    /:id/registry-credentials                       — list (metadata only)
 *   POST   /:id/registry-credentials                       — create (encrypts)
 *   PATCH  /:id/registry-credentials/:credId               — display_name only
 *   PATCH  /:id/registry-credentials/:credId/rotate        — re-encrypt + bump key version
 *   DELETE /:id/registry-credentials/:credId               — soft-detaches images via FK
 *   POST   /:id/registry-credentials/:credId/test          — decrypt-shape dry-run
 *
 * Encryption: AES-256-GCM via lib/ai/encryption.ts. The encrypted column
 * stores JSON.stringify(plaintextCredentials) — one secret blob per row.
 * GET never returns encrypted_credentials. Decrypt errors log full stack
 * to console.error and surface as `{ error: 'credential_operation_failed' }`
 * per feedback_no_raw_errors_to_users.md.
 *
 * RBAC: every mutating route is gated by checkOrgManageIntegrations
 * (lib/rbac.ts) — same gate as BYOK provider keys. Read uses checkOrgAccess.
 */

import express from 'express';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { encryptApiKey, decryptApiKey, isEncryptionConfigured } from '../lib/ai/encryption';
import { checkOrgAccess, checkOrgManageIntegrations } from '../lib/rbac';
import { createActivity } from '../lib/activities';

const router = express.Router();

// ============================================================================
// Schema validation — mirrors phase27b_iac_v2_registries.sql CHECK constraints
// ============================================================================

const REGISTRY_TYPES = [
  'ghcr', 'ecr', 'gcr', 'acr', 'dockerhub', 'quay', 'harbor', 'jfrog', 'custom',
] as const;
type RegistryType = typeof REGISTRY_TYPES[number];

const CREDENTIAL_SHAPES = [
  'username_password', 'aws_keys', 'gcp_service_account_key',
  'azure_service_principal', 'token',
] as const;
type CredentialShape = typeof CREDENTIAL_SHAPES[number];

// (registry_type, credential_shape) pairs allowed by orc_registry_shape_pair_check.
const VALID_PAIRS: Array<[RegistryType, CredentialShape]> = [
  ['ghcr', 'username_password'], ['ghcr', 'token'],
  ['ecr', 'aws_keys'],
  ['gcr', 'gcp_service_account_key'],
  ['acr', 'azure_service_principal'], ['acr', 'username_password'],
  ['dockerhub', 'username_password'], ['dockerhub', 'token'],
  ['quay', 'username_password'], ['quay', 'token'],
  ['harbor', 'username_password'],
  ['jfrog', 'username_password'], ['jfrog', 'token'],
  ['custom', 'username_password'], ['custom', 'token'],
];

const REGISTRY_URL_REQUIRED: ReadonlyArray<RegistryType> = ['harbor', 'jfrog', 'custom'];

function isValidPair(rt: string, cs: string): boolean {
  return VALID_PAIRS.some(([a, b]) => a === rt && b === cs);
}

type CredentialPlaintext =
  | { shape: 'username_password'; username: string; password: string }
  | { shape: 'aws_keys'; access_key_id: string; secret_access_key: string; session_token?: string; region: string }
  | { shape: 'gcp_service_account_key'; service_account_json: string }
  | { shape: 'azure_service_principal'; client_id: string; client_secret: string; tenant_id: string }
  | { shape: 'token'; token: string };

function validatePlaintext(c: any): { ok: true; value: CredentialPlaintext } | { ok: false; error: string } {
  if (!c || typeof c !== 'object') return { ok: false, error: 'credentials must be an object' };
  const shape = c.shape;
  if (!CREDENTIAL_SHAPES.includes(shape)) {
    return { ok: false, error: `credentials.shape must be one of ${CREDENTIAL_SHAPES.join(', ')}` };
  }
  switch (shape) {
    case 'username_password':
      if (typeof c.username !== 'string' || !c.username) return { ok: false, error: 'username required' };
      if (typeof c.password !== 'string' || !c.password) return { ok: false, error: 'password required' };
      return { ok: true, value: { shape, username: c.username, password: c.password } };
    case 'aws_keys':
      if (typeof c.access_key_id !== 'string' || !c.access_key_id) return { ok: false, error: 'access_key_id required' };
      if (typeof c.secret_access_key !== 'string' || !c.secret_access_key) return { ok: false, error: 'secret_access_key required' };
      if (typeof c.region !== 'string' || !c.region) return { ok: false, error: 'region required' };
      if (c.session_token !== undefined && typeof c.session_token !== 'string') return { ok: false, error: 'session_token must be a string' };
      return {
        ok: true,
        value: {
          shape,
          access_key_id: c.access_key_id,
          secret_access_key: c.secret_access_key,
          region: c.region,
          ...(c.session_token ? { session_token: c.session_token } : {}),
        },
      };
    case 'gcp_service_account_key':
      if (typeof c.service_account_json !== 'string' || !c.service_account_json) return { ok: false, error: 'service_account_json required' };
      try { JSON.parse(c.service_account_json); } catch { return { ok: false, error: 'service_account_json must be valid JSON' }; }
      return { ok: true, value: { shape, service_account_json: c.service_account_json } };
    case 'azure_service_principal':
      if (typeof c.client_id !== 'string' || !c.client_id) return { ok: false, error: 'client_id required' };
      if (typeof c.client_secret !== 'string' || !c.client_secret) return { ok: false, error: 'client_secret required' };
      if (typeof c.tenant_id !== 'string' || !c.tenant_id) return { ok: false, error: 'tenant_id required' };
      return { ok: true, value: { shape, client_id: c.client_id, client_secret: c.client_secret, tenant_id: c.tenant_id } };
    case 'token':
      if (typeof c.token !== 'string' || !c.token) return { ok: false, error: 'token required' };
      return { ok: true, value: { shape, token: c.token } };
  }
}

const META_COLUMNS =
  'id, organization_id, registry_type, registry_url, display_name, ' +
  'credential_shape, encryption_key_version, last_used_at, created_by, created_at, updated_at';

// ============================================================================
// GET /:id/registry-credentials — list (metadata only)
// ============================================================================
router.get('/:id/registry-credentials', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await checkOrgAccess(userId, orgId))) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    const { data, error } = await supabase
      .from('organization_registry_credentials')
      .select(META_COLUMNS)
      .eq('organization_id', orgId);

    if (error) throw error;
    res.json(data ?? []);
  } catch (error: any) {
    console.error('Error listing registry credentials:', error);
    res.status(500).json({ error: 'credential_operation_failed' });
  }
});

// ============================================================================
// POST /:id/registry-credentials — create
// ============================================================================
router.post('/:id/registry-credentials', authenticateUser, async (req: AuthRequest, res) => {
  try {
    if (!isEncryptionConfigured()) {
      return res.status(503).json({ error: 'AI_ENCRYPTION_KEY not configured' });
    }
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await checkOrgManageIntegrations(userId, orgId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const { registry_type, registry_url, display_name, credentials } = req.body ?? {};

    if (!REGISTRY_TYPES.includes(registry_type)) {
      return res.status(400).json({ error: `registry_type must be one of ${REGISTRY_TYPES.join(', ')}` });
    }
    if (typeof display_name !== 'string' || !display_name.trim()) {
      return res.status(400).json({ error: 'display_name required' });
    }
    if (REGISTRY_URL_REQUIRED.includes(registry_type) && (typeof registry_url !== 'string' || !registry_url.trim())) {
      return res.status(400).json({ error: `registry_url required for ${registry_type}` });
    }
    if (registry_url !== undefined && registry_url !== null && typeof registry_url !== 'string') {
      return res.status(400).json({ error: 'registry_url must be a string or null' });
    }

    const validated = validatePlaintext(credentials);
    if (!validated.ok) {
      return res.status(400).json({ error: validated.error });
    }
    if (!isValidPair(registry_type, validated.value.shape)) {
      return res.status(400).json({
        error: `credentials.shape "${validated.value.shape}" is not valid for registry_type "${registry_type}"`,
      });
    }

    let encrypted: string;
    let encryption_key_version: number;
    try {
      const result = encryptApiKey(JSON.stringify(validated.value));
      encrypted = result.encrypted;
      encryption_key_version = result.version;
    } catch (err) {
      console.error('Error encrypting registry credential:', err);
      return res.status(500).json({ error: 'credential_operation_failed' });
    }

    const { data, error } = await supabase
      .from('organization_registry_credentials')
      .insert({
        organization_id: orgId,
        registry_type,
        registry_url: registry_url?.trim() || null,
        display_name: display_name.trim(),
        credential_shape: validated.value.shape,
        encrypted_credentials: encrypted,
        encryption_key_version,
        created_by: userId,
      })
      .select(META_COLUMNS)
      .single();

    if (error) throw error;

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'registry_credential_created',
      description: `created registry credential "${data.display_name}" (${data.registry_type})`,
      metadata: { credential_id: data.id, registry_type: data.registry_type, credential_shape: data.credential_shape },
    });

    res.status(201).json(data);
  } catch (error: any) {
    console.error('Error creating registry credential:', error);
    res.status(500).json({ error: 'credential_operation_failed' });
  }
});

// ============================================================================
// PATCH /:id/registry-credentials/:credId — display_name only
// ============================================================================
router.patch('/:id/registry-credentials/:credId', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    const credId = req.params.credId;
    if (!(await checkOrgManageIntegrations(userId, orgId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const body = req.body ?? {};
    const allowed = new Set(['display_name']);
    const unknown = Object.keys(body).find((k) => !allowed.has(k));
    if (unknown) {
      return res.status(400).json({ error: 'unknown_field', field: unknown });
    }
    if (typeof body.display_name !== 'string' || !body.display_name.trim()) {
      return res.status(400).json({ error: 'display_name required' });
    }

    const { data, error } = await supabase
      .from('organization_registry_credentials')
      .update({ display_name: body.display_name.trim(), updated_at: new Date().toISOString() })
      .eq('id', credId)
      .eq('organization_id', orgId)
      .select(META_COLUMNS)
      .single();

    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Credential not found' });

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'registry_credential_updated',
      description: `renamed registry credential to "${data.display_name}"`,
      metadata: { credential_id: credId },
    });

    res.json(data);
  } catch (error: any) {
    console.error('Error updating registry credential:', error);
    res.status(500).json({ error: 'credential_operation_failed' });
  }
});

// ============================================================================
// PATCH /:id/registry-credentials/:credId/rotate — re-encrypt new plaintext
// ============================================================================
router.patch('/:id/registry-credentials/:credId/rotate', authenticateUser, async (req: AuthRequest, res) => {
  try {
    if (!isEncryptionConfigured()) {
      return res.status(503).json({ error: 'AI_ENCRYPTION_KEY not configured' });
    }
    const userId = req.user!.id;
    const orgId = req.params.id;
    const credId = req.params.credId;
    if (!(await checkOrgManageIntegrations(userId, orgId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const body = req.body ?? {};
    const allowed = new Set(['credentials']);
    const unknown = Object.keys(body).find((k) => !allowed.has(k));
    if (unknown) {
      return res.status(400).json({ error: 'unknown_field', field: unknown });
    }

    const { data: existing, error: fetchErr } = await supabase
      .from('organization_registry_credentials')
      .select('id, registry_type, credential_shape')
      .eq('id', credId)
      .eq('organization_id', orgId)
      .single();
    if (fetchErr || !existing) {
      return res.status(404).json({ error: 'Credential not found' });
    }

    const validated = validatePlaintext(body.credentials);
    if (!validated.ok) {
      return res.status(400).json({ error: validated.error });
    }
    // Rotate cannot change the shape — that would imply a different cred type.
    if (validated.value.shape !== existing.credential_shape) {
      return res.status(400).json({
        error: `cannot rotate to a different credential_shape (existing: ${existing.credential_shape}, new: ${validated.value.shape})`,
      });
    }

    let encrypted: string;
    let encryption_key_version: number;
    try {
      const result = encryptApiKey(JSON.stringify(validated.value));
      encrypted = result.encrypted;
      encryption_key_version = result.version;
    } catch (err) {
      console.error('Error encrypting rotated credential:', err);
      return res.status(500).json({ error: 'credential_operation_failed' });
    }

    const { data, error } = await supabase
      .from('organization_registry_credentials')
      .update({
        encrypted_credentials: encrypted,
        encryption_key_version,
        updated_at: new Date().toISOString(),
      })
      .eq('id', credId)
      .eq('organization_id', orgId)
      .select(META_COLUMNS)
      .single();

    if (error) throw error;

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'registry_credential_rotated',
      description: `rotated registry credential "${data.display_name}"`,
      metadata: { credential_id: credId, encryption_key_version },
    });

    res.json(data);
  } catch (error: any) {
    console.error('Error rotating registry credential:', error);
    res.status(500).json({ error: 'credential_operation_failed' });
  }
});

// ============================================================================
// DELETE /:id/registry-credentials/:credId
// ============================================================================
router.delete('/:id/registry-credentials/:credId', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    const credId = req.params.credId;
    if (!(await checkOrgManageIntegrations(userId, orgId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    // Count attached configured-images so the API surface tells the UI how
    // many will be soft-detached by ON DELETE SET NULL on the composite FK.
    const { data: attached } = await supabase
      .from('project_configured_images')
      .select('id')
      .eq('credentials_id', credId)
      .eq('organization_id', orgId);
    const detachedCount = attached?.length ?? 0;

    const { data: existing, error: fetchErr } = await supabase
      .from('organization_registry_credentials')
      .select('id, display_name, registry_type')
      .eq('id', credId)
      .eq('organization_id', orgId)
      .single();
    if (fetchErr || !existing) {
      return res.status(404).json({ error: 'Credential not found' });
    }

    const { error } = await supabase
      .from('organization_registry_credentials')
      .delete()
      .eq('id', credId)
      .eq('organization_id', orgId);

    if (error) throw error;

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'registry_credential_deleted',
      description: `deleted registry credential "${existing.display_name}"`,
      metadata: { credential_id: credId, detached_image_count: detachedCount },
    });

    res.json({ message: 'Credential deleted', detached_image_count: detachedCount });
  } catch (error: any) {
    console.error('Error deleting registry credential:', error);
    res.status(500).json({ error: 'credential_operation_failed' });
  }
});

// ============================================================================
// POST /:id/registry-credentials/:credId/test — decrypt-shape dry-run
// ----------------------------------------------------------------------------
// Light "does this cred decrypt and parse?" probe. Intentionally does NOT
// mint cloud-provider STS / OAuth tokens — that lives in the depscanner
// orchestrator (Phase 1b M5/M8) where the real auth envelope is built. This
// endpoint catches the most common UX failure (wrong-key or shape-drift)
// without requiring AWS / GCP / Azure SDKs in the API tier.
// ============================================================================
router.post('/:id/registry-credentials/:credId/test', authenticateUser, async (req: AuthRequest, res) => {
  try {
    if (!isEncryptionConfigured()) {
      return res.status(503).json({ error: 'AI_ENCRYPTION_KEY not configured' });
    }
    const userId = req.user!.id;
    const orgId = req.params.id;
    const credId = req.params.credId;
    if (!(await checkOrgManageIntegrations(userId, orgId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const { data: row, error: fetchErr } = await supabase
      .from('organization_registry_credentials')
      .select('id, encrypted_credentials, encryption_key_version, credential_shape, display_name')
      .eq('id', credId)
      .eq('organization_id', orgId)
      .single();
    if (fetchErr || !row) {
      return res.status(404).json({ error: 'Credential not found' });
    }

    let parsed: any;
    try {
      const plaintext = decryptApiKey(row.encrypted_credentials, row.encryption_key_version);
      parsed = JSON.parse(plaintext);
    } catch (err) {
      console.error('Error decrypting credential during test:', err);
      await createActivity({
        organization_id: orgId,
        user_id: userId,
        activity_type: 'registry_credential_tested',
        description: `tested registry credential "${row.display_name}" (decrypt_failed)`,
        metadata: { credential_id: credId, ok: false, error_class: 'decrypt_failed' },
      });
      return res.json({ ok: false, error_class: 'decrypt_failed' });
    }

    const reValidated = validatePlaintext(parsed);
    if (!reValidated.ok || reValidated.value.shape !== row.credential_shape) {
      await createActivity({
        organization_id: orgId,
        user_id: userId,
        activity_type: 'registry_credential_tested',
        description: `tested registry credential "${row.display_name}" (shape_invalid)`,
        metadata: { credential_id: credId, ok: false, error_class: 'shape_invalid' },
      });
      return res.json({ ok: false, error_class: 'shape_invalid' });
    }

    await createActivity({
      organization_id: orgId,
      user_id: userId,
      activity_type: 'registry_credential_tested',
      description: `tested registry credential "${row.display_name}"`,
      metadata: { credential_id: credId, ok: true },
    });

    res.json({ ok: true });
  } catch (error: any) {
    console.error('Error testing registry credential:', error);
    res.status(500).json({ error: 'credential_operation_failed' });
  }
});

export default router;
