import express from 'express';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { validateExternalUrl } from '../lib/url-guard';
import { startDastMachine } from '../lib/fly-machines';
import {
  checkProjectAccess,
  checkOrgManageIntegrationsPermission,
} from '../lib/project-access';
import { loadTargetOrDeny, isLoadTargetDeny } from '../lib/dast-tenant-guard';
import { validateScopeConfig } from '../lib/dast-scope-validate';
import { detectRuntime, nextRuntimeTtlIso } from '../lib/dast-spa-detect';
import { validateAndPrepareCredential, summarizePayload } from '../lib/dast-credential-validate';
import {
  encryptCredential,
  isDastEncryptionConfigured,
  decryptCredential,
} from '../lib/dast-encryption';
import type {
  DastConfigDTO,
  DastCredentialSummaryDTO,
  DastFindingDTO,
  DastJobDTO,
  DastScanProfile,
  DastTargetDTO,
} from '../types/dast';

const router = express.Router();
router.use(authenticateUser);

const VALID_SCAN_PROFILES: ReadonlySet<DastScanProfile> = new Set(['auto', 'quick', 'full', 'api']);
const TIMEOUT_MIN = 5;
const TIMEOUT_MAX = 60;
const DAST_SCAN_TYPES = ['dast', 'dast_zap', 'dast_nuclei'];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type AccessResolved = { organizationId: string; deny?: undefined };
type AccessDenied = { organizationId?: undefined; deny: { status: number; message: string } };

async function resolveProjectAccess(
  userId: string,
  projectId: string,
): Promise<AccessResolved | AccessDenied> {
  const { data: project, error } = await supabase
    .from('projects')
    .select('organization_id')
    .eq('id', projectId)
    .single();

  if (error || !project) {
    return { deny: { status: 404, message: 'Project not found' } };
  }

  const access = await checkProjectAccess(userId, project.organization_id, projectId);
  if (!access.hasAccess) {
    return {
      deny: {
        status: access.error?.status ?? 403,
        message: access.error?.message ?? 'Access denied',
      },
    };
  }

  return { organizationId: project.organization_id };
}

function targetRowToDto(row: any): DastTargetDTO {
  return {
    id: row.id,
    target_url: row.target_url,
    label: row.label ?? null,
    enabled: !!row.enabled,
    detected_runtime: row.detected_runtime ?? 'unknown',
    detected_runtime_at: row.detected_runtime_at ?? null,
    detected_runtime_ttl_at: row.detected_runtime_ttl_at ?? null,
    has_credentials: !!row.has_credentials,
    auth_strategy: row.auth_strategy ?? null,
    active_dast_run_id: row.active_dast_run_id ?? null,
    last_scanned_at: row.last_scanned_at ?? null,
    created_at: row.created_at,
  };
}

async function loadTargetsWithCreds(projectId: string): Promise<DastTargetDTO[]> {
  const { data: targets, error } = await supabase
    .from('project_dast_targets')
    .select(
      'id, target_url, label, enabled, detected_runtime, detected_runtime_at, detected_runtime_ttl_at, active_dast_run_id, last_scanned_at, created_at',
    )
    .eq('project_id', projectId)
    .order('created_at');

  if (error) {
    console.error('[dast] loadTargetsWithCreds:', error.message);
    return [];
  }

  if (!targets || targets.length === 0) return [];

  const { data: creds } = await supabase
    .from('project_dast_credentials')
    .select('target_id, auth_strategy')
    .in('target_id', targets.map((t: any) => t.id));

  const credByTarget: Record<string, { auth_strategy: string }> = {};
  for (const c of creds ?? []) credByTarget[c.target_id] = { auth_strategy: c.auth_strategy };

  return targets.map((row: any) =>
    targetRowToDto({
      ...row,
      has_credentials: !!credByTarget[row.id],
      auth_strategy: credByTarget[row.id]?.auth_strategy ?? null,
    }),
  );
}

// ---------------------------------------------------------------------------
// GET /:projectId/dast/config
// Returns scan_profile, scan_timeout_minutes, scope_config, targets[].
// ---------------------------------------------------------------------------
router.get('/:projectId/dast/config', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }

    const { data, error } = await supabase
      .from('project_dast_config')
      .select('enabled, target_url, scan_profile, scan_timeout_minutes, scope_config')
      .eq('project_id', projectId)
      .maybeSingle();

    if (error) {
      console.error('[dast] GET config error:', error.message);
      return res.status(500).json({ error: 'Failed to load DAST config' });
    }

    const targets = await loadTargetsWithCreds(projectId);

    const config: DastConfigDTO = data
      ? {
          enabled: !!data.enabled,
          target_url: data.target_url ?? null,
          scan_profile: data.scan_profile,
          scan_timeout_minutes: data.scan_timeout_minutes,
          scope_config: data.scope_config ?? {},
          targets,
        }
      : {
          enabled: false,
          target_url: null,
          scan_profile: 'auto',
          scan_timeout_minutes: 30,
          scope_config: {},
          targets,
        };

    return res.json(config);
  } catch (e: any) {
    console.error('[dast] GET config exception:', e);
    return res.status(500).json({ error: 'Failed to load DAST config' });
  }
});

// ---------------------------------------------------------------------------
// PUT /:projectId/dast/config
// Updates profile / timeout / scope_config. Targets go through their own
// endpoints. scope_config rejects sensitive headers + ReDoS patterns.
// ---------------------------------------------------------------------------
router.put('/:projectId/dast/config', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }

    if (!(await checkOrgManageIntegrationsPermission(userId, access.organizationId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const body = req.body ?? {};
    const enabled = typeof body.enabled === 'boolean' ? body.enabled : false;
    const scanProfile: DastScanProfile = VALID_SCAN_PROFILES.has(body.scan_profile)
      ? body.scan_profile
      : 'auto';
    const scanTimeoutMinutes = Math.max(
      TIMEOUT_MIN,
      Math.min(TIMEOUT_MAX, Number(body.scan_timeout_minutes) || 30),
    );

    let scopeConfig = {};
    if (body.scope_config !== undefined) {
      const r = validateScopeConfig(body.scope_config);
      if (r.ok === false) return res.status(422).json(r.error);
      scopeConfig = r.value;
    }

    const { error } = await supabase.from('project_dast_config').upsert(
      {
        project_id: projectId,
        organization_id: access.organizationId,
        enabled,
        scan_profile: scanProfile,
        scan_timeout_minutes: scanTimeoutMinutes,
        scope_config: scopeConfig,
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'project_id' },
    );

    if (error) {
      console.error('[dast] PUT config error:', error.message);
      return res.status(500).json({ error: 'Failed to save DAST config' });
    }

    const targets = await loadTargetsWithCreds(projectId);
    const config: DastConfigDTO = {
      enabled,
      scan_profile: scanProfile,
      scan_timeout_minutes: scanTimeoutMinutes,
      scope_config: scopeConfig,
      targets,
    };
    return res.json(config);
  } catch (e: any) {
    console.error('[dast] PUT config exception:', e);
    return res.status(500).json({ error: 'Failed to save DAST config' });
  }
});

// ---------------------------------------------------------------------------
// GET /:projectId/dast/targets
// ---------------------------------------------------------------------------
router.get('/:projectId/dast/targets', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }

    const targets = await loadTargetsWithCreds(projectId);
    return res.json(targets);
  } catch (e: any) {
    console.error('[dast] GET targets exception:', e);
    return res.status(500).json({ error: 'Failed to load DAST targets' });
  }
});

// ---------------------------------------------------------------------------
// POST /:projectId/dast/targets
// Body: { target_url, label?, enabled? }
// ---------------------------------------------------------------------------
router.post('/:projectId/dast/targets', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }
    if (!(await checkOrgManageIntegrationsPermission(userId, access.organizationId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const { target_url, label, enabled } = req.body ?? {};
    if (typeof target_url !== 'string' || target_url.length === 0) {
      return res.status(422).json({ error: 'invalid_target_url', detail: 'target_url required' });
    }
    const guard = await validateExternalUrl(target_url);
    if (guard.valid === false) {
      return res.status(422).json({ error: 'invalid_target_url', detail: guard.reason });
    }

    // SPA-detect probe synchronously (best-effort — 'unknown' on probe failure
    // gets retried on first scan).
    const probe = await detectRuntime(target_url);
    const probeSuccess = probe.runtime !== 'unknown';
    const detectedAt = probeSuccess ? new Date().toISOString() : null;
    const detectedTtl = probeSuccess ? nextRuntimeTtlIso() : null;

    const { data: inserted, error } = await supabase
      .from('project_dast_targets')
      .insert({
        project_id: projectId,
        organization_id: access.organizationId,
        target_url,
        label: typeof label === 'string' && label.length > 0 ? label : null,
        enabled: typeof enabled === 'boolean' ? enabled : true,
        detected_runtime: probe.runtime,
        detected_runtime_at: detectedAt,
        detected_runtime_ttl_at: detectedTtl,
      })
      .select(
        'id, target_url, label, enabled, detected_runtime, detected_runtime_at, detected_runtime_ttl_at, active_dast_run_id, last_scanned_at, created_at',
      )
      .single();

    if (error) {
      if (/duplicate key|unique/i.test(error.message)) {
        return res.status(409).json({ error: 'target_url_duplicate' });
      }
      console.error('[dast] POST target error:', error.message);
      return res.status(500).json({ error: 'Failed to create target' });
    }

    return res
      .status(201)
      .json(targetRowToDto({ ...inserted, has_credentials: false, auth_strategy: null }));
  } catch (e: any) {
    console.error('[dast] POST target exception:', e);
    return res.status(500).json({ error: 'Failed to create target' });
  }
});

// ---------------------------------------------------------------------------
// PATCH /:projectId/dast/targets/:targetId
// Update label / enabled. target_url is immutable (delete+recreate to migrate).
// ---------------------------------------------------------------------------
router.patch('/:projectId/dast/targets/:targetId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId, targetId } = req.params;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }
    if (!(await checkOrgManageIntegrationsPermission(userId, access.organizationId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const guard = await loadTargetOrDeny(supabase, targetId, projectId, access.organizationId);
    if (isLoadTargetDeny(guard)) return res.status(404).json({ error: 'target_not_found' });

    const patch: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if (typeof req.body?.label === 'string') {
      patch.label = req.body.label.length > 0 ? req.body.label : null;
    } else if (req.body?.label === null) {
      patch.label = null;
    }
    if (typeof req.body?.enabled === 'boolean') patch.enabled = req.body.enabled;

    const { data: updated, error } = await supabase
      .from('project_dast_targets')
      .update(patch)
      .eq('id', targetId)
      .select(
        'id, target_url, label, enabled, detected_runtime, detected_runtime_at, detected_runtime_ttl_at, active_dast_run_id, last_scanned_at, created_at',
      )
      .single();

    if (error) {
      console.error('[dast] PATCH target error:', error.message);
      return res.status(500).json({ error: 'Failed to update target' });
    }

    const { data: cred } = await supabase
      .from('project_dast_credentials')
      .select('auth_strategy')
      .eq('target_id', targetId)
      .maybeSingle();

    return res.json(
      targetRowToDto({
        ...updated,
        has_credentials: !!cred,
        auth_strategy: cred?.auth_strategy ?? null,
      }),
    );
  } catch (e: any) {
    console.error('[dast] PATCH target exception:', e);
    return res.status(500).json({ error: 'Failed to update target' });
  }
});

// ---------------------------------------------------------------------------
// DELETE /:projectId/dast/targets/:targetId
// Cascades to credentials / findings / scan_jobs via ON DELETE CASCADE.
// ---------------------------------------------------------------------------
router.delete('/:projectId/dast/targets/:targetId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId, targetId } = req.params;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }
    if (!(await checkOrgManageIntegrationsPermission(userId, access.organizationId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const guard = await loadTargetOrDeny(supabase, targetId, projectId, access.organizationId);
    if (isLoadTargetDeny(guard)) return res.status(404).json({ error: 'target_not_found' });

    const { error } = await supabase.from('project_dast_targets').delete().eq('id', targetId);
    if (error) {
      console.error('[dast] DELETE target error:', error.message);
      return res.status(500).json({ error: 'Failed to delete target' });
    }
    return res.status(204).send();
  } catch (e: any) {
    console.error('[dast] DELETE target exception:', e);
    return res.status(500).json({ error: 'Failed to delete target' });
  }
});

// ---------------------------------------------------------------------------
// POST /:projectId/dast/targets/:targetId/recheck-runtime
// Force re-probe SPA detection. Idempotent.
// ---------------------------------------------------------------------------
router.post(
  '/:projectId/dast/targets/:targetId/recheck-runtime',
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user!.id;
      const { projectId, targetId } = req.params;

      const access = await resolveProjectAccess(userId, projectId);
      if (access.deny) {
        return res.status(access.deny.status).json({ error: access.deny.message });
      }
      if (!(await checkOrgManageIntegrationsPermission(userId, access.organizationId))) {
        return res.status(403).json({ error: 'You do not have permission to manage integrations' });
      }

      const guard = await loadTargetOrDeny(supabase, targetId, projectId, access.organizationId);
      if (isLoadTargetDeny(guard)) return res.status(404).json({ error: 'target_not_found' });

      const probe = await detectRuntime(guard.target.target_url);
      const probeSuccess = probe.runtime !== 'unknown';
      const detectedAt = probeSuccess ? new Date().toISOString() : null;
      const detectedTtl = probeSuccess ? nextRuntimeTtlIso() : null;

      const { data: updated, error } = await supabase
        .from('project_dast_targets')
        .update({
          detected_runtime: probe.runtime,
          detected_runtime_at: detectedAt,
          detected_runtime_ttl_at: detectedTtl,
          updated_at: new Date().toISOString(),
        })
        .eq('id', targetId)
        .select(
          'id, target_url, label, enabled, detected_runtime, detected_runtime_at, detected_runtime_ttl_at, active_dast_run_id, last_scanned_at, created_at',
        )
        .single();

      if (error) {
        console.error('[dast] recheck-runtime error:', error.message);
        return res.status(500).json({ error: 'Failed to re-probe runtime' });
      }
      return res.json({
        target: targetRowToDto({ ...updated, has_credentials: false, auth_strategy: null }),
        probe: {
          probed: probeSuccess,
          confidence: probe.confidence,
          markers: probe.markers,
        },
      });
    } catch (e: any) {
      console.error('[dast] recheck-runtime exception:', e);
      return res.status(500).json({ error: 'Failed to re-probe runtime' });
    }
  },
);

// ---------------------------------------------------------------------------
// GET /:projectId/dast/targets/:targetId/credentials
// Returns redacted summary. Permission: manage_integrations.
// ---------------------------------------------------------------------------
router.get(
  '/:projectId/dast/targets/:targetId/credentials',
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user!.id;
      const { projectId, targetId } = req.params;

      const access = await resolveProjectAccess(userId, projectId);
      if (access.deny) {
        return res.status(access.deny.status).json({ error: access.deny.message });
      }
      if (!(await checkOrgManageIntegrationsPermission(userId, access.organizationId))) {
        return res.status(403).json({ error: 'You do not have permission to manage integrations' });
      }

      const guard = await loadTargetOrDeny(supabase, targetId, projectId, access.organizationId);
      if (isLoadTargetDeny(guard)) return res.status(404).json({ error: 'target_not_found' });

      const { data: cred, error } = await supabase
        .from('project_dast_credentials')
        .select(
          'auth_strategy, encrypted_payload, encryption_key_version, organization_id, logged_in_indicator, logged_out_indicator, updated_at',
        )
        .eq('target_id', targetId)
        .maybeSingle();
      if (error) {
        console.error('[dast] GET creds error:', error.message);
        return res.status(500).json({ error: 'Failed to load credentials' });
      }
      if (!cred) return res.status(404).json({ error: 'credentials_not_set' });

      // Cross-tenant defense-in-depth. The default Supabase client uses
      // service-role and bypasses RLS, so a credential row whose
      // organization_id has drifted (FK race, manual SQL, RLS-bypassing
      // INSERT) would be decrypted across tenants. loadTargetOrDeny verifies
      // the target's tenancy upstream but doesn't read the credential row.
      // Match the worker's invariant: refuse to decrypt if the row's org
      // doesn't match the access-resolved org. 404 to avoid enumeration.
      if ((cred as { organization_id: string }).organization_id !== access.organizationId) {
        return res.status(404).json({ error: 'credentials_not_set' });
      }

      // Decrypt only to derive the summary, then drop the plaintext from
      // memory immediately. We intentionally do NOT return raw plaintext.
      let summary;
      try {
        if (!isDastEncryptionConfigured()) {
          return res.status(503).json({ error: 'dast_encryption_not_configured' });
        }
        const plaintext = decryptCredential(cred.encrypted_payload, cred.encryption_key_version);
        const parsed = JSON.parse(plaintext);
        summary = summarizePayload(parsed);
        // Best-effort scrub of the local string. JS strings are immutable so
        // we can't actually wipe — relying on GC.
      } catch (e: any) {
        console.error('[dast] credential decrypt failed:', e?.message);
        return res.status(500).json({ error: 'credential_decrypt_failed' });
      }

      const dto: DastCredentialSummaryDTO = {
        auth_strategy: cred.auth_strategy,
        payload_summary: summary,
        logged_in_indicator: cred.logged_in_indicator ?? null,
        logged_out_indicator: cred.logged_out_indicator ?? null,
        updated_at: cred.updated_at,
      };
      return res.json(dto);
    } catch (e: any) {
      console.error('[dast] GET creds exception:', e);
      return res.status(500).json({ error: 'Failed to load credentials' });
    }
  },
);

// ---------------------------------------------------------------------------
// PUT /:projectId/dast/targets/:targetId/credentials
// Strategy validation → encrypt → upsert. Permission: manage_integrations.
// ---------------------------------------------------------------------------
router.put(
  '/:projectId/dast/targets/:targetId/credentials',
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user!.id;
      const { projectId, targetId } = req.params;

      const access = await resolveProjectAccess(userId, projectId);
      if (access.deny) {
        return res.status(access.deny.status).json({ error: access.deny.message });
      }
      if (!(await checkOrgManageIntegrationsPermission(userId, access.organizationId))) {
        return res.status(403).json({ error: 'You do not have permission to manage integrations' });
      }

      if (!isDastEncryptionConfigured()) {
        return res.status(503).json({ error: 'dast_encryption_not_configured' });
      }

      const guard = await loadTargetOrDeny(supabase, targetId, projectId, access.organizationId);
      if (isLoadTargetDeny(guard)) return res.status(404).json({ error: 'target_not_found' });

      const { data: cfg } = await supabase
        .from('project_dast_config')
        .select('scan_timeout_minutes')
        .eq('project_id', projectId)
        .maybeSingle();
      const scanTimeoutMinutes = cfg?.scan_timeout_minutes ?? 30;

      const validated = await validateAndPrepareCredential(req.body, {
        scanTimeoutMinutes,
        runFormProbe: req.body?.skip_login_probe === true ? false : true,
      });
      if (validated.ok === false) return res.status(422).json(validated.error);

      const { encrypted, version } = encryptCredential(validated.serializedPlaintext);

      const { error } = await supabase.from('project_dast_credentials').upsert(
        {
          target_id: targetId,
          organization_id: access.organizationId,
          auth_strategy: validated.payload.kind,
          encrypted_payload: encrypted,
          encryption_key_version: version,
          logged_in_indicator: req.body?.logged_in_indicator ?? null,
          logged_out_indicator: req.body?.logged_out_indicator ?? null,
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'target_id' },
      );
      if (error) {
        console.error('[dast] PUT creds error:', error.message);
        return res.status(500).json({ error: 'Failed to save credentials' });
      }

      const dto: DastCredentialSummaryDTO = {
        auth_strategy: validated.payload.kind,
        payload_summary: validated.summary,
        logged_in_indicator: req.body?.logged_in_indicator ?? null,
        logged_out_indicator: req.body?.logged_out_indicator ?? null,
        updated_at: new Date().toISOString(),
      };
      return res.json(dto);
    } catch (e: any) {
      console.error('[dast] PUT creds exception:', e);
      return res.status(500).json({ error: 'Failed to save credentials' });
    }
  },
);

// ---------------------------------------------------------------------------
// DELETE /:projectId/dast/targets/:targetId/credentials
// ---------------------------------------------------------------------------
router.delete(
  '/:projectId/dast/targets/:targetId/credentials',
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user!.id;
      const { projectId, targetId } = req.params;

      const access = await resolveProjectAccess(userId, projectId);
      if (access.deny) {
        return res.status(access.deny.status).json({ error: access.deny.message });
      }
      if (!(await checkOrgManageIntegrationsPermission(userId, access.organizationId))) {
        return res.status(403).json({ error: 'You do not have permission to manage integrations' });
      }

      const guard = await loadTargetOrDeny(supabase, targetId, projectId, access.organizationId);
      if (isLoadTargetDeny(guard)) return res.status(404).json({ error: 'target_not_found' });

      const { error } = await supabase
        .from('project_dast_credentials')
        .delete()
        .eq('target_id', targetId);
      if (error) {
        console.error('[dast] DELETE creds error:', error.message);
        return res.status(500).json({ error: 'Failed to delete credentials' });
      }
      return res.status(204).send();
    } catch (e: any) {
      console.error('[dast] DELETE creds exception:', e);
      return res.status(500).json({ error: 'Failed to delete credentials' });
    }
  },
);

// ---------------------------------------------------------------------------
// POST /:projectId/dast/scan
// Body: { target_id }. Pre-flight SSRF + SPA-detect refresh; queue_scan_job
// with p_target_id. INTERNAL_DAST_PAUSED → 503 handled by middleware.
// ---------------------------------------------------------------------------
router.post('/:projectId/dast/scan', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }
    if (!(await checkOrgManageIntegrationsPermission(userId, access.organizationId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const targetId = req.body?.target_id;
    if (typeof targetId !== 'string' || targetId.length === 0) {
      return res.status(422).json({ error: 'target_id required' });
    }

    const guard = await loadTargetOrDeny(supabase, targetId, projectId, access.organizationId);
    if (isLoadTargetDeny(guard)) return res.status(404).json({ error: 'target_not_found' });
    if (!guard.target.enabled) {
      return res.status(409).json({ error: 'target_disabled' });
    }

    // Re-validate URL (SSRF + DNS pinning).
    const urlGuard = await validateExternalUrl(guard.target.target_url);
    if (urlGuard.valid === false) {
      return res.status(422).json({ error: 'invalid_target_url', detail: urlGuard.reason });
    }

    // Read project-level config for profile + timeout.
    const { data: cfg } = await supabase
      .from('project_dast_config')
      .select('scan_profile, scan_timeout_minutes')
      .eq('project_id', projectId)
      .maybeSingle();
    const scanProfile = cfg?.scan_profile ?? 'auto';
    const scanTimeoutMinutes = cfg?.scan_timeout_minutes ?? 30;

    // Re-probe SPA detection if cache expired. This is synchronous and
    // best-effort — a probe failure leaves runtime unchanged ('unknown' is
    // safe; Task 4's machine-shape dispatcher upgrades 'unknown' → SPA-shape).
    let detectedRuntime = guard.target.detected_runtime;
    const ttl = guard.target.detected_runtime_ttl_at;
    if (!ttl || new Date(ttl).getTime() < Date.now()) {
      const probe = await detectRuntime(guard.target.target_url);
      if (probe.runtime !== 'unknown') {
        detectedRuntime = probe.runtime;
        await supabase
          .from('project_dast_targets')
          .update({
            detected_runtime: probe.runtime,
            detected_runtime_at: new Date().toISOString(),
            detected_runtime_ttl_at: nextRuntimeTtlIso(),
            updated_at: new Date().toISOString(),
          })
          .eq('id', targetId);
      }
    }

    const { data: queued, error: queueError } = await supabase.rpc('queue_scan_job', {
      p_project_id: projectId,
      p_organization_id: access.organizationId,
      p_type: 'dast_zap',
      p_payload: { source: 'manual_dast_scan', detected_runtime: detectedRuntime },
      p_target_id: targetId,
      p_target_url: guard.target.target_url,
      p_scan_profile: scanProfile,
      p_timeout_minutes: scanTimeoutMinutes,
      p_trigger_source: 'manual',
      p_triggered_by: userId,
    });

    if (queueError) {
      const detail = queueError.message ?? 'Failed to queue scan';
      if (detail.includes('project_concurrent_dast_blocked')) {
        return res.status(409).json({ error: 'project_concurrent_dast_blocked', detail });
      }
      if (detail.includes('org_concurrent_dast_cap')) {
        return res.status(409).json({ error: 'org_concurrent_dast_cap', detail });
      }
      if (detail.includes('tenant drift')) {
        // Should be impossible after loadTargetOrDeny; return 404 to avoid
        // existence enumeration if it ever triggers.
        return res.status(404).json({ error: 'target_not_found' });
      }
      if (
        detail.includes('rejected (private/loopback/internal)') ||
        detail.includes('must be http(s)')
      ) {
        return res.status(422).json({ error: 'invalid_target_url', detail });
      }
      console.error('[dast] queue_scan_job error:', detail);
      return res.status(500).json({ error: 'Failed to queue scan' });
    }

    const job = Array.isArray(queued) ? queued[0] : queued;
    if (!job?.id) {
      console.error('[dast] queue_scan_job returned no row');
      return res.status(500).json({ error: 'Failed to queue scan' });
    }

    try {
      // Pass detected_runtime so SPA targets get a performance-4x 16GB
      // machine; classic targets downsize to shared-cpu-4x 8GB. 'unknown'
      // (first scan, no runtime cached) is treated as SPA for safety.
      await startDastMachine(detectedRuntime);
    } catch (e: any) {
      console.warn(`[dast] startDastMachine failed (job stays queued): ${e?.message ?? e}`);
    }

    return res.status(202).json({
      jobId: job.id,
      status: job.status,
      target_id: targetId,
      target_url: job.target_url,
      scan_profile: job.scan_profile,
      detected_runtime: detectedRuntime,
      created_at: job.created_at,
    });
  } catch (e: any) {
    console.error('[dast] POST scan exception:', e);
    return res.status(500).json({ error: 'Failed to trigger scan' });
  }
});

// ---------------------------------------------------------------------------
// GET /:projectId/dast/jobs?limit=N&target_id=...
// ---------------------------------------------------------------------------
router.get('/:projectId/dast/jobs', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;
    const limit = Math.max(1, Math.min(100, Number(req.query.limit) || 20));
    const filterTargetId = typeof req.query.target_id === 'string' ? req.query.target_id : null;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }

    if (filterTargetId) {
      const guard = await loadTargetOrDeny(
        supabase,
        filterTargetId,
        projectId,
        access.organizationId,
      );
      if (isLoadTargetDeny(guard)) return res.status(404).json({ error: 'target_not_found' });
    }

    let query = supabase
      .from('scan_jobs')
      .select(
        'id, status, trigger_source, target_id, target_url, scan_profile, findings_count, duration_seconds, started_at, completed_at, error, error_category, attempts, created_at',
      )
      .eq('project_id', projectId)
      .in('type', DAST_SCAN_TYPES)
      .order('created_at', { ascending: false })
      .limit(limit);
    if (filterTargetId) query = query.eq('target_id', filterTargetId);

    const { data, error } = await query;
    if (error) {
      console.error('[dast] GET jobs error:', error.message);
      return res.status(500).json({ error: 'Failed to load DAST jobs' });
    }

    const jobs: DastJobDTO[] = (data ?? []).map((row: any) => ({
      id: row.id,
      status: row.status,
      trigger_source: row.trigger_source,
      target_id: row.target_id ?? null,
      target_url: row.target_url,
      scan_profile: row.scan_profile,
      findings_count: row.findings_count,
      duration_seconds: row.duration_seconds,
      started_at: row.started_at,
      completed_at: row.completed_at,
      error: row.error,
      error_category: row.error_category,
      attempts: row.attempts ?? 0,
      created_at: row.created_at,
    }));
    return res.json(jobs);
  } catch (e: any) {
    console.error('[dast] GET jobs exception:', e);
    return res.status(500).json({ error: 'Failed to load DAST jobs' });
  }
});

// ---------------------------------------------------------------------------
// GET /:projectId/dast/findings?limit=N&target_id=...
// ---------------------------------------------------------------------------
router.get('/:projectId/dast/findings', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;
    const limit = Math.max(1, Math.min(500, Number(req.query.limit) || 100));
    const filterTargetId = typeof req.query.target_id === 'string' ? req.query.target_id : null;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }

    if (filterTargetId) {
      const guard = await loadTargetOrDeny(
        supabase,
        filterTargetId,
        projectId,
        access.organizationId,
      );
      if (isLoadTargetDeny(guard)) return res.status(404).json({ error: 'target_not_found' });
    }

    // Resolve the active dast_run_id per filter scope. With a target filter we
    // read the per-target pointer; without, fall back to the legacy
    // projects.active_dast_run_id (covers v1 single-target findings during the
    // shadow window).
    let activeRunIds: string[] = [];
    if (filterTargetId) {
      const { data } = await supabase
        .from('project_dast_targets')
        .select('active_dast_run_id')
        .eq('id', filterTargetId)
        .maybeSingle();
      if (data?.active_dast_run_id) activeRunIds = [data.active_dast_run_id];
    } else {
      const { data: project } = await supabase
        .from('projects')
        .select('active_dast_run_id')
        .eq('id', projectId)
        .single();
      if (project?.active_dast_run_id) activeRunIds = [project.active_dast_run_id];
    }

    if (activeRunIds.length === 0) return res.json([]);

    let query = supabase
      .from('project_dast_findings')
      .select(
        'id, target_id, auth_state, engine, endpoint_url, http_method, vulnerability_type, severity, cwe_id, owasp_top10_ref, rule_id, message, payload_redacted, response_evidence_redacted, confidence, handler_file_path, handler_function_name, handler_line, linked_sca_osv_id, linked_sca_project_dependency_id, linked_sast_finding_id, cross_link_methods, status, risk_accepted_reason, created_at',
      )
      .eq('project_id', projectId)
      .in('dast_run_id', activeRunIds)
      .order('severity', { ascending: true })
      .limit(limit);
    if (filterTargetId) query = query.eq('target_id', filterTargetId);

    const { data, error } = await query;
    if (error) {
      console.error('[dast] GET findings error:', error.message);
      return res.status(500).json({ error: 'Failed to load DAST findings' });
    }

    const findings: DastFindingDTO[] = (data ?? []).map((row: any) => ({
      id: row.id,
      target_id: row.target_id ?? null,
      auth_state: row.auth_state ?? null,
      engine: row.engine ?? null,
      endpoint_url: row.endpoint_url,
      http_method: row.http_method,
      vulnerability_type: row.vulnerability_type,
      severity: row.severity,
      cwe_id: row.cwe_id,
      owasp_top10_ref: row.owasp_top10_ref,
      rule_id: row.rule_id,
      message: row.message,
      payload_redacted: row.payload_redacted,
      response_evidence_redacted: row.response_evidence_redacted,
      confidence: row.confidence,
      handler_file_path: row.handler_file_path,
      handler_function_name: row.handler_function_name,
      handler_line: row.handler_line,
      linked_sca_osv_id: row.linked_sca_osv_id,
      linked_sca_project_dependency_id: row.linked_sca_project_dependency_id,
      linked_sast_finding_id: row.linked_sast_finding_id ?? null,
      cross_link_methods: row.cross_link_methods ?? null,
      confirmed_exploitable: row.linked_sca_osv_id != null,
      status: row.status,
      risk_accepted_reason: row.risk_accepted_reason,
      created_at: row.created_at,
    }));
    return res.json(findings);
  } catch (e: any) {
    console.error('[dast] GET findings exception:', e);
    return res.status(500).json({ error: 'Failed to load DAST findings' });
  }
});

export default router;
