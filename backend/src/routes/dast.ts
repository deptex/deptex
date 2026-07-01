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
import { DAST_SCAN_TYPES, loadDastFindings } from '../lib/dast-findings';
import { validateScopeConfig } from '../lib/dast-scope-validate';
import { detectRuntime, nextRuntimeTtlIso } from '../lib/dast-spa-detect';
import { validateAndPrepareCredential, summarizePayload, validateDastJobPayload } from '../lib/dast-credential-validate';
import {
  encryptCredential,
  isDastEncryptionConfigured,
  decryptCredential,
} from '../lib/dast-encryption';
import { parseHar } from '../lib/dast-har-parse';
import { createActivity } from '../lib/activities';
import {
  validateSpecSource,
  validateAndFetchSpecUrl,
} from '../lib/dast-spec-validate';
import {
  presignSynthesizedSpecDownload,
  deleteAllSpecsForTarget,
} from '../lib/dast-spec-storage';
import type {
  DastConfigDTO,
  DastCredentialSummaryDTO,
  DastJobDTO,
  DastScanProfile,
  DastTargetDTO,
} from '../types/dast';

const router = express.Router();
router.use(authenticateUser);

const VALID_SCAN_PROFILES: ReadonlySet<DastScanProfile> = new Set(['auto', 'quick', 'full', 'api']);
const TIMEOUT_MIN = 5;
const TIMEOUT_MAX = 60;

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
    // Phase 35 (v1.1) — OpenAPI spec config. Defaults guard rows that
    // pre-date phase35 (the migration's UPDATE only runs once, but
    // pglite/test fixtures may not have run it).
    spec_config: {
      api_spec_source: (row.api_spec_source ?? 'none') as 'synthesized' | 'url' | 'none',
      api_spec_url: row.api_spec_url ?? null,
      last_synthesized_at: row.last_synthesized_at ?? null,
      last_synthesis_endpoint_count: row.last_synthesis_endpoint_count ?? null,
      last_synthesis_ok: row.last_synthesis_ok ?? null,
    },
  };
}

async function loadTargetsWithCreds(projectId: string): Promise<DastTargetDTO[]> {
  const { data: targets, error } = await supabase
    .from('project_dast_targets')
    .select(
      'id, target_url, label, enabled, detected_runtime, detected_runtime_at, detected_runtime_ttl_at, active_dast_run_id, last_scanned_at, created_at, api_spec_source, api_spec_url, last_synthesized_at, last_synthesis_endpoint_count, last_synthesis_ok',
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
      .select('enabled, scan_profile, scan_timeout_minutes, scope_config')
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
          scan_profile: data.scan_profile,
          scan_timeout_minutes: data.scan_timeout_minutes,
          scope_config: data.scope_config ?? {},
          targets,
        }
      : {
          enabled: false,
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

    // Phase 35 (v1.1) — sweep the target's bucket prefix
    // (`{org}/{target}/`) after the DB cascade. Best-effort: storage failures
    // log but never bubble up — the target row is already gone.
    try {
      await deleteAllSpecsForTarget(access.organizationId, targetId);
    } catch (e) {
      console.warn(
        `[dast] DELETE target ${targetId}: spec cleanup failed (non-fatal): ${
          (e as Error).message
        }`,
      );
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
  // Phase 36 (v1.1) — route-local 1.5MB parser. The replay credential carries
  // the assembled captured-request list (up to HAR_MAX_SERIALIZED_PLAINTEXT_BYTES
  // = 1MB plaintext); other strategies (form / jwt / cookie / recorded) ship
  // <10KB bodies. The global parser is path-gated to SKIP PUT /credentials
  // (see backend/src/index.ts:117-) so this route-local express.json is what
  // actually buffers the body. Without this, a legitimate 150KB replay payload
  // would be rejected by the global 100kb parser and surface as a generic 500.
  express.json({ limit: '1.5mb' }),
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
// PATCH /:projectId/dast/targets/:targetId/spec                 (Phase 35 v1.1)
//
// Update the target's OpenAPI spec source. Body:
//   { api_spec_source: 'synthesized' | 'url' | 'none', api_spec_url?: string }
//
// `url` mode triggers SSRF guard + bounded fetch + swagger-parser strict
// validate inline. Failures map to the SPEC_ERROR_CODES canonical strings
// (frontend mirror in frontend/src/lib/dast-error-codes.ts; CI checks parity).
// ---------------------------------------------------------------------------
router.patch(
  '/:projectId/dast/targets/:targetId/spec',
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

      const sourceCheck = validateSpecSource(req.body?.api_spec_source);
      if (sourceCheck.ok === false) {
        return res.status(400).json({ error: 'invalid_spec_source' });
      }
      const next: 'synthesized' | 'url' | 'none' = sourceCheck.value;

      const update: Record<string, unknown> = {
        api_spec_source: next,
        updated_at: new Date().toISOString(),
      };
      let endpointCount: number | null = null;

      if (next === 'url') {
        const candidateUrl = typeof req.body?.api_spec_url === 'string'
          ? req.body.api_spec_url.trim()
          : '';
        if (candidateUrl.length === 0) {
          return res.status(400).json({ error: 'spec_url_required' });
        }
        const fetched = await validateAndFetchSpecUrl(candidateUrl);
        if (fetched.ok === false) {
          const err = fetched.error;
          // Status mapping: SSRF/required → 400, network → 502, parse → 422,
          // size cap → 413. The frontend's friendlySpecErrorMessage maps the
          // body.error code to user-friendly copy.
          let status = 400;
          if (err.code === 'spec_url_unreachable') status = 502;
          else if (err.code === 'spec_parse_failed') status = 422;
          else if (err.code === 'spec_too_large') status = 413;
          const body: Record<string, unknown> = { error: err.code };
          if ('detail' in err && err.detail) body.detail = err.detail;
          return res.status(status).json(body);
        }
        update.api_spec_url = candidateUrl;
        endpointCount = fetched.endpoint_count;
      } else {
        // synthesized / none — clear any prior URL.
        update.api_spec_url = null;
      }

      const { data: updated, error: updateErr } = await supabase
        .from('project_dast_targets')
        .update(update)
        .eq('id', targetId)
        .select(
          'id, target_url, label, enabled, detected_runtime, detected_runtime_at, detected_runtime_ttl_at, active_dast_run_id, last_scanned_at, created_at, api_spec_source, api_spec_url, last_synthesized_at, last_synthesis_endpoint_count, last_synthesis_ok',
        )
        .single();
      if (updateErr || !updated) {
        console.error('[dast] PATCH /spec update:', updateErr?.message);
        return res.status(500).json({ error: 'Failed to update spec config' });
      }

      // Single activity type for all spec-config changes — metadata carries
      // discriminator so the activity feed can render distinct copy without
      // needing 4 separate types.
      try {
        await createActivity({
          organization_id: access.organizationId,
          user_id: userId,
          activity_type: 'dast_spec.configured',
          description: 'Updated DAST OpenAPI spec config',
          metadata: {
            target_id: targetId,
            from_source: guard.target.api_spec_source,
            to_source: next,
            has_url: next === 'url',
            url_endpoint_count: endpointCount,
          },
        });
      } catch {
        /* non-fatal */
      }

      // Best-effort credential summary refresh — preserves the existing
      // targetRowToDto shape callers rely on.
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
      console.error('[dast] PATCH /spec exception:', e);
      return res.status(500).json({ error: 'Failed to update spec config' });
    }
  },
);

// ---------------------------------------------------------------------------
// GET /:projectId/dast/targets/:targetId/spec/download           (Phase 35 v1.1)
//
// Returns a signed download URL for the active spec. Synthesized mode →
// presigned bucket URL; url mode → upstream URL passthrough (we already
// validated it at PATCH time); none → 404 spec_unavailable.
// ---------------------------------------------------------------------------
router.get(
  '/:projectId/dast/targets/:targetId/spec/download',
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user!.id;
      const { projectId, targetId } = req.params;
      const access = await resolveProjectAccess(userId, projectId);
      if (access.deny) {
        return res.status(access.deny.status).json({ error: access.deny.message });
      }
      // Spec download is a read; gate on view permission rather than
      // manage. Anyone who can see DAST findings can download the spec
      // that produced them.

      const guard = await loadTargetOrDeny(supabase, targetId, projectId, access.organizationId);
      if (isLoadTargetDeny(guard)) return res.status(404).json({ error: 'target_not_found' });

      const source = guard.target.api_spec_source;
      if (source === 'none') {
        return res.status(404).json({ error: 'spec_unavailable' });
      }
      if (source === 'url') {
        if (!guard.target.api_spec_url) {
          return res.status(404).json({ error: 'spec_unavailable' });
        }
        return res.json({
          kind: 'url',
          url: guard.target.api_spec_url,
          expires_at: null,
          content_length: null,
        });
      }
      // synthesized — require at least one successful scan to have produced
      // the bucket object.
      if (!guard.target.last_synthesized_at) {
        return res.status(404).json({ error: 'spec_unavailable' });
      }
      const presigned = await presignSynthesizedSpecDownload(
        access.organizationId,
        targetId,
      );
      if (!presigned) {
        return res.status(404).json({ error: 'spec_unavailable' });
      }
      return res.json({
        kind: presigned.kind,
        url: presigned.url,
        expires_at: presigned.expires_at,
        content_length: null,
      });
    } catch (e: any) {
      console.error('[dast] GET /spec/download exception:', e);
      return res.status(500).json({ error: 'Failed to load spec download' });
    }
  },
);

// ---------------------------------------------------------------------------
// POST /:projectId/dast/targets/:targetId/replay/preview         (Phase 36)
//
// Stateless HAR preview endpoint. Used by the FE Replay tab before the user
// commits a credential — they drop a .har file, we extract the replayable
// requests, scrub URL-query tokens, run the TOTP + non-replayable detectors,
// and return a boolean-only preview shape. No DB writes; no credential row
// touched; no plaintext echoed back beyond the structural metadata.
//
// Body-cap: 1.5MB via route-local express.json (the global parser at
// src/index.ts is path-gated to SKIP this exact route — see
// REPLAY_PREVIEW_PATH there). 100kb default would reject the average HAR.
//
// Privacy:
//   - `express.json` errors carry the failed body bytes on err.body; the
//     route-scoped error handler at the bottom strips them before re-
//     throwing. Defense-in-depth against the global handler at
//     backend/src/index.ts (which also strips, but this is the first gate).
//   - Response carries `Cache-Control: no-store` so no proxy / browser
//     cache holds the preview shape (which carries scrubbed URLs + body
//     sizes for the failed-auth analysis layer).
//   - parseHar emits no log lines on either path. Any 5xx logs only the
//     error code + index — never body / header contents.
// ---------------------------------------------------------------------------
router.post(
  '/:projectId/dast/targets/:targetId/replay/preview',
  // Route-local 1.5MB body cap (HAR files are typically 500KB-1MB).
  express.json({ limit: '1.5mb' }),
  // Route-scoped error handler — converts body-parser 400s into our
  // canonical error_code shape WITHOUT echoing err.body. Mounted as a
  // four-arg middleware so Express recognizes it as an error handler;
  // delegated by `next(err)` from the route handler below.
  async (req: AuthRequest, res, next) => {
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
        return res.status(503).json({ error_code: 'dast_encryption_not_configured' });
      }

      const guard = await loadTargetOrDeny(supabase, targetId, projectId, access.organizationId);
      if (isLoadTargetDeny(guard)) return res.status(404).json({ error: 'target_not_found' });

      const harShape = (req.body as { har?: unknown })?.har;
      if (harShape === undefined) {
        return res.status(422).json({
          error_code: 'invalid_har_shape',
          detail: 'request body must be `{ har: <HAR 1.2 JSON> }`',
        });
      }

      let result;
      try {
        result = parseHar(harShape);
      } catch (e) {
        const code = (e as { error_code?: string }).error_code;
        if (code) {
          return res.status(422).json({
            error_code: code,
            detail: (e as { detail?: string }).detail ?? 'HAR rejected',
          });
        }
        // Unstructured throw — log shape metadata only, never bytes.
        console.error('[dast] /replay/preview unstructured parser failure');
        return res.status(500).json({ error: 'Failed to parse HAR' });
      }

      // No-store / no-cache: the preview carries scrubbed URLs + body sizes
      // that could otherwise sit in a shared proxy cache. Private narrows
      // it further; must-revalidate guards browsers that ignore no-store.
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

      return res.status(200).json({
        requests: result.entries,
        summary: result.summary,
        totp_detected: result.totp_detected,
        non_replayable_warnings: result.non_replayable_warnings,
      });
    } catch (e: any) {
      // Strip body-parser's leaked-body fields BEFORE re-throwing to the
      // global handler. The global handler at backend/src/index.ts also
      // strips these for defense-in-depth, but the closer the strip the
      // safer: a future logger added between here and there can't see
      // them either.
      if (e && typeof e === 'object') {
        if ('body' in e) delete (e as { body?: unknown }).body;
        if ('bodyRaw' in e) delete (e as { bodyRaw?: unknown }).bodyRaw;
        if ('rawBody' in e) delete (e as { rawBody?: unknown }).rawBody;
      }
      console.error('[dast] /replay/preview exception:', e?.message ?? '(no message)');
      return res.status(500).json({ error: 'Failed to parse HAR' });
    }
  },
);

// Route-scoped body-parser error handler. body-parser throws PayloadTooLargeError
// (with .type='entity.too.large') and various SyntaxErrors (with .body /
// .bodyRaw on the error). Convert all to our canonical 413 / 422 codes
// without echoing the bytes. Mounted ONLY on the preview path so other dast
// routes still use the default Express error path.
router.use(
  '/:projectId/dast/targets/:targetId/replay/preview',
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  (err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (!err) return next();
    // Strip leaked-body fields immediately so any downstream log call sees
    // a scrubbed object.
    if (err && typeof err === 'object') {
      if ('body' in err) delete err.body;
      if ('bodyRaw' in err) delete err.bodyRaw;
    }
    if (err.type === 'entity.too.large' || err.status === 413) {
      return res.status(413).json({
        error_code: 'har_too_large',
        detail: 'request body exceeds 1.5MB',
      });
    }
    if (err instanceof SyntaxError || err.type === 'entity.parse.failed') {
      return res.status(422).json({
        error_code: 'invalid_har_shape',
        detail: 'request body is not valid JSON',
      });
    }
    console.error('[dast] /replay/preview body-parser error:', err?.message ?? '(no message)');
    return res.status(500).json({ error: 'Failed to parse request' });
  },
);

// Phase 36 (v1.1) — PUT /credentials route-scoped body-parser error handler.
// Mirrors the preview-route handler above but maps to `replay_payload_too_large`
// since the documented PUT cap (HAR_MAX_SERIALIZED_PLAINTEXT_BYTES=1MB +
// 0.5MB headroom = 1.5MB route-local) is the replay-feature contract.
// Non-replay strategies (form/jwt/cookie/recorded) ship <10KB bodies; if any
// of them ever hit 1.5MB it's because someone's smuggling a HAR through
// auth_strategy='form' and 413 is correct.
router.use(
  '/:projectId/dast/targets/:targetId/credentials',
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  (err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (!err) return next();
    if (err && typeof err === 'object') {
      if ('body' in err) delete err.body;
      if ('bodyRaw' in err) delete err.bodyRaw;
    }
    if (err.type === 'entity.too.large' || err.status === 413) {
      return res.status(413).json({
        error_code: 'replay_payload_too_large',
        detail: 'request body exceeds 1.5MB',
      });
    }
    if (err instanceof SyntaxError || err.type === 'entity.parse.failed') {
      return res.status(422).json({
        error_code: 'invalid_credential_shape',
        detail: 'request body is not valid JSON',
      });
    }
    console.error('[dast] PUT /credentials body-parser error:', err?.message ?? '(no message)');
    return res.status(500).json({ error: 'Failed to parse request' });
  },
);

// ---------------------------------------------------------------------------
// POST /:projectId/dast/targets/:targetId/credentials/test     (v2.1d)
// Queues a dry-run dast_zap job carrying `payload.dry_run: true`. The worker
// branches on that flag and runs the recorded-login probe ONLY (no spider,
// no active-scan, no findings emit, no PDV mutation), writing the test
// result into scan_jobs.error_payload under {kind:'test_result', …}. The
// FE polls GET /dast/jobs?id=<test_job_id> until status is terminal.
//
// 422 wrong-strategy: only recorded credentials are testable; form/jwt/
// cookie use the inline route-side probe at PUT time.
// 503 fly_machine_unavailable: cold worker fails to start within the 60s
// p50 budget — the route deletes the just-queued row so it doesn't sit as
// "queued forever".
// ---------------------------------------------------------------------------
router.post(
  '/:projectId/dast/targets/:targetId/credentials/test',
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
      if (!guard.target.enabled) {
        return res.status(409).json({ error: 'target_disabled' });
      }

      // Phase 36 (v1.1): testable strategies are `recorded` AND `replay`.
      // Form / JWT / cookie validate inline at PUT time via probeFormLogin /
      // JWT exp / shape checks and don't need the dry-run probe.
      const { data: credRow } = await supabase
        .from('project_dast_credentials')
        .select('auth_strategy')
        .eq('target_id', targetId)
        .maybeSingle();
      if (!credRow) {
        return res.status(404).json({ error: 'credentials_not_set' });
      }
      if (credRow.auth_strategy !== 'recorded' && credRow.auth_strategy !== 'replay') {
        return res.status(422).json({
          code: 'unsupported_strategy_for_test',
          detail: 'Only recorded and replay credentials use the Test-login flow; form/jwt/cookie validate at save time.',
        });
      }

      // SPA-detect refresh — same pattern as POST /scan so the test job runs
      // on the right Fly machine shape.
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

      // Read project DAST config for scan_timeout — same as /scan.
      const { data: cfg } = await supabase
        .from('project_dast_config')
        .select('scan_profile, scan_timeout_minutes')
        .eq('project_id', projectId)
        .maybeSingle();
      const scanProfile = cfg?.scan_profile ?? 'auto';
      const scanTimeoutMinutes = cfg?.scan_timeout_minutes ?? 30;

      // v2.1d /criticalreview SVED-1: Queue type='dast_zap_dry_run' (NOT
      // type='dast_zap' + payload.dry_run). The new type is the dispatch
      // discriminator; old workers don't advertise it so claim_scan_job will
      // skip them and a stale worker can never accidentally run a full real
      // scan in place of a Test-login probe. payload.dry_run is retained
      // transitionally for backwards compat and will be removed in v2.1e.
      const testPayload = {
        source: 'credential_test',
        detected_runtime: detectedRuntime,
        dry_run: true,
      };
      // v2.1d /criticalreview RH-1: validateDastJobPayload runs at queue time
      // AND at worker startup. Defense against typo'd keys (dryRun vs
      // dry_run) and against any future internal caller that bypasses the
      // hard-coded literal below. The worker also re-validates after job
      // load — the route layer's check fails fast with a 400 instead of
      // burning a Fly cold start before discovering the typo.
      const payloadGuard = validateDastJobPayload(testPayload);
      if ('__error' in payloadGuard) {
        console.error('[dast] credentials/test invalid payload:', payloadGuard.__error);
        return res.status(400).json({ error: 'invalid_payload', detail: payloadGuard.__error });
      }
      const { data: queued, error: queueError } = await supabase.rpc('queue_scan_job', {
        p_project_id: projectId,
        p_organization_id: access.organizationId,
        p_type: 'dast_zap_dry_run',
        p_payload: testPayload,
        p_target_id: targetId,
        p_target_url: guard.target.target_url,
        p_scan_profile: scanProfile,
        p_timeout_minutes: scanTimeoutMinutes,
        p_trigger_source: 'manual',
        p_triggered_by: userId,
      });

      if (queueError) {
        const detail = queueError.message ?? 'Failed to queue test';
        if (detail.includes('project_concurrent_dast_blocked')) {
          // v2.1d /criticalreview BAD-3 + RSS-2 fix: look up the conflicting
          // job_id and return it in the 409 body so the FE's "Cancel running
          // scan" affordance has a real id to call POST /jobs/:jobId/cancel
          // with. Previously the FE set conflictJobId='unknown' and the
          // Cancel button was gated on `conflictJobId !== 'unknown'`, so the
          // affordance was dead UI.
          const { data: conflict } = await supabase
            .from('scan_jobs')
            .select('id')
            .eq('project_id', projectId)
            .eq('organization_id', access.organizationId)
            .in('type', DAST_SCAN_TYPES)
            .in('status', ['queued', 'processing'])
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();
          return res.status(409).json({
            error: 'project_concurrent_dast_blocked',
            detail,
            conflict_job_id: conflict?.id ?? null,
          });
        }
        if (detail.includes('org_concurrent_dast_cap')) {
          return res.status(409).json({ error: 'org_concurrent_dast_cap', detail });
        }
        if (detail.includes('tenant drift')) {
          return res.status(404).json({ error: 'target_not_found' });
        }
        console.error('[dast] queue_scan_job(test) error:', detail);
        return res.status(500).json({ error: 'Failed to queue test' });
      }

      const job = Array.isArray(queued) ? queued[0] : queued;
      if (!job?.id) {
        console.error('[dast] queue_scan_job(test) returned no row');
        return res.status(500).json({ error: 'Failed to queue test' });
      }

      // Test-login budget (≤60s p50) is unforgiving of Fly cold-start
      // failure. Surface as 503 synchronously AND clean up the queued row
      // so it doesn't sit as "queued forever" — the FE retries on 503.
      try {
        await startDastMachine(detectedRuntime);
      } catch (e: any) {
        console.error(
          `[dast] startDastMachine(test) failed (cleaning up queued row): ${e?.message ?? e}`,
        );
        // Best-effort delete; we own the row by ID and it's still 'queued'.
        await supabase.from('scan_jobs').delete().eq('id', job.id);
        return res.status(503).json({ error: 'fly_machine_unavailable' });
      }

      // Audit-log entry (best-effort; activities table is gitignored from
      // failure cascades — never break the user-facing 202 over a log write).
      //
      // Phase 36 / Decision 16: reuse `dast_login_test.run` activity_type with
      // metadata.strategy so the FE activity feed can distinguish recorded
      // from replay without adding a parallel activity type.
      try {
        await createActivity({
          organization_id: access.organizationId,
          user_id: userId,
          activity_type: 'dast_login_test.run',
          description:
            credRow.auth_strategy === 'replay'
              ? 'Started replay (HAR) login test'
              : 'Started recorded-login test',
          metadata: {
            test_job_id: job.id,
            target_id: targetId,
            strategy: credRow.auth_strategy,
          },
        });
      } catch {
        /* createActivity already swallows; this catch is defensive */
      }

      return res.status(202).json({
        test_job_id: job.id,
        status: 'queued',
      });
    } catch (e: any) {
      console.error('[dast] POST credentials/test exception:', e);
      return res.status(500).json({ error: 'Failed to trigger test' });
    }
  },
);

// ---------------------------------------------------------------------------
// POST /:projectId/dast/jobs/:jobId/cancel                     (v2.1d)
// User-initiated cancellation of a queued/processing scan_jobs row. Backs
// the editor's "Cancel running scan" affordance for the Test-login flow
// concurrency mitigation: a user blocked by a long real scan can cancel
// it, freeing the 1/project DAST cap so Test-login becomes available.
//
// Delegates to the phase34 cancel_scan_job(p_job_id, p_organization_id) RPC
// — atomic UPDATE scoped to the caller's org. RPC empty-return → 404 (cross-
// org or missing) OR 409 (job not in cancellable state) — distinguished by
// a follow-up status lookup.
// ---------------------------------------------------------------------------
router.post(
  '/:projectId/dast/jobs/:jobId/cancel',
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user!.id;
      const { projectId, jobId } = req.params;

      const access = await resolveProjectAccess(userId, projectId);
      if (access.deny) {
        return res.status(access.deny.status).json({ error: access.deny.message });
      }
      if (!(await checkOrgManageIntegrationsPermission(userId, access.organizationId))) {
        return res.status(403).json({ error: 'You do not have permission to manage integrations' });
      }

      // v2.1d /criticalreview HEH-1 fix: pass projectId so the RPC AND-binds
      // project_id (and filters type to the DAST family). Without this, an
      // org-level manage_integrations holder could cancel scans in projects
      // they have no team access to.
      const { data: cancelled, error: cancelErr } = await supabase.rpc('cancel_scan_job', {
        p_job_id: jobId,
        p_organization_id: access.organizationId,
        p_project_id: projectId,
      });
      if (cancelErr) {
        console.error('[dast] cancel_scan_job RPC error:', cancelErr.message);
        return res.status(500).json({ error: 'Failed to cancel scan' });
      }

      const row = Array.isArray(cancelled) ? cancelled[0] : cancelled;
      if (!row) {
        // Empty return — distinguish 404 (missing / cross-project / cross-org
        // / non-DAST type) from 409 (job exists in caller's project but not
        // in cancellable state). The probe must scope by project_id AND
        // organization_id AND DAST type so a cross-project caller still
        // returns 404 without leaking current_status of foreign rows.
        // Destructure error so a transient supabase blip doesn't silently
        // return 404 (per /criticalreview EHA-4).
        const { data: probe, error: probeErr } = await supabase
          .from('scan_jobs')
          .select('status')
          .eq('id', jobId)
          .eq('organization_id', access.organizationId)
          .eq('project_id', projectId)
          .in('type', DAST_SCAN_TYPES)
          .maybeSingle();
        if (probeErr) {
          console.error('[dast] cancel probe error:', probeErr.message);
          return res.status(500).json({ error: 'Failed to look up scan status' });
        }
        if (!probe) {
          return res.status(404).json({ error: 'job_not_found' });
        }
        return res.status(409).json({
          code: 'job_not_cancellable',
          current_status: probe.status,
        });
      }

      // Audit-log entry. Best-effort.
      try {
        await createActivity({
          organization_id: access.organizationId,
          user_id: userId,
          activity_type: 'dast_scan.cancelled',
          description: 'Cancelled DAST scan',
          metadata: { job_id: jobId, prior_status: row.status === 'cancelled' ? null : row.status },
        });
      } catch {
        /* swallow */
      }

      return res.json({ job_id: jobId, status: 'cancelled' });
    } catch (e: any) {
      console.error('[dast] POST cancel exception:', e);
      return res.status(500).json({ error: 'Failed to cancel scan' });
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

    // Engine selection. Validated AFTER the permission + target-tenant guards
    // so an unsupported engine value cannot probe target existence. Defaults
    // to 'zap'; maps to the scan_jobs.type the worker dispatches on.
    const engine = req.body?.engine ?? 'zap';
    if (engine !== 'zap' && engine !== 'nuclei') {
      return res.status(400).json({ code: 'unsupported_engine', supported: ['zap', 'nuclei'] });
    }
    const scanJobType = engine === 'nuclei' ? 'dast_nuclei' : 'dast_zap';

    // v2.1d — Nuclei + recorded credential is structurally unsupported:
    // Nuclei is a template engine with no auth-replay execution model.
    // Reject before queue so the user gets a fast, actionable error. We
    // fetch auth_strategy via a SECOND guarded query (not via
    // loadTargetOrDeny) to preserve loadTargetOrDeny's single-SELECT timing-
    // side-channel posture.
    if (engine === 'nuclei') {
      const { data: credForEngine } = await supabase
        .from('project_dast_credentials')
        .select('auth_strategy')
        .eq('target_id', targetId)
        .maybeSingle();
      if (credForEngine?.auth_strategy === 'recorded') {
        return res.status(400).json({
          code: 'unsupported_recorded_on_nuclei',
          detail:
            'Recorded login can only be replayed by the ZAP engine. Re-run with engine=zap.',
        });
      }

      // Phase 35 (v1.1) — Nuclei has no native OpenAPI import. Target rows
      // configured for synthesized or url spec must run on ZAP. The
      // api_spec_source field is on loadTargetOrDeny's widened SELECT.
      if (guard.target.api_spec_source && guard.target.api_spec_source !== 'none') {
        return res.status(422).json({
          code: 'unsupported_openapi_on_nuclei',
          detail:
            'OpenAPI mode is currently ZAP-only. Switch engine to ZAP or set spec source to None.',
        });
      }
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

    // The worker reads scan_profile from the payload JSONB (pipeline.ts
    // `payload.scan_profile ?? 'auto'`), NOT the scan_jobs.scan_profile column —
    // so without this the configured profile never reaches the engine and every
    // scan ran passive-only ('auto'). Carry it in the payload too.
    const scanPayload = {
      source: 'manual_dast_scan',
      detected_runtime: detectedRuntime,
      engine,
      scan_profile: scanProfile,
    };
    // v2.1d /criticalreview RH-1: defense-in-depth payload validation at
    // queue time. The hard-coded literal above is safe today; the validator
    // catches any future caller (cron, Aegis tool, webhook) that constructs
    // a malformed payload.
    const scanPayloadGuard = validateDastJobPayload(scanPayload);
    if ('__error' in scanPayloadGuard) {
      console.error('[dast] /scan invalid payload:', scanPayloadGuard.__error);
      return res.status(400).json({ error: 'invalid_payload', detail: scanPayloadGuard.__error });
    }
    const { data: queued, error: queueError } = await supabase.rpc('queue_scan_job', {
      p_project_id: projectId,
      p_organization_id: access.organizationId,
      p_type: scanJobType,
      p_payload: scanPayload,
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
        'id, status, trigger_source, target_id, target_url, scan_profile, findings_count, duration_seconds, started_at, completed_at, error, error_category, error_payload, attempts, created_at',
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

    // Phase 36 / Patch G — `error_payload.diagnostic_responses` (populated by
    // the worker on a failed Test-replay) can carry 256-byte response-body
    // excerpts. Strip them for any caller lacking manage_integrations: a
    // regular project member with view access can still see test result
    // shape + failure kind, but never the raw bodies. Credential editors
    // still get the full surface for debugging.
    const canSeeDiagnostics = await checkOrgManageIntegrationsPermission(
      userId,
      access.organizationId,
    );

    const jobs: DastJobDTO[] = (data ?? []).map((row: any) => {
      let errorPayload = row.error_payload ?? null;
      if (
        errorPayload
        && !canSeeDiagnostics
        && typeof errorPayload === 'object'
        && 'diagnostic_responses' in errorPayload
      ) {
        // Shallow clone + null-out the leak surface; preserve the
        // discriminated-union .kind + the rest of the failure-context fields.
        errorPayload = { ...errorPayload, diagnostic_responses: null };
      }
      return {
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
        // v2.1d — discriminated union, FE switches on .kind for the recorded-
        // login outcome (test_result / pre_flight_failed / session_loss).
        // Always JSONB-shaped; null when no auth-failure / no test result.
        error_payload: errorPayload,
        attempts: row.attempts ?? 0,
        created_at: row.created_at,
      };
    });
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
    // Opt-in: resolve the target server-side instead of forcing the caller to
    // do a jobs→findings waterfall. The Findings tab used to fetch /dast/jobs,
    // pick `jobs.find(j => j.target_id)`, then fetch /dast/findings — two
    // serial round-trips on the project-open critical path. With this flag the
    // server runs the same selection and returns findings in one request.
    const resolveLatestTarget = req.query.resolve_target === 'latest';

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }

    // Target resolution + tenant guard + findings shaping live in
    // lib/dast-findings.ts so the project findings-bundle reuses them verbatim.
    const result = await loadDastFindings(supabase, {
      projectId,
      organizationId: access.organizationId,
      limit,
      filterTargetId,
      resolveLatestTarget,
    });
    if (result.deny) return res.status(result.deny.status).json({ error: result.deny.error });
    return res.json(result.findings);
  } catch (e: any) {
    console.error('[dast] GET findings exception:', e);
    return res.status(500).json({ error: 'Failed to load DAST findings' });
  }
});

export default router;
