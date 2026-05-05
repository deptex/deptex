/**
 * Organization-wide malicious-package allowlist routes.
 *
 *   GET    /api/organizations/:id/malicious-allowlist          → list active entries
 *   POST   /api/organizations/:id/malicious-allowlist          → add entry (manage_organization_settings)
 *   DELETE /api/organizations/:id/malicious-allowlist/:entryId → soft-delete (manage_organization_settings)
 *
 * The list endpoint gates on org membership only — every member can see what
 * the org has allowlisted, but only members with `manage_organization_settings`
 * can add or revoke entries. Cross-org requests return 404 (not 403) so an
 * attacker probing for valid org IDs can't distinguish "exists but no access"
 * from "doesn't exist".
 */
import express from 'express';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { canonicalizeEcosystem, CANONICAL_ECOSYSTEMS } from '../lib/malicious/ecosystem';

const router = express.Router();
router.use(authenticateUser);

// ─── helpers ───────────────────────────────────────────────────────────────

async function isOrgMember(userId: string, orgId: string): Promise<boolean> {
  // Inline membership check — matches the pattern used in project-access.ts
  // for the read gate (no helper needed for org-only routes).
  const { data, error } = await supabase
    .from('organization_members')
    .select('user_id')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .maybeSingle();
  return !error && !!data;
}

async function hasOrgPermission(
  userId: string,
  orgId: string,
  permission: string,
): Promise<boolean> {
  const { data: member, error } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .maybeSingle();
  if (error || !member) return false;
  if (member.role === 'owner') return true;

  const { data: roleRow } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', member.role)
    .maybeSingle();
  return roleRow?.permissions?.[permission] === true;
}

async function resolveCallerEmail(req: AuthRequest): Promise<string | null> {
  if (req.user?.email) return req.user.email;
  // API-token auth omits email — look it up so the audit field stays populated.
  const { data } = await supabase
    .from('users')                              // public.users mirrors auth.users.email at signup
    .select('email')
    .eq('id', req.user!.id)
    .maybeSingle();
  return data?.email ?? null;
}

// Reject anything that looks like a semver range so v2 keeps the contract
// "exact-string match or null" and v3 can introduce range semantics cleanly.
const RANGE_OPERATOR_RE = /[\^~<>=*]|(\s+-\s+)/;

type ValidationResult =
  | { ok: true; value: string | null }
  | { ok: false; error: string };

function validateVersionOrNull(input: unknown): ValidationResult {
  if (input === null || input === undefined || input === '') return { ok: true, value: null };
  if (typeof input !== 'string') return { ok: false, error: 'version must be a string or null' };
  const trimmed = input.trim();
  if (trimmed === '') return { ok: true, value: null };
  if (trimmed.length > 200) return { ok: false, error: 'version must be ≤200 characters' };
  if (RANGE_OPERATOR_RE.test(trimmed)) {
    return { ok: false, error: 'version must be an exact version string; semver-range support is deferred to v3' };
  }
  return { ok: true, value: trimmed };
}

interface AllowlistRow {
  id: string;
  organization_id: string;
  package_name: string;
  version: string | null;
  ecosystem: string;
  reason: string;
  added_by: string | null;
  added_by_email: string;
  added_at: string;
  revoked_at: string | null;
  revoked_by: string | null;
  revoked_by_email: string | null;
}

function publicShape(row: AllowlistRow) {
  return {
    id: row.id,
    package_name: row.package_name,
    version: row.version,
    ecosystem: row.ecosystem,
    reason: row.reason,
    added_by: row.added_by,
    added_by_email: row.added_by_email,
    added_at: row.added_at,
    revoked_at: row.revoked_at,
  };
}

// ─── GET list (active only) ────────────────────────────────────────────────

router.get('/:id/malicious-allowlist', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;

    if (!(await isOrgMember(userId, orgId))) {
      // 404 not 403 — don't leak which org IDs exist.
      return res.status(404).json({ error: 'Organization not found' });
    }

    const { data, error } = await supabase
      .from('organization_malicious_allowlist')
      .select('*')
      .eq('organization_id', orgId)
      .is('revoked_at', null)
      .order('added_at', { ascending: false });
    if (error) throw error;

    const rows = (data ?? []) as AllowlistRow[];
    res.json({ data: rows.map(publicShape) });
  } catch (error: any) {
    console.error('Error listing malicious allowlist:', error);
    res.status(500).json({ error: error.message || 'Failed to list allowlist entries' });
  }
});

// ─── POST add entry ────────────────────────────────────────────────────────

router.post('/:id/malicious-allowlist', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;

    if (!(await isOrgMember(userId, orgId))) {
      return res.status(404).json({ error: 'Organization not found' });
    }
    if (!(await hasOrgPermission(userId, orgId, 'manage_organization_settings'))) {
      return res.status(403).json({ error: 'Requires manage_organization_settings permission' });
    }

    const body = req.body ?? {};

    // package_name
    if (typeof body.package_name !== 'string' || body.package_name.trim() === '') {
      return res.status(400).json({ error: 'package_name is required' });
    }
    const packageName = body.package_name.trim();
    if (packageName.length > 256) {
      return res.status(400).json({ error: 'package_name must be ≤256 characters' });
    }

    // ecosystem (canonicalize first so 'php' / 'rust' / etc. land as 'composer' / 'cargo')
    if (typeof body.ecosystem !== 'string') {
      return res.status(400).json({ error: 'ecosystem is required' });
    }
    const eco = canonicalizeEcosystem(body.ecosystem);
    if (!eco) {
      return res.status(400).json({
        error: `ecosystem must be one of ${CANONICAL_ECOSYSTEMS.join(', ')}`,
      });
    }

    // version (exact string or null)
    const verResult: ValidationResult = validateVersionOrNull(body.version);
    if (verResult.ok === false) {
      return res.status(400).json({ error: verResult.error });
    }

    // reason — server accepts any non-empty string. Frontend enforces min-10-char.
    if (typeof body.reason !== 'string' || body.reason.trim().length === 0) {
      return res.status(400).json({ error: 'reason is required' });
    }
    const reason = body.reason.trim();
    if (reason.length > 2000) {
      return res.status(400).json({ error: 'reason must be ≤2000 characters' });
    }

    const callerEmail = await resolveCallerEmail(req);
    if (!callerEmail) {
      // Audit-trail integrity: refuse to write a row without an email anchor.
      return res.status(400).json({ error: 'Caller has no email on file; cannot record audit identity' });
    }

    const { data: inserted, error: insertError } = await supabase
      .from('organization_malicious_allowlist')
      .insert({
        organization_id: orgId,
        package_name: packageName,
        version: verResult.value,
        ecosystem: eco,
        reason,
        added_by: userId,
        added_by_email: callerEmail,
      })
      .select('*')
      .single();

    if (insertError) {
      // Postgres unique-violation = duplicate (org, pkg, version, ecosystem)
      if ((insertError as any).code === '23505') {
        return res.status(409).json({ error: 'An allowlist entry for this package + version already exists' });
      }
      throw insertError;
    }

    res.status(201).json(publicShape(inserted as AllowlistRow));
  } catch (error: any) {
    console.error('Error adding malicious allowlist entry:', error);
    res.status(500).json({ error: error.message || 'Failed to add allowlist entry' });
  }
});

// ─── DELETE soft-revoke ────────────────────────────────────────────────────

router.delete('/:id/malicious-allowlist/:entryId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    const entryId = req.params.entryId;

    if (!(await isOrgMember(userId, orgId))) {
      return res.status(404).json({ error: 'Organization not found' });
    }
    if (!(await hasOrgPermission(userId, orgId, 'manage_organization_settings'))) {
      return res.status(403).json({ error: 'Requires manage_organization_settings permission' });
    }

    // Cross-org probe: same 404 for "no such entry" and "entry belongs to a
    // different org". Also already-revoked entries return 404 (idempotency
    // would mask whether revocation succeeded).
    const { data: existing } = await supabase
      .from('organization_malicious_allowlist')
      .select('id, organization_id, revoked_at')
      .eq('id', entryId)
      .maybeSingle();

    if (!existing || existing.organization_id !== orgId || existing.revoked_at !== null) {
      return res.status(404).json({ error: 'Allowlist entry not found' });
    }

    const callerEmail = await resolveCallerEmail(req);

    const { error: updateError } = await supabase
      .from('organization_malicious_allowlist')
      .update({
        revoked_at: new Date().toISOString(),
        revoked_by: userId,
        revoked_by_email: callerEmail,
      })
      .eq('id', entryId)
      .eq('organization_id', orgId);  // belt-and-braces: scope by org_id even though we just verified

    if (updateError) throw updateError;
    res.json({ success: true });
  } catch (error: any) {
    console.error('Error revoking malicious allowlist entry:', error);
    res.status(500).json({ error: error.message || 'Failed to revoke allowlist entry' });
  }
});

export default router;
