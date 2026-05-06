/**
 * Per-package capability tag lookup.
 *
 *   GET /api/organizations/:id/packages/:ecosystem/:packageName/:version/capabilities
 *
 * Returns the row from `package_capabilities` for the requested
 * (package, version, ecosystem) tuple. Capability data is global cache —
 * the row contains no org-derived data — but the URL is org-scoped to
 * prevent enumeration of capability data through random org IDs (a
 * cross-org request returns 404, not 403, so the org-existence side
 * channel is closed).
 *
 * 404 on cache miss until the next pipeline run unpacks + scans the
 * package; the frontend renders the "scan pending" empty state in that
 * case.
 */
import express from 'express';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { canonicalizeEcosystem } from '../lib/malicious/ecosystem';

const router = express.Router();
router.use(authenticateUser);

const CAPABILITY_KEYS = [
  'spawns_processes',
  'network_io',
  'eval_dynamic',
  'native_addon_load',
  'filesystem_write',
  'crypto_operations',
  'serialization_deser',
  'install_script',
  'dns_query',
  'websocket',
  'process_signal',
  'encrypted_payload',
  'dynamic_import',
  'reads_env',
  'clipboard_access',
] as const;

async function isOrgMember(userId: string, orgId: string): Promise<boolean> {
  const { data, error } = await supabase
    .from('organization_members')
    .select('user_id')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .maybeSingle();
  return !error && !!data;
}

router.get(
  '/:id/packages/:ecosystem/:packageName/:version/capabilities',
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user!.id;
      const orgId = req.params.id;

      if (!(await isOrgMember(userId, orgId))) {
        // 404 not 403 — don't leak which org IDs exist.
        return res.status(404).json({ error: 'Organization not found' });
      }

      const eco = canonicalizeEcosystem(req.params.ecosystem);
      if (!eco) {
        return res.status(404).json({ error: 'Capability data not available for this package' });
      }

      const packageName = req.params.packageName;
      const version = req.params.version;

      const { data, error } = await supabase
        .from('package_capabilities')
        .select(
          [
            'package_name',
            'version',
            'ecosystem',
            'scanner_version',
            'scanned_at',
            'scan_error',
            ...CAPABILITY_KEYS,
          ].join(', '),
        )
        .eq('package_name', packageName)
        .eq('version', version)
        .eq('ecosystem', eco)
        .maybeSingle();

      if (error) throw error;
      if (!data) {
        return res.status(404).json({ error: 'Capability data not available for this package' });
      }

      const row = data as unknown as Record<string, unknown>;
      const capabilities: Record<string, boolean> = {};
      for (const k of CAPABILITY_KEYS) capabilities[k] = row[k] === true;

      res.json({
        package_name: row.package_name,
        version: row.version,
        ecosystem: row.ecosystem,
        scanner_version: row.scanner_version,
        scanned_at: row.scanned_at,
        scan_error: row.scan_error,
        capabilities,
      });
    } catch (error: any) {
      console.error('Error fetching package capabilities:', error);
      res.status(500).json({ error: error.message || 'Failed to fetch capabilities' });
    }
  },
);

export default router;
