import { useCallback, useEffect, useState } from 'react';
import { useOutletContext, useParams } from 'react-router-dom';
import {
  api,
  type Organization,
  type FindingTrackerLink,
  type FindingGroupSuppression,
  type FindingAcknowledgement,
} from '../../lib/api';
import { teamBundleToRows } from '../../lib/team-findings';
import VulnerabilityExpandableTable, {
  type SecurityTableRow,
} from '../../components/security/VulnerabilityExpandableTable';
import OrganizationVulnerabilitiesTableSkeleton from '../../components/security/OrganizationVulnerabilitiesTableSkeleton';
import PageHeader from '../../components/PageHeader';

interface OrganizationContextType {
  organization: Organization | null;
  /** Effective permissions resolved by OrganizationLayout (fresh DB role perms,
   *  then cache, then org payload). `organization.permissions` is often null. */
  userPermissions?: Record<string, boolean> | null;
}

export default function OrganizationFindingsPage() {
  const { id: orgId } = useParams<{ id: string }>();
  const { organization, userPermissions } = useOutletContext<OrganizationContextType>();
  const organizationId = organization?.id ?? orgId ?? '';

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [allRows, setAllRows] = useState<SecurityTableRow[]>([]);
  const [trackerLinks, setTrackerLinks] = useState<FindingTrackerLink[]>([]);
  const [groupSuppressions, setGroupSuppressions] = useState<FindingGroupSuppression[]>([]);
  const [acknowledgements, setAcknowledgements] = useState<FindingAcknowledgement[]>([]);

  const loadTrackerLinks = useCallback(async () => {
    if (!organizationId) return;
    // Three INDEPENDENT fetches — a failure in one (e.g. a route the running
    // backend doesn't have yet) must not block the others, or the links (and the
    // resolved-✓ external_state they carry) silently freeze at a stale snapshot.
    api.getOrgTrackerLinks(organizationId).then(({ links }) => setTrackerLinks(links)).catch(() => {});
    api.getOrgGroupSuppressions(organizationId).then(({ suppressions }) => setGroupSuppressions(suppressions)).catch(() => {});
    api.getOrgAcknowledgements(organizationId).then(({ acknowledgements }) => setAcknowledgements(acknowledgements)).catch(() => {});
  }, [organizationId]);

  // Load all findings across the org in ONE request. The server fans every finding
  // type across all accessible projects (SCA as one bounded cross-project query, the
  // other types per-project), tags each row with project_id/name/framework, and
  // returns the org-wide chip maps alongside — replacing the old getProjects + bulk
  // CVE + per-project fan-out of 7. The whole set is swapped in once (a status-change
  // refresh keeps the current rows on screen until the swap; no blank flash).
  const load = useCallback(async (isRefresh = false) => {
    if (!organizationId) return;
    if (!isRefresh) {
      setLoading(true);
      setAllRows([]);
    }
    setError(null);
    try {
      const bundle = await api.getOrgFindings(organizationId);
      // Chip maps ride along in the bundle (org-wide, fetched once server-side).
      setTrackerLinks(bundle.trackerLinks ?? []);
      setGroupSuppressions(bundle.groupSuppressions ?? []);
      setAcknowledgements(bundle.acknowledgements ?? []);
      const { rows } = teamBundleToRows(bundle);
      setAllRows(rows);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to load security findings');
      if (!isRefresh) setAllRows([]);
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!organizationId) {
    return (
      <main className="flex h-svh w-full flex-col bg-background">
        <PageHeader title="Findings" fullWidth centerTitle />
        <div className="px-4 py-6 sm:px-6">
          <p className="text-sm text-foreground-secondary">Loading organization…</p>
        </div>
      </main>
    );
  }

  // Full-bleed work surface (Sentry/Linear/Vercel pattern): slim fixed header
  // band, table spans the content area, scrolling lives in the content pane —
  // not a centered max-w reading column.
  return (
    <main className="flex h-svh w-full flex-col bg-background">
      <PageHeader title="Findings" fullWidth centerTitle />
      <div className="custom-scrollbar min-h-0 flex-1 overflow-y-auto">
        <div className="w-full space-y-4 px-4 py-4 sm:px-6">
          {error && (
            <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}

          {/* Flat findings table — non-embedded mode brings its own toolbar,
              thead, and rounded card frame. */}
          {loading && allRows.length === 0 ? (
            <OrganizationVulnerabilitiesTableSkeleton />
          ) : (
            <VulnerabilityExpandableTable
              organizationId={organizationId}
              rows={allRows}
              canManageFindings={!!userPermissions?.manage_findings}
              canTriggerFix={!!userPermissions?.trigger_fix}
              trackerLinks={trackerLinks}
              groupSuppressions={groupSuppressions}
              acknowledgements={acknowledgements}
              onTrackerChange={() => void loadTrackerLinks()}
              onAckChange={() => void loadTrackerLinks()}
              onStatusChange={() => { void load(true); void loadTrackerLinks(); }}
            />
          )}
        </div>
      </div>
    </main>
  );
}
