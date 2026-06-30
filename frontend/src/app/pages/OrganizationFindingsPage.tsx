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

  // App globally hides body/html scrollbars in Main.css. Restore them on this
  // route via a scoped class — same trick as Compliance.
  useEffect(() => {
    document.documentElement.classList.add('security-scrollbar');
    document.body.classList.add('security-scrollbar');
    return () => {
      document.documentElement.classList.remove('security-scrollbar');
      document.body.classList.remove('security-scrollbar');
    };
  }, []);

  if (!organizationId) {
    return (
      <main className="flex flex-col flex-1 min-h-0 w-full bg-background">
        <div className="mx-auto max-w-7xl w-full px-4 sm:px-6 lg:px-8 py-8">
          <p className="text-sm text-foreground-secondary">Loading organization…</p>
        </div>
      </main>
    );
  }

  return (
    <main className="flex flex-col flex-1 min-h-0 w-full bg-background">
      <div className="mx-auto max-w-7xl w-full px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {/* Title */}
        <div>
          <h1 className="text-2xl font-bold text-foreground">Findings</h1>
          <p className="mt-1 max-w-2xl text-sm text-foreground-secondary">
            All findings across your organization.
          </p>
        </div>

        {error && (
          <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}

        {/* Flat findings table — non-embedded mode brings its own Type+Project
            filter bar, thead, and rounded card frame. */}
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
    </main>
  );
}
