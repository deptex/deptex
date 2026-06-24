import { useCallback, useEffect, useState } from 'react';
import { useOutletContext, useParams } from 'react-router-dom';
import {
  api,
  type Organization,
  type ProjectVulnerability,
  type FindingTrackerLink,
  type FindingGroupSuppression,
  type FindingAcknowledgement,
} from '../../lib/api';
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

const PER_PAGE_PER_TYPE = 100;

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

  // Load every finding type across the org into the unified table: one org-wide
  // CVE request + a per-project fan-out for the other types (secrets, semgrep,
  // IaC, container, malicious, DAST, data-flow).
  //
  // On first load each project's rows are appended the moment they land, so the
  // table appears as soon as the first results arrive and fills in progressively
  // rather than waiting for the slowest project. A status-change refresh keeps the
  // current rows on screen and swaps the fresh set in one shot at the end (no blank
  // flash). v2 backlog collapses the per-project fan-out into one bundle endpoint.
  const load = useCallback(async (isRefresh = false) => {
    if (!organizationId) return;
    if (!isRefresh) {
      setLoading(true);
      setAllRows([]);
    }
    setError(null);
    try {
      const projectList = await api.getProjects(organizationId);
      const nameById = new Map(projectList.map((p) => [p.id, p.name]));
      const frameworkById = new Map(projectList.map((p) => [p.id, p.framework ?? null]));

      const collected: SecurityTableRow[] = [];
      const flush = (rows: SecurityTableRow[]) => {
        if (!rows.length) return;
        collected.push(...rows);
        if (!isRefresh) setAllRows((prev) => [...prev, ...rows]);
      };

      const tasks: Promise<void>[] = [];

      // Org-wide CVEs in a single request.
      tasks.push(
        api
          .getOrganizationVulnerabilities(organizationId, { page: 1, per_page: PER_PAGE_PER_TYPE * 2 })
          .then((res) => {
            flush(
              (res.data as ProjectVulnerability[]).map((v) => ({
                type: 'vulnerability' as const,
                data: {
                  ...v,
                  project_framework:
                    (v as any).project_framework ?? frameworkById.get((v as any).project_id) ?? null,
                } as ProjectVulnerability,
              })),
            );
          })
          .catch((e) => console.error('Failed to load org vulnerabilities', e)),
      );

      // Per-project: the non-CVE finding types. Each project appends independently.
      for (const p of projectList) {
        tasks.push(
          (async () => {
            const projectName = nameById.get(p.id);
            const framework = frameworkById.get(p.id) ?? null;
            const stamp = (item: any) => ({ ...item, project_name: projectName, project_framework: framework });
            const [secret, semgrep, iac, container, malicious, dast, codeFlow] = await Promise.allSettled([
              api.getProjectSecretFindings(organizationId, p.id, 1, PER_PAGE_PER_TYPE),
              api.getProjectSemgrepFindings(organizationId, p.id, 1, PER_PAGE_PER_TYPE),
              api.getProjectIaCFindings(organizationId, p.id, { perPage: PER_PAGE_PER_TYPE, status: 'open' }),
              api.getProjectContainerFindings(organizationId, p.id, { perPage: PER_PAGE_PER_TYPE, status: 'open' }),
              api.maliciousFindings.list(organizationId, p.id, 1, PER_PAGE_PER_TYPE),
              // DAST is per-target: resolve the latest scan's target, then load its
              // findings. Most projects have no DAST target, so this short-circuits to
              // an empty list after one cheap jobs request.
              (async () => {
                const jobs = await api.getDastJobs(p.id, { limit: 5 });
                const targetId = jobs.find((j) => j.target_id)?.target_id ?? undefined;
                return targetId ? await api.getDastFindings(p.id, { limit: PER_PAGE_PER_TYPE, targetId }) : [];
              })(),
              api.getCodeFlowFindings(organizationId, p.id),
            ]);
            const rows: SecurityTableRow[] = [];
            if (secret.status === 'fulfilled') for (const it of secret.value.data ?? []) rows.push({ type: 'secret', data: stamp(it) });
            if (semgrep.status === 'fulfilled') for (const it of semgrep.value.data ?? []) rows.push({ type: 'semgrep', data: stamp(it) });
            if (iac.status === 'fulfilled') for (const it of iac.value.data ?? []) rows.push({ type: 'iac', data: stamp(it) });
            if (container.status === 'fulfilled') for (const it of container.value.data ?? []) rows.push({ type: 'container', data: stamp(it) });
            if (malicious.status === 'fulfilled') for (const it of malicious.value.data ?? []) rows.push({ type: 'malicious', data: stamp(it) });
            if (dast.status === 'fulfilled') for (const it of dast.value ?? []) rows.push({ type: 'dast', data: stamp(it) });
            if (codeFlow.status === 'fulfilled') for (const it of codeFlow.value.data ?? []) rows.push({ type: 'taint_flow', data: stamp(it) });
            flush(rows);
          })(),
        );
      }

      await Promise.all(tasks);
      if (isRefresh) setAllRows(collected);
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

  useEffect(() => {
    void loadTrackerLinks();
  }, [loadTrackerLinks]);

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
