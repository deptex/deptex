import { useCallback, useEffect, useState } from 'react';
import { useOutletContext, useParams } from 'react-router-dom';
import { api, type Organization, type ProjectVulnerability } from '../../lib/api';
import VulnerabilityExpandableTable from '../../components/security/VulnerabilityExpandableTable';
import OrganizationVulnerabilitiesTableSkeleton from '../../components/security/OrganizationVulnerabilitiesTableSkeleton';
import { Button } from '../../components/ui/button';

interface OrganizationContextType {
  organization: Organization | null;
}

export default function OrganizationVulnerabilitiesTabPage() {
  const { id: orgId } = useParams<{ id: string }>();
  const { organization } = useOutletContext<OrganizationContextType>();
  const [listLoading, setListLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [vulns, setVulns] = useState<ProjectVulnerability[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const perPage = 50;

  const organizationId = organization?.id ?? orgId ?? '';

  const loadPage = useCallback(
    async (p: number) => {
      if (!organizationId) return;
      setListLoading(true);
      setListError(null);
      try {
        const res = await api.getOrganizationVulnerabilities(organizationId, {
          page: p,
          per_page: perPage,
        });
        setVulns(res.data);
        setTotal(res.total);
        setPage(res.page);
      } catch (e: any) {
        setListError(e?.message ?? 'Failed to load vulnerabilities');
        setVulns([]);
        setTotal(0);
      } finally {
        setListLoading(false);
      }
    },
    [organizationId, perPage]
  );

  useEffect(() => {
    if (!organizationId) return;
    void loadPage(1);
  }, [organizationId, loadPage]);

  const totalPages = Math.max(1, Math.ceil(total / perPage));

  if (!organizationId) {
    return (
      <main className="flex flex-col flex-1 min-h-0 w-full bg-background overflow-y-auto">
        <div className="mx-auto max-w-7xl w-full px-4 sm:px-6 lg:px-8 py-6">
          <p className="text-sm text-foreground-secondary">Loading organization…</p>
        </div>
      </main>
    );
  }

  return (
    <main className="flex flex-col flex-1 min-h-0 w-full bg-background overflow-y-auto">
      <div className="mx-auto max-w-7xl w-full px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        <div>
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <h1 className="text-lg font-semibold text-foreground">Vulnerabilities</h1>
            {!listLoading && (
              <span className="text-sm tabular-nums text-muted-foreground">{total.toLocaleString()} open</span>
            )}
          </div>
          <p className="text-sm text-muted-foreground mt-1.5 max-w-2xl leading-relaxed">
            Dependency advisories across your workspace.
          </p>
        </div>

        {listError && (
          <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {listError}
          </div>
        )}

        {listLoading && vulns.length === 0 ? (
          <OrganizationVulnerabilitiesTableSkeleton />
        ) : (
          <>
            <VulnerabilityExpandableTable organizationId={organizationId} vulnerabilities={vulns} />
            {totalPages > 1 && (
              <div className="flex items-center justify-between gap-3 pt-2">
                <span className="text-xs text-foreground-secondary">
                  Page {page} of {totalPages}
                </span>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-8"
                    disabled={listLoading || page <= 1}
                    onClick={() => void loadPage(page - 1)}
                  >
                    Previous
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-8"
                    disabled={listLoading || page >= totalPages}
                    onClick={() => void loadPage(page + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </main>
  );
}
