import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  TowerControl,
  Loader2,
  ShieldAlert,
  Eye,
  ExternalLink,
  Package,
  BarChart3,
} from 'lucide-react';
import { api } from '../../lib/api';
import { cn } from '../../lib/utils';

interface OrgWatchtowerOverview {
  projects_enabled: number;
  projects_total: number;
  packages_monitored: number;
  total_alerts: number;
  total_blocked: number;
  projects: Array<{
    id: string;
    name: string;
    tier: string | null;
    watchtower_enabled: boolean;
    enabled_at: string | null;
  }>;
}

interface PackageUsage {
  name: string;
  dependency_id: string;
  project_count: number;
  watched: boolean;
}

export default function OrganizationWatchtowerPage() {
  const { id: orgId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [overview, setOverview] = useState<OrgWatchtowerOverview | null>(null);
  const [packageUsage, setPackageUsage] = useState<PackageUsage[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    if (!orgId) return;
    try {
      const [overviewRes, usageRes] = await Promise.all([
        api.authenticatedGet(`/api/organizations/${orgId}/watchtower/overview`),
        api.authenticatedGet(`/api/organizations/${orgId}/watchtower/package-usage`).catch(() => []),
      ]);
      setOverview(overviewRes);
      setPackageUsage(usageRes || []);
    } catch {
      setOverview(null);
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => { fetchData(); }, [fetchData]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-6 w-6 animate-spin text-foreground-secondary" />
      </div>
    );
  }

  if (!overview) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-foreground-secondary">Failed to load Watchtower data.</p>
      </div>
    );
  }

  const enabledProjects = overview.projects.filter(p => p.watchtower_enabled);
  const inactiveProjects = overview.projects.filter(p => !p.watchtower_enabled);

  return (
    <div className="flex min-h-[calc(100vh-3rem)]">
      {/* Sidebar */}
      <div className="w-56 flex-shrink-0 border-r border-border bg-background overflow-y-auto">
        <div className="p-4 space-y-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-foreground-secondary">Watchtower</p>

          <button
            className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-sm font-medium text-foreground bg-background-card"
          >
            <BarChart3 className="h-4 w-4 text-foreground-secondary" />
            Overview
          </button>

          {enabledProjects.length > 0 && (
            <>
              <div className="border-t border-border" />
              <p className="text-[10px] font-semibold uppercase tracking-wider text-foreground-secondary">Projects</p>
              <div className="space-y-0.5">
                {enabledProjects.map(p => (
                  <button
                    key={p.id}
                    onClick={() => navigate(`/organizations/${orgId}/projects/${p.id}/watchtower`)}
                    className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-sm text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50 transition-colors"
                  >
                    <span className="h-2 w-2 rounded-full bg-green-500 flex-shrink-0" />
                    <span className="truncate">{p.name}</span>
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 min-w-0 px-6 py-6 overflow-auto space-y-6">
        <div className="flex items-center gap-3">
          <TowerControl className="h-5 w-5 text-foreground-secondary" />
          <h1 className="text-lg font-semibold text-foreground">Watchtower Overview</h1>
        </div>

        {/* Stats Strip */}
        <div className="grid grid-cols-4 gap-4">
          <div className="rounded-lg border border-border bg-background-card p-4">
            <p className="text-xs text-foreground-secondary">Projects Active</p>
            <p className="text-xl font-semibold text-foreground mt-1">
              {overview.projects_enabled} <span className="text-sm text-foreground-secondary font-normal">/ {overview.projects_total}</span>
            </p>
          </div>
          <div className="rounded-lg border border-border bg-background-card p-4">
            <p className="text-xs text-foreground-secondary">Packages Monitored</p>
            <p className="text-xl font-semibold text-foreground mt-1">{overview.packages_monitored}</p>
          </div>
          <div className="rounded-lg border border-border bg-background-card p-4">
            <p className="text-xs text-foreground-secondary">Active Alerts</p>
            <p className={cn('text-xl font-semibold mt-1', overview.total_alerts > 0 ? 'text-red-400' : 'text-foreground')}>{overview.total_alerts}</p>
          </div>
          <div className="rounded-lg border border-border bg-background-card p-4">
            <p className="text-xs text-foreground-secondary">Blocked Versions</p>
            <p className={cn('text-xl font-semibold mt-1', overview.total_blocked > 0 ? 'text-yellow-400' : 'text-foreground')}>{overview.total_blocked}</p>
          </div>
        </div>

        {/* Projects Summary Table */}
        <div className="space-y-3">
          <h2 className="text-sm font-medium text-foreground">Projects</h2>
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-background-card-header border-b border-border text-left">
                  <th className="px-4 py-2.5 text-xs font-medium text-foreground-secondary">Project</th>
                  <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary">Tier</th>
                  <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary">Status</th>
                  <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary w-20"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {enabledProjects.map(p => (
                  <tr key={p.id} className="hover:bg-table-hover/40 transition-colors">
                    <td className="px-4 py-2.5 font-medium text-foreground">{p.name}</td>
                    <td className="px-3 py-2.5 text-foreground-secondary text-xs">{p.tier || '—'}</td>
                    <td className="px-3 py-2.5">
                      <span className="inline-flex items-center gap-1 rounded-full bg-green-500/10 px-2 py-0.5 text-xs font-medium text-green-400">Active</span>
                    </td>
                    <td className="px-3 py-2.5">
                      <button
                        onClick={() => navigate(`/organizations/${orgId}/projects/${p.id}/watchtower`)}
                        className="inline-flex items-center gap-1 text-xs text-foreground-secondary hover:text-foreground"
                      >
                        <Eye className="h-3.5 w-3.5" />
                        View
                      </button>
                    </td>
                  </tr>
                ))}
                {inactiveProjects.map(p => (
                  <tr key={p.id} className="hover:bg-table-hover/40 transition-colors opacity-60">
                    <td className="px-4 py-2.5 font-medium text-foreground">{p.name}</td>
                    <td className="px-3 py-2.5 text-foreground-secondary text-xs">{p.tier || '—'}</td>
                    <td className="px-3 py-2.5">
                      <span className="inline-flex items-center rounded-full bg-zinc-500/10 px-2 py-0.5 text-xs font-medium text-foreground-secondary">Inactive</span>
                    </td>
                    <td className="px-3 py-2.5">
                      <button
                        onClick={() => navigate(`/organizations/${orgId}/projects/${p.id}/watchtower`)}
                        className="inline-flex items-center gap-1 text-xs text-foreground-secondary hover:text-foreground"
                      >
                        Enable
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Package Coverage */}
        {packageUsage.length > 0 && (
          <div className="space-y-3">
            <h2 className="text-sm font-medium text-foreground">Package Coverage</h2>
            <p className="text-xs text-foreground-secondary">Top packages across your organization by usage.</p>
            <div className="rounded-lg border border-border overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-background-card-header border-b border-border text-left">
                    <th className="px-4 py-2.5 text-xs font-medium text-foreground-secondary">Package</th>
                    <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary">Used in</th>
                    <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary">Monitored</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {packageUsage.slice(0, 20).map(pkg => (
                    <tr key={pkg.dependency_id} className="hover:bg-table-hover/40 transition-colors">
                      <td className="px-4 py-2.5 font-medium text-foreground">
                        <div className="flex items-center gap-2">
                          <Package className="h-3.5 w-3.5 text-foreground-secondary" />
                          {pkg.name}
                        </div>
                      </td>
                      <td className="px-3 py-2.5 text-foreground-secondary">{pkg.project_count} project{pkg.project_count !== 1 ? 's' : ''}</td>
                      <td className="px-3 py-2.5">
                        {pkg.watched ? (
                          <span className="inline-flex items-center gap-1 text-xs text-green-400">
                            <span className="h-1.5 w-1.5 rounded-full bg-green-400" />
                            Yes
                          </span>
                        ) : (
                          <span className="text-xs text-foreground-secondary">No</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
