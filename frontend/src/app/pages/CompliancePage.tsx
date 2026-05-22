import { Fragment, useCallback, useEffect, useMemo, useState } from 'react';
import { useOutletContext, useParams } from 'react-router-dom';
import {
  ChevronRight,
  ExternalLink,
  Search,
} from 'lucide-react';
import { api, type Organization, type Project } from '../../lib/api';
import { FrameworkIcon } from '../../components/framework-icon';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../../components/ui/select';
import { cn } from '../../lib/utils';


interface OrganizationContextType {
  organization: Organization | null;
}

/**
 * v1: flat org-wide violations view, modeled after Snyk/Endor compliance reports.
 * The unit of attention is the *violation*, not the project — compliance officers
 * triage by age/severity across the org. Just filters + a single table for now;
 * dashboard visualizations were stripped 2026-05-21 and shifted as planned add-ons
 * for the Security tab instead (funnel + donut). Dummy data until the policy
 * builder + eval pipeline lands.
 */
type RuleType = 'license' | 'banned' | 'sla';
type Severity = 'block' | 'warn';

type Violation = {
  id: string;
  projectId: string;
  projectName: string;
  framework: string | null;
  packageName: string;
  packageVersion: string;
  ruleType: RuleType;
  ruleName: string;
  ruleDetail: string;
  recommendation: string;
  severity: Severity;
  ageDays: number;
};

// Dummy violation templates — wired to real projects at render time so the table
// uses actual project names/frameworks from the org.
const VIOLATION_TEMPLATES: Array<Omit<Violation, 'id' | 'projectId' | 'projectName' | 'framework'>> = [
  {
    packageName: 'axios-loader',
    packageVersion: '1.2.3',
    ruleType: 'license',
    ruleName: 'GPL-3.0 license blocked',
    ruleDetail: 'Org policy "Block copyleft licenses" rejects GPL-3.0 and AGPL-3.0 across all projects.',
    recommendation: 'Replace axios-loader with an MIT-licensed alternative, or request a policy exception.',
    severity: 'block',
    ageDays: 14,
  },
  {
    packageName: 'lodash',
    packageVersion: '4.17.21',
    ruleType: 'banned',
    ruleName: 'Banned package version',
    ruleDetail: 'Org bans the lodash@4.x range — upgrade to lodash@5 or drop the dependency.',
    recommendation: 'Bump to lodash@5.0.0 or remove the dependency entirely.',
    severity: 'block',
    ageDays: 28,
  },
  {
    packageName: 'left-pad',
    packageVersion: '1.3.0',
    ruleType: 'sla',
    ruleName: 'High CVEs over SLA',
    ruleDetail: '3 high-severity CVEs unfixed for more than the 30-day org SLA window.',
    recommendation: 'Upgrade to left-pad@1.4.0 (clears all 3 CVEs) or sprint to remediation.',
    severity: 'block',
    ageDays: 47,
  },
  {
    packageName: 'jsonwebtoken',
    packageVersion: '8.5.0',
    ruleType: 'license',
    ruleName: 'AGPL-3.0 license blocked',
    ruleDetail: 'Org policy "Block copyleft licenses" rejects AGPL-3.0 transitive deps.',
    recommendation: 'Pin to jsonwebtoken@9.x which dropped the AGPL transitive.',
    severity: 'block',
    ageDays: 7,
  },
  {
    packageName: 'requests',
    packageVersion: '2.20.0',
    ruleType: 'sla',
    ruleName: 'Critical CVE over SLA',
    ruleDetail: 'CVE-2024-1101 (critical, no fix available) past the 14-day org SLA for critical-no-fix.',
    recommendation: 'Apply org-approved mitigation or request risk acceptance until upstream fix lands.',
    severity: 'block',
    ageDays: 19,
  },
  {
    packageName: 'gin-gonic/gin',
    packageVersion: '1.7.0',
    ruleType: 'banned',
    ruleName: 'Banned package version',
    ruleDetail: 'Pinned version 1.7.x banned for CVE-2023-29401 not patched downstream of this line.',
    recommendation: 'Upgrade to gin@1.9.1 or later.',
    severity: 'block',
    ageDays: 3,
  },
  {
    packageName: 'mysql-connector-java',
    packageVersion: '5.1.49',
    ruleType: 'sla',
    ruleName: 'High CVE over SLA',
    ruleDetail: 'CVE-2022-21363 (high) unfixed for 62 days, past the 30-day org SLA window.',
    recommendation: 'Migrate to mysql-connector-j@8.x — drop-in replacement for most use cases.',
    severity: 'block',
    ageDays: 62,
  },
  {
    packageName: 'colors',
    packageVersion: '1.4.0',
    ruleType: 'banned',
    ruleName: 'Banned package',
    ruleDetail: 'colors@1.4.0 contains an intentional infinite loop introduced by the maintainer.',
    recommendation: 'Pin to colors@1.4.1 (clean) or migrate to chalk.',
    severity: 'block',
    ageDays: 4,
  },
];

const SLA_OVERDUE_DAYS = 30;

const RULE_TYPE_LABELS: Record<RuleType, string> = {
  license: 'License',
  banned: 'Banned',
  sla: 'SLA',
};

function severityChipClass(sev: Severity): string {
  if (sev === 'block') return 'bg-red-500/10 text-red-400 border-red-500/20';
  return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
}

function ruleTypeChipClass(t: RuleType): string {
  switch (t) {
    case 'license':
      return 'bg-blue-500/10 text-blue-300 border-blue-500/20';
    case 'banned':
      return 'bg-purple-500/10 text-purple-300 border-purple-500/20';
    case 'sla':
      return 'bg-orange-500/10 text-orange-300 border-orange-500/20';
  }
}

export default function CompliancePage() {
  const { id: orgId } = useParams<{ id: string }>();
  const { organization } = useOutletContext<OrganizationContextType>();
  const organizationId = organization?.id ?? orgId ?? '';

  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const [ruleTypeFilter, setRuleTypeFilter] = useState<RuleType | 'all'>('all');
  const [projectFilter, setProjectFilter] = useState<string>('all');
  const [search, setSearch] = useState('');

  const load = useCallback(async () => {
    if (!organizationId) return;
    setLoading(true);
    setError(null);
    try {
      const projectList = await api.getProjects(organizationId);
      setProjects(projectList);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to load compliance');
      setProjects([]);
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    document.documentElement.classList.add('security-scrollbar');
    document.body.classList.add('security-scrollbar');
    return () => {
      document.documentElement.classList.remove('security-scrollbar');
      document.body.classList.remove('security-scrollbar');
    };
  }, []);

  // Bind each dummy template to a real project so the rows reference projects
  // that actually exist in this org. Concentrate violations on roughly half of
  // the projects so the headline compliance % isn't always 0 — fixed assignment
  // pattern reads more naturally than random.
  const violations = useMemo<Violation[]>(() => {
    if (projects.length === 0) return [];
    const violatingCount = Math.max(1, Math.ceil(projects.length / 2));
    return VIOLATION_TEMPLATES.map((tpl, i) => {
      const p = projects[i % violatingCount];
      return {
        ...tpl,
        id: `v-${i}-${p.id}`,
        projectId: p.id,
        projectName: p.name,
        framework: p.framework ?? null,
      };
    });
  }, [projects]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return violations.filter((v) => {
      if (ruleTypeFilter !== 'all' && v.ruleType !== ruleTypeFilter) return false;
      if (projectFilter !== 'all' && v.projectId !== projectFilter) return false;
      if (q) {
        const hay = `${v.packageName} ${v.packageVersion} ${v.ruleName} ${v.projectName}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [violations, ruleTypeFilter, projectFilter, search]);

  const toggle = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
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
          <h1 className="text-2xl font-bold text-foreground">Compliance</h1>
          <p className="mt-1 max-w-2xl text-sm text-foreground-secondary">
            Policy violations across all projects in this organization, ranked by severity and age.
          </p>
        </div>

        {error && (
          <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}

        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-2">
          <Select
            value={ruleTypeFilter}
            onValueChange={(v) => setRuleTypeFilter(v as RuleType | 'all')}
          >
            <SelectTrigger className="h-9 w-[10rem]">
              <SelectValue placeholder="Rule type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All rule types</SelectItem>
              <SelectItem value="license">License</SelectItem>
              <SelectItem value="banned">Banned package</SelectItem>
              <SelectItem value="sla">SLA</SelectItem>
            </SelectContent>
          </Select>

          <Select value={projectFilter} onValueChange={setProjectFilter}>
            <SelectTrigger className="h-9 w-[14rem]">
              <SelectValue placeholder="Project" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All projects</SelectItem>
              {projects.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  <div className="flex items-center gap-2 min-w-0">
                    <FrameworkIcon
                      frameworkId={p.framework?.toLowerCase()}
                      size={14}
                      className="text-foreground-secondary shrink-0"
                    />
                    <span className="truncate">{p.name}</span>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <div className="relative flex-1 min-w-[14rem] max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search package, rule, project…"
              className="w-full h-9 pl-9 pr-3 rounded-md border border-border bg-background-card text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-1 focus:ring-foreground/40"
            />
          </div>

          <div className="ml-auto text-xs text-foreground-secondary tabular-nums">
            {filtered.length} of {violations.length}
          </div>
        </div>

        {/* Violations table */}
        {loading && violations.length === 0 ? (
          <div className="rounded-lg border border-border bg-background-card px-4 py-12 text-center text-sm text-foreground-secondary">
            Loading compliance…
          </div>
        ) : filtered.length === 0 ? (
          <div className="rounded-lg border border-border bg-background-card px-4 py-12 text-center text-sm text-foreground-secondary">
            {violations.length === 0 ? 'No policy violations across your projects.' : 'No violations match the current filters.'}
          </div>
        ) : (
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <table className="w-full">
              <thead className="bg-background-card-header border-b border-border">
                <tr>
                  <th className="w-20 pl-4 pr-2 py-2.5 text-left text-[10px] uppercase tracking-wider text-foreground-secondary font-semibold">
                    Severity
                  </th>
                  <th className="w-[14rem] px-2 py-2.5 text-left text-[10px] uppercase tracking-wider text-foreground-secondary font-semibold">
                    Project
                  </th>
                  <th className="w-[16rem] px-2 py-2.5 text-left text-[10px] uppercase tracking-wider text-foreground-secondary font-semibold">
                    Package
                  </th>
                  <th className="px-2 py-2.5 text-left text-[10px] uppercase tracking-wider text-foreground-secondary font-semibold">
                    Rule
                  </th>
                  <th className="w-20 px-2 py-2.5 text-right text-[10px] uppercase tracking-wider text-foreground-secondary font-semibold">
                    Age
                  </th>
                  <th className="w-10 pl-2 pr-4 py-2.5" aria-hidden="true" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filtered.map((v) => {
                  const isOpen = expanded.has(v.id);
                  const overdue = v.ageDays > SLA_OVERDUE_DAYS;
                  return (
                    <Fragment key={v.id}>
                      <tr
                        className="cursor-pointer hover:bg-background-subtle/40 transition-colors"
                        onClick={() => toggle(v.id)}
                        aria-expanded={isOpen}
                      >
                        <td className="pl-4 pr-2 py-3">
                          <span
                            className={cn(
                              'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border',
                              severityChipClass(v.severity),
                            )}
                          >
                            {v.severity.toUpperCase()}
                          </span>
                        </td>
                        <td className="px-2 py-3">
                          <div className="flex items-center gap-2 min-w-0">
                            <FrameworkIcon
                              frameworkId={v.framework?.toLowerCase()}
                              size={14}
                              className="text-foreground-secondary shrink-0"
                            />
                            <span className="text-sm text-foreground truncate">{v.projectName}</span>
                          </div>
                        </td>
                        <td className="px-2 py-3">
                          <div className="text-sm font-mono text-foreground truncate">
                            {v.packageName}
                            <span className="text-foreground-secondary">@{v.packageVersion}</span>
                          </div>
                        </td>
                        <td className="px-2 py-3">
                          <div className="flex items-center gap-2 min-w-0">
                            <span
                              className={cn(
                                'inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-medium border shrink-0',
                                ruleTypeChipClass(v.ruleType),
                              )}
                            >
                              {RULE_TYPE_LABELS[v.ruleType]}
                            </span>
                            <span className="text-sm text-foreground truncate">{v.ruleName}</span>
                          </div>
                        </td>
                        <td className="px-2 py-3 text-right">
                          <span
                            className={cn(
                              'text-sm tabular-nums',
                              overdue ? 'text-red-400 font-semibold' : 'text-foreground-secondary',
                            )}
                          >
                            {v.ageDays}d
                          </span>
                        </td>
                        <td className="pl-2 pr-4 py-3 text-right">
                          <ChevronRight
                            className={cn(
                              'h-4 w-4 text-foreground-secondary transition-transform inline-block',
                              isOpen && 'rotate-90',
                            )}
                          />
                        </td>
                      </tr>
                      {isOpen && (
                        <tr>
                          <td colSpan={6} className="px-0 py-0 bg-background-subtle/30">
                            <div className="px-4 py-4 space-y-3">
                              <div>
                                <div className="text-[10px] uppercase tracking-wider text-foreground-secondary mb-1">
                                  Rule
                                </div>
                                <div className="text-sm text-foreground leading-relaxed">
                                  {v.ruleDetail}
                                </div>
                              </div>
                              <div>
                                <div className="text-[10px] uppercase tracking-wider text-foreground-secondary mb-1">
                                  Recommendation
                                </div>
                                <div className="text-sm text-foreground leading-relaxed">
                                  {v.recommendation}
                                </div>
                              </div>
                              <div className="flex items-center gap-2 pt-1">
                                <a
                                  href={`/organizations/${organizationId}/projects/${v.projectId}`}
                                  className="inline-flex items-center gap-1.5 text-xs text-foreground hover:underline"
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  View project
                                  <ExternalLink className="h-3 w-3" />
                                </a>
                                <span className="text-xs text-foreground-secondary">·</span>
                                <a
                                  href={`/organizations/${organizationId}/findings`}
                                  className="inline-flex items-center gap-1.5 text-xs text-foreground hover:underline"
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  View in Security
                                  <ExternalLink className="h-3 w-3" />
                                </a>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </main>
  );
}
