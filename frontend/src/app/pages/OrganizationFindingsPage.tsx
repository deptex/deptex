import { useCallback, useEffect, useMemo, useState } from 'react';
import { useOutletContext, useParams } from 'react-router-dom';
import {
  Area,
  AreaChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Sector,
  Tooltip,
  XAxis,
} from 'recharts';
import {
  api,
  type Organization,
  type Project,
  type ProjectVulnerability,
  type SecretFinding,
  type SemgrepFinding,
  type IaCFinding,
  type ContainerFinding,
  type MaliciousFinding,
  type DastFindingDTO,
  type DataFlowFinding,
} from '../../lib/api';
import VulnerabilityExpandableTable, {
  type SecurityTableRow,
} from '../../components/security/VulnerabilityExpandableTable';
import OrganizationVulnerabilitiesTableSkeleton from '../../components/security/OrganizationVulnerabilitiesTableSkeleton';
import { FrameworkIcon } from '../../components/framework-icon';
import {
  Tooltip as UiTooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '../../components/ui/tooltip';

interface OrganizationContextType {
  organization: Organization | null;
}

const PER_PAGE_PER_TYPE = 100;

// Max rows shown in the Severities by Projects leaderboard. Tuned so the card
// height matches the Findings by Type donut next to it — 4 rows lines up with
// ~6 donut legend items + the standard p-5 card padding.
const TOP_PROJECTS_LIMIT = 4;

// Severity colors used by the funnel chart AND the Severities by Projects
// bars. Endor-style warm gradient: dark red → red → orange → yellow.
// Critical sits on top of the funnel stack so the dark-red edge reads as
// "this is the critical share that survives each filter stage."
const SEVERITY_COLORS = {
  critical: '#b91c1c', // red-700 — dark red
  high: '#ef4444', // red-500
  medium: '#f97316', // orange-500
  low: '#eab308', // yellow-500
};

type SeverityKey = keyof typeof SEVERITY_COLORS;

// Read a row's depscore — prefer the contextual (EPD-applied) score when
// present, then base depscore, then fall back to mapping the raw `severity`
// field to a mid-bucket value for rows that haven't been scored yet.
function rowDepscore(row: SecurityTableRow): number {
  const d = row.data as {
    depscore?: number | null;
    contextual_depscore?: number | null;
    severity?: string | null;
  };
  if (d.contextual_depscore != null && Number.isFinite(Number(d.contextual_depscore))) {
    return Number(d.contextual_depscore);
  }
  if (d.depscore != null && Number.isFinite(Number(d.depscore))) {
    return Number(d.depscore);
  }
  const sev = (d.severity ?? '').toLowerCase();
  if (sev === 'critical') return 95;
  if (sev === 'high') return 75;
  if (sev === 'medium') return 50;
  if (sev === 'low') return 20;
  return 0;
}

// Bucket a depscore into severity tiers. Matches CVSS thresholds — 90+
// critical, 70+ high, 40+ medium, otherwise low.
function depscoreToSeverity(score: number): SeverityKey {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

// Finding-type palette used by the "Findings by Type" donut + its legend.
// Matches the type-icon colors inside VulnerabilityExpandableTable so the
// donut wedges and the per-row type chips read as the same system.
type TypeKey = SecurityTableRow['type'];
// Cohesive emerald → green → teal palette (all in the green family that
// matches the `success` accent used elsewhere in the app — Compliant badge,
// etc.). The whole type system reads as one family rather than a rainbow.
// Severity colors (red/orange/yellow/zinc) stay distinct because they signal
// a different concept and should not blend with type colors.
const TYPE_COLORS: Record<TypeKey, string> = {
  vulnerability: '#10b981', // emerald-500 — primary anchor (biggest segment most orgs)
  secret: '#14b8a6', // teal-500
  semgrep: '#22c55e', // green-500
  license: '#86efac', // green-300 — light
  iac: '#34d399', // emerald-400 — medium emerald
  iac_group: '#34d399', // emerald-400 — same family as IaC
  container: '#2dd4bf', // teal-400 — medium teal
  container_group: '#2dd4bf', // teal-400 — same family as container CVEs
  dast: '#0d9488', // teal-600 — runtime
  malicious: '#047857', // emerald-700 — deepest
  taint_flow: '#5eead4', // teal-300 — first-party data-flow paths
};
const TYPE_LABELS: Record<TypeKey, string> = {
  vulnerability: 'CVEs',
  secret: 'Secrets',
  semgrep: 'Code findings',
  license: 'License',
  iac: 'IaC',
  iac_group: 'Container hardening',
  container: 'Container',
  container_group: 'Base image',
  dast: 'DAST',
  malicious: 'Malicious',
  taint_flow: 'Data-flow',
};

// Per-type description surfaced in the Findings by Type detail panel when
// the user clicks/hovers a donut wedge. Each `source` names the scanner(s)
// that produce the type. Descriptions are deliberately trimmed to ≤ 3
// lines at the column's natural width so every type's panel content fits
// within the donut's h-28 (112px) height — keeps the card from resizing
// as the user switches between types.
const TYPE_DESCRIPTIONS: Record<TypeKey, { source: string; description: string }> = {
  vulnerability: {
    source: 'cdxgen → dep-scan → reachability engine',
    description:
      'Open-source dependency CVEs. The reachability engine confirms which touch your code, then EPD reweights severities.',
  },
  secret: {
    source: 'TruffleHog',
    description:
      'Hardcoded credentials and API keys in your repo. TruffleHog pattern-verifies matches before flagging.',
  },
  semgrep: {
    source: 'Semgrep SAST',
    description:
      'Code-level findings — SQL injection, XSS, insecure deserialization, weak crypto. Semgrep across 8 languages.',
  },
  license: {
    source: 'cdxgen + policy engine',
    description:
      "Dependencies whose licenses violate your org's policy — copyleft, unknown, or explicitly banned.",
  },
  iac: {
    source: 'Checkov + Trivy',
    description:
      'Terraform / K8s / Dockerfile misconfigurations — IAM, networking, encryption. Mapped to CIS, NIST, SOC2, PCI.',
  },
  container: {
    source: 'Trivy',
    description:
      'OS-package CVEs in container images — Dockerfile bases and connected registry images.',
  },
  iac_group: {
    source: 'Checkov + Trivy',
    description:
      'The defense-in-depth k8s hardening tail (drop NET_RAW, restrict the SA token, seccomp, NetworkPolicy…) collapsed into one finding.',
  },
  container_group: {
    source: 'Trivy',
    description:
      'An out-of-date base image, with all its OS-package CVEs collapsed into one finding — fixed by upgrading the image.',
  },
  dast: {
    source: 'OWASP ZAP + Nuclei',
    description:
      'Runtime findings from actively scanning your live app — SQLi, XSS, SSTI. Cross-linked to the source handler and any reachable dependency.',
  },
  malicious: {
    source: 'OSV malicious feeds + GHSA',
    description:
      'Packages flagged as actively malicious — typosquats, protestware, credential stealers. Fix-immediately.',
  },
  taint_flow: {
    source: 'Taint engine',
    description:
      'A traced source→sink path in your OWN code — untrusted input reaching a dangerous sink (XSS, SQLi, SSRF). Reachable, not just a pattern match.',
  },
};


// Demo severity composition per funnel stage. Hand-tuned so columns sum to
// the demo stage values (247 / 198 / 89 / 32) and the critical share grows
// as a fraction of the remaining as the filters tighten. Replaced once real
// reachability + KEV/EPSS data are wired end-to-end. Stage keys map 1:1 to
// fields on `ProjectVulnerability`:
//   fix         → fix_versions populated
//   reachable   → reachability_level ∈ {module, function, data_flow, confirmed}
//   exploitable → is_kev = true OR epss_score >= 0.5
const DEMO_SEVERITY_BY_STAGE: Record<string, { critical: number; high: number; medium: number; low: number }> = {
  total: { critical: 25, high: 60, medium: 100, low: 62 },
  fix: { critical: 23, high: 55, medium: 80, low: 40 },
  reachable: { critical: 18, high: 32, medium: 28, low: 11 },
  exploitable: { critical: 10, high: 16, medium: 5, low: 1 },
};

// EPD-reweighted severity distribution of the apex priority bucket
// (depscore ≥ 80). NOT a funnel stage — same set as Exploitable, just
// renamed by depscore. Surfaced ONLY in the Depscore hover, which fires
// when the cursor is in the trailing chart zone past the Exploitable
// column. Total here (12 at scale 1.0) ≈ 38% of Exploitable; demo only.
const DEMO_DEPSCORE_DIST = { critical: 6, high: 4, medium: 2, low: 0 };

// Severity order for tooltip display — critical first, most-actionable to
// least-actionable.
const SEVERITY_ORDER: Array<keyof typeof SEVERITY_COLORS> = ['critical', 'high', 'medium', 'low'];

// Per-stage descriptions surfaced inside the hover tooltip so each stage
// explains the filter it applies, not just the count. Keyed by the same
// label string that `funnel.stages[].label` produces.
const STAGE_DESCRIPTIONS: Record<string, string> = {
  'Total CVEs':
    'All vulnerabilities found by dep-scan across every dependency in your projects — pre-filter baseline.',
  'Fix available':
    'CVEs where an upstream patched release exists. The rest are zero-day or abandoned — harder to remediate.',
  'Reachable':
    'CVEs in code paths reached from your production entry points. Implicitly excludes test-scoped deps and unreached library code.',
  'Exploitable':
    'CVEs that are KEV-listed (CISA’s known-exploited list) or have an EPSS probability ≥ 0.5 — actively weaponized in the wild or highly likely to be.',
  'Depscore':
    'EPD reweighting + project-importance multiplier applied to the Exploitable set. Same findings, ranked by contextual depscore — the apex bucket (≥ 80) is your fix-this-week list.',
};

// Label used by the synthetic tail point so its hover renders the Depscore
// lens instead of being suppressed. Not a funnel stage — depscore reweights
// the Exploitable set, doesn't filter it.
const DEPSCORE_HOVER_LABEL = 'Depscore';

// Findings-by-Type donut geometry. Constants so the active sector and the
// resting Pie use IDENTICAL radii except for the small intentional growth.
const DONUT_INNER_R = 32;
const DONUT_OUTER_R = 52;
// On hover the active wedge grows outward by this many pixels. +3 lands
// inside the wrapper without clipping (radius 55 in a 56-from-center
// container) and reads as "a little bigger" without flopping forward.
const DONUT_HOVER_GROW = 3;

// Active wedge shape — grows outward by DONUT_HOVER_GROW only. No stroke
// (that was the ugly white "outline" recharts' default activeShape was
// painting), no leader lines, no inner accent ring. Inner radius pinned
// so the donut hole stays the same size and the center number doesn't
// jitter.
function renderDonutActiveShape(props: any) {
  const { cx, cy, startAngle, endAngle, fill } = props;
  return (
    <Sector
      cx={cx}
      cy={cy}
      innerRadius={DONUT_INNER_R}
      outerRadius={DONUT_OUTER_R + DONUT_HOVER_GROW}
      startAngle={startAngle}
      endAngle={endAngle}
      fill={fill}
      stroke="none"
    />
  );
}

function FunnelTooltip({
  active,
  payload,
  label,
  apexDist,
  exploitableTotal,
}: {
  active?: boolean;
  payload?: Array<{ dataKey?: string; value?: number; color?: string }>;
  label?: string;
  // Severity composition of the apex priority bucket (depscore ≥ 80) — used
  // when the cursor sits on the synthetic tail point (label === 'Depscore').
  // The chart payload at that point duplicates Exploitable for a smooth
  // curve, but the Depscore HOVER shows the EPD-reweighted distribution of
  // the apex subset.
  apexDist?: { critical: number; high: number; medium: number; low: number };
  // Headline "X of Y are top priority" denominator on the Depscore hover.
  exploitableTotal?: number;
}) {
  if (!active || !payload || payload.length === 0 || !label) return null;
  const isDepscoreHover = label === DEPSCORE_HOVER_LABEL;

  // Chart values are sqrt-transformed — square them back to real counts.
  // sqrt of a whole-number round-trips exactly, so this matches the stage
  // stats shown above the chart.
  const realCount = (v: number | undefined): number => Math.round((v ?? 0) ** 2);
  const byKey = new Map(payload.map((p) => [p.dataKey, p]));

  // Severity row source: real apex distribution on the Depscore hover (the
  // EPD lens), payload-derived counts on every other stage. Total recomputes
  // from whichever source so the % column is consistent.
  const severities: Record<SeverityKey, number> = isDepscoreHover && apexDist
    ? { ...apexDist }
    : {
        critical: realCount(byKey.get('critical')?.value),
        high: realCount(byKey.get('high')?.value),
        medium: realCount(byKey.get('medium')?.value),
        low: realCount(byKey.get('low')?.value),
      };
  const total = severities.critical + severities.high + severities.medium + severities.low;
  const description = STAGE_DESCRIPTIONS[label];

  return (
    <div className="rounded-lg border border-border bg-background shadow-2xl p-3 min-w-[16rem] max-w-[20rem]">
      {/* Stage title + headline count on one line so the tooltip stays short.
          On the Depscore hover the headline reads "X of Y" so it's clear the
          5 here is a subset of the Exploitable set, not a count reduction. */}
      <div className="flex items-baseline justify-between gap-3">
        <div className="text-sm font-semibold text-foreground">{label}</div>
        <div className="flex items-baseline gap-1.5">
          <span className="text-lg font-bold tabular-nums text-foreground leading-none">
            {total}
          </span>
          {isDepscoreHover && exploitableTotal != null ? (
            <span className="text-[10px] text-foreground-secondary">
              of {exploitableTotal} exploitable
            </span>
          ) : (
            <span className="text-[10px] text-foreground-secondary">
              {total === 1 ? 'finding' : 'findings'}
            </span>
          )}
        </div>
      </div>

      {/* Per-stage description — explains what this filter step does */}
      {description && (
        <p className="mt-2 text-xs text-foreground-secondary leading-snug">
          {description}
        </p>
      )}

      <div className="my-2 h-px bg-border" />

      {/* Severity composition. On the Depscore hover this row IS the
          EPD-reweighted severities of the apex bucket (depscore ≥ 80). */}
      <ul className="space-y-1">
        {SEVERITY_ORDER.map((sev) => {
          const value = severities[sev];
          const pct = total > 0 ? Math.round((value / total) * 100) : 0;
          return (
            <li key={sev} className="flex items-center gap-2 text-xs">
              <span
                className="h-2 w-2 rounded-sm shrink-0"
                style={{ background: SEVERITY_COLORS[sev] }}
              />
              <span className="text-foreground-secondary capitalize flex-1">{sev}</span>
              <span className="tabular-nums text-foreground">{value}</span>
              <span className="tabular-nums text-foreground-secondary w-8 text-right">
                {pct}%
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}


export default function OrganizationFindingsPage() {
  const { id: orgId } = useParams<{ id: string }>();
  const { organization } = useOutletContext<OrganizationContextType>();
  const organizationId = organization?.id ?? orgId ?? '';

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [allRows, setAllRows] = useState<SecurityTableRow[]>([]);
  // Projects state — used by the Top Projects leaderboard for framework icons
  // and name fallbacks when a finding row doesn't carry `project_name`.
  const [projects, setProjects] = useState<Project[]>([]);

  // Findings by Type donut — single piece of state. Hover commits the
  // active wedge (no separate click gesture needed) and the active wedge
  // sticks until another wedge is hovered. Initially set to 0 (largest
  // type) by the effect below so the panel is never blank.
  const [activeWedge, setActiveWedge] = useState<number | null>(null);

  const load = useCallback(async () => {
    if (!organizationId) return;
    setLoading(true);
    setError(null);
    try {
      // Step 1: project list — drives the per-project fan-out and feeds the
      // Top Projects leaderboard with framework icons + names.
      const projectList = await api.getProjects(organizationId);
      setProjects(projectList);
      const nameById = new Map(projectList.map((p) => [p.id, p.name]));
      const frameworkById = new Map(projectList.map((p) => [p.id, p.framework ?? null]));

      // Step 2: fire one org-wide vulns request + 5 per-project requests in parallel.
      // allSettled so a single broken endpoint doesn't blank the page. v2 backlog
      // collapses this into one `getOrganizationFindings(orgId)` endpoint.
      const orgVulnsPromise = api
        .getOrganizationVulnerabilities(organizationId, {
          page: 1,
          per_page: PER_PAGE_PER_TYPE * 2,
        })
        .then((res) => res.data);

      const perProjectPromises = projectList.flatMap((p) => [
        api.getProjectSecretFindings(organizationId, p.id, 1, PER_PAGE_PER_TYPE).then((r) => ({
          kind: 'secret' as const,
          projectId: p.id,
          data: r.data ?? [],
        })),
        api.getProjectSemgrepFindings(organizationId, p.id, 1, PER_PAGE_PER_TYPE).then((r) => ({
          kind: 'semgrep' as const,
          projectId: p.id,
          data: r.data ?? [],
        })),
        api
          .getProjectIaCFindings(organizationId, p.id, {
            perPage: PER_PAGE_PER_TYPE,
            status: 'open',
          })
          .then((r) => ({ kind: 'iac' as const, projectId: p.id, data: r.data ?? [] })),
        api
          .getProjectContainerFindings(organizationId, p.id, {
            perPage: PER_PAGE_PER_TYPE,
            status: 'open',
          })
          .then((r) => ({ kind: 'container' as const, projectId: p.id, data: r.data ?? [] })),
        api.maliciousFindings.list(organizationId, p.id, 1, PER_PAGE_PER_TYPE).then((r) => ({
          kind: 'malicious' as const,
          projectId: p.id,
          data: r.data ?? [],
        })),
        // DAST is per-target: resolve the latest scan's target, then load its
        // findings. Most projects have no DAST target, so this short-circuits to
        // an empty list after one cheap jobs request.
        (async () => {
          const jobs = await api.getDastJobs(p.id, { limit: 5 });
          const targetId = jobs.find((j) => j.target_id)?.target_id ?? undefined;
          const data = targetId
            ? await api.getDastFindings(p.id, { limit: PER_PAGE_PER_TYPE, targetId })
            : [];
          return { kind: 'dast' as const, projectId: p.id, data };
        })(),
        api.getCodeFlowFindings(organizationId, p.id).then((r) => ({
          kind: 'code_flow' as const,
          projectId: p.id,
          data: r.data ?? [],
        })),
      ]);

      const [vulnsResult, ...perProjectResults] = await Promise.allSettled([
        orgVulnsPromise,
        ...perProjectPromises,
      ]);

      const rows: SecurityTableRow[] = [];

      if (vulnsResult.status === 'fulfilled') {
        for (const v of vulnsResult.value as ProjectVulnerability[]) {
          const stamped = {
            ...v,
            project_framework: (v as any).project_framework ?? frameworkById.get((v as any).project_id) ?? null,
          };
          rows.push({ type: 'vulnerability', data: stamped as ProjectVulnerability });
        }
      } else {
        console.error('Failed to load org vulnerabilities', vulnsResult.reason);
      }

      for (const settled of perProjectResults) {
        if (settled.status !== 'fulfilled') {
          console.error('Failed to load a per-project finding type', settled.reason);
          continue;
        }
        const { kind, projectId, data } = settled.value;
        const projectName = nameById.get(projectId);
        for (const item of data as (
          | SecretFinding
          | SemgrepFinding
          | IaCFinding
          | ContainerFinding
          | MaliciousFinding
          | DastFindingDTO
          | DataFlowFinding
        )[]) {
          const stamped = { ...item, project_name: projectName, project_framework: frameworkById.get(projectId) ?? null };
          switch (kind) {
            case 'secret':
              rows.push({ type: 'secret', data: stamped as SecretFinding & { project_name?: string } });
              break;
            case 'semgrep':
              rows.push({ type: 'semgrep', data: stamped as SemgrepFinding & { project_name?: string } });
              break;
            case 'iac':
              rows.push({ type: 'iac', data: stamped as IaCFinding });
              break;
            case 'container':
              rows.push({ type: 'container', data: stamped as ContainerFinding });
              break;
            case 'dast':
              rows.push({ type: 'dast', data: stamped as DastFindingDTO & { project_name?: string } });
              break;
            case 'malicious':
              rows.push({ type: 'malicious', data: stamped as MaliciousFinding & { project_name?: string } });
              break;
            case 'code_flow':
              rows.push({ type: 'taint_flow', data: stamped as DataFlowFinding & { project_name?: string } });
              break;
          }
        }
      }

      setAllRows(rows);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to load security findings');
      setAllRows([]);
      setProjects([]);
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

  // Vulnerability prioritization funnel — 4 stages mapped to Deptex's actual
  // pipeline (dep-scan → fix lookup → reachability engine → KEV/EPSS lookup).
  // "Not in test" intentionally absent: reachability already excludes test-
  // scoped deps since it traces from production entry points.
  //
  // Depscore is NOT a stage — EPD reweights severities on the apex set, it
  // doesn't filter further. The depscore-apex count (≥ 80) is surfaced ONLY
  // on the Exploitable stage's hover tooltip, NOT as a stat column.
  //
  // Demo numbers until real fix-availability + reachability + KEV/EPSS data
  // are wired end-to-end. Scales to the org's real CVE count when meaningful
  // (≥ 20); otherwise seeds at 247 so the funnel actually visualizes the
  // narrowing.
  const funnel = useMemo(() => {
    const vulnCount = allRows.filter((r) => r.type === 'vulnerability').length;
    const total = vulnCount >= 20 ? vulnCount : 247;
    const exploitable = Math.round(total * 0.13);
    // Apex bucket (depscore ≥ 80 of the Exploitable set) — surfaced ONLY on
    // the Depscore hover, not as a funnel column. Scaled from the demo dist
    // so the apex severities sum to ≈ 38% of Exploitable.
    const scale = total / 247;
    const apexDist = {
      critical: Math.round(DEMO_DEPSCORE_DIST.critical * scale),
      high: Math.round(DEMO_DEPSCORE_DIST.high * scale),
      medium: Math.round(DEMO_DEPSCORE_DIST.medium * scale),
      low: Math.round(DEMO_DEPSCORE_DIST.low * scale),
    };
    return {
      stages: [
        { key: 'total', label: 'Total CVEs', value: total },
        { key: 'fix', label: 'Fix available', value: Math.round(total * 0.80) },
        { key: 'reachable', label: 'Reachable', value: Math.round(total * 0.36) },
        { key: 'exploitable', label: 'Exploitable', value: exploitable },
      ],
      total,
      exploitable,
      apexDist,
    };
  }, [allRows]);

  // Stacked-area data for the funnel chart: at each stage, the area breaks
  // into 4 severity bands (critical on top, then high, medium, low). Demo
  // values for now; scale them to the funnel's `total` so the chart matches
  // the stage stats above.
  //
  // Values are sqrt-transformed before being handed to the chart so the tail
  // of the funnel (where ~4 findings sit) stays visible instead of collapsing
  // to a near-invisible sliver. The real counts come back in the tooltip via
  // `Math.round(value ** 2)` — sqrt of a whole-number count round-trips
  // exactly so the visible count matches `funnel.stages[].value` perfectly.
  //
  // A 5th synthetic point ("tail") is appended duplicating the last stage's
  // values — same chart heights as Exploitable, so the curve flows smoothly
  // (depscore reweights, doesn't filter, so the curve must NOT narrow
  // further here). With 5 points recharts spreads them at 0/25/50/75/100%
  // of the plot area: the 4 stat columns line up with the first 4 points
  // and the tail fills the trailing 12.5% of the chart width. The tail
  // carries `stage: 'Depscore'` so its hover renders the EPD lens (apex
  // bucket severity distribution + "X of Y exploitable" headline).
  const funnelChartData = useMemo(() => {
    const scale = funnel.total > 0 ? funnel.total / 247 : 1;
    const stagePoints = funnel.stages.map((s) => {
      const base = DEMO_SEVERITY_BY_STAGE[s.key] ?? DEMO_SEVERITY_BY_STAGE.total;
      return {
        stage: s.label,
        // Sqrt transform — compresses big values, amplifies small ones, so
        // the funnel still narrows but the tail doesn't disappear.
        low: Math.sqrt(Math.round(base.low * scale)),
        medium: Math.sqrt(Math.round(base.medium * scale)),
        high: Math.sqrt(Math.round(base.high * scale)),
        critical: Math.sqrt(Math.round(base.critical * scale)),
      };
    });
    const last = stagePoints[stagePoints.length - 1];
    if (last) stagePoints.push({ ...last, stage: DEPSCORE_HOVER_LABEL });
    return stagePoints;
  }, [funnel]);

  // Severities-by-projects leaderboard — aggregate `allRows` by project,
  // bucket each finding into a severity tier (critical/high/medium/low) by
  // its depscore, sort projects by a weighted severity score so the WORST
  // projects (most criticals first, then highs, etc.) rank top of the list.
  const topProjects = useMemo(() => {
    const projectsById = new Map(projects.map((p) => [p.id, p]));
    const acc = new Map<
      string,
      {
        name: string;
        framework: string | null;
        critical: number;
        high: number;
        medium: number;
        low: number;
        total: number;
      }
    >();
    for (const r of allRows) {
      const pid = (r.data as { project_id?: string }).project_id;
      if (!pid) continue;
      const proj = projectsById.get(pid);
      let bucket = acc.get(pid);
      if (!bucket) {
        bucket = {
          name: proj?.name ?? (r.data as { project_name?: string }).project_name ?? pid,
          framework: proj?.framework ?? null,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          total: 0,
        };
        acc.set(pid, bucket);
      }
      bucket[depscoreToSeverity(rowDepscore(r))]++;
      bucket.total++;
    }
    const arr = Array.from(acc.entries()).map(([id, b]) => ({ projectId: id, ...b }));
    // Sort by total finding count desc — biggest list of findings first.
    arr.sort((a, b) => b.total - a.total);
    return arr.slice(0, TOP_PROJECTS_LIMIT);
  }, [allRows, projects]);

  const maxProjectTotal = useMemo(
    () => topProjects.reduce((m, p) => Math.max(m, p.total), 0),
    [topProjects],
  );

  // Findings-by-type donut — count by row.type, ordered desc so the biggest
  // segment lands first. Zero-count types are filtered out separately
  // (kept in `breakdown` for completeness, dropped in `visibleBreakdown`
  // for everything the donut + detail panel index into).
  const breakdown = useMemo(() => {
    const counts: Record<TypeKey, number> = {
      vulnerability: 0,
      secret: 0,
      semgrep: 0,
      license: 0,
      iac: 0,
      iac_group: 0,
      container: 0,
      container_group: 0,
      dast: 0,
      malicious: 0,
      taint_flow: 0,
    };
    for (const r of allRows) counts[r.type]++;
    return (Object.keys(counts) as TypeKey[])
      .map((key) => ({ key, name: TYPE_LABELS[key], value: counts[key], color: TYPE_COLORS[key] }))
      .sort((a, b) => b.value - a.value);
  }, [allRows]);

  const visibleBreakdown = useMemo(
    () => breakdown.filter((b) => b.value > 0),
    [breakdown],
  );

  // Default the active wedge to the largest type once data loads, and
  // rescue from stale indices if the dataset shrinks (e.g. all of one
  // type get marked fixed and that index disappears).
  useEffect(() => {
    if (visibleBreakdown.length === 0) {
      if (activeWedge !== null) setActiveWedge(null);
      return;
    }
    if (activeWedge === null || activeWedge >= visibleBreakdown.length) {
      setActiveWedge(0);
    }
  }, [visibleBreakdown.length, activeWedge]);

  const displayedType =
    activeWedge !== null ? visibleBreakdown[activeWedge] ?? null : null;

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

        {/* Vulnerability prioritization funnel — Endor-inspired, full width */}
        <div className="rounded-lg border border-border bg-background-card p-5 flex flex-col">
          {/* Title in normal case (not uppercase muted label) */}
          <h2 className="text-sm font-semibold text-foreground">
            Vulnerability Prioritization Funnel
          </h2>

          {/* Relative wrapper so vertical separator lines span both the
              stage stats row AND the chart. */}
          <div className="relative mt-5 flex-1 flex flex-col">
            {/* 3 separators dividing the 4 stage columns. Span full height
                of the wrapper so they continue down into the chart area. */}
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                aria-hidden
                className="absolute top-0 bottom-0 w-px bg-border/60 pointer-events-none"
                style={{ left: `${(i / 4) * 100}%` }}
              />
            ))}

            {/* Stage stat row — bold numbers, no % subtitle */}
            <div className="grid grid-cols-4">
              {funnel.stages.map((s) => (
                <div key={s.key} className="px-3 first:pl-0 last:pr-0">
                  <div className="text-3xl font-bold tabular-nums text-foreground leading-none">
                    {s.value}
                  </div>
                  <div className="mt-2 text-xs text-foreground-secondary">{s.label}</div>
                </div>
              ))}
            </div>

            {/* Stacked-severity area chart: 4 bands (low → medium → high →
                critical) sum to each stage's total. Critical sits on top so
                the red edge reads as "how much of the remaining is critical".
                Each layer has its own linear-gradient fill — more saturated
                at the top of the band, fading toward transparent at the
                bottom. Thin strokes trace each layer's top curve so the
                stack boundaries stay legible.
                No tooltip — this is a glanceable overview, not a data probe. */}
            <div className="mt-5 h-28 -mx-1 -mb-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={funnelChartData}
                  margin={{ top: 4, right: 4, left: 4, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="sevLow" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={SEVERITY_COLORS.low} stopOpacity={0.45} />
                      <stop offset="100%" stopColor={SEVERITY_COLORS.low} stopOpacity={0.05} />
                    </linearGradient>
                    <linearGradient id="sevMedium" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={SEVERITY_COLORS.medium} stopOpacity={0.5} />
                      <stop offset="100%" stopColor={SEVERITY_COLORS.medium} stopOpacity={0.05} />
                    </linearGradient>
                    <linearGradient id="sevHigh" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={SEVERITY_COLORS.high} stopOpacity={0.55} />
                      <stop offset="100%" stopColor={SEVERITY_COLORS.high} stopOpacity={0.05} />
                    </linearGradient>
                    <linearGradient id="sevCritical" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={SEVERITY_COLORS.critical} stopOpacity={0.65} />
                      <stop offset="100%" stopColor={SEVERITY_COLORS.critical} stopOpacity={0.05} />
                    </linearGradient>
                  </defs>
                  {/* Hidden categorical axis so the tooltip label resolves to
                      the stage name ("Total CVEs", "Fix available", …) instead
                      of the array index. */}
                  <XAxis dataKey="stage" hide />
                  <Tooltip
                    content={(props: any) => (
                      <FunnelTooltip
                        {...props}
                        apexDist={funnel.apexDist}
                        exploitableTotal={funnel.exploitable}
                      />
                    )}
                    cursor={{
                      stroke: 'rgba(255,255,255,0.25)',
                      strokeWidth: 1,
                      strokeDasharray: '3 3',
                    }}
                    // Render the tooltip above subsequent cards (it would
                    // otherwise be clipped by the Severities card below)
                    // and let it escape the chart's clip area vertically.
                    wrapperStyle={{ zIndex: 50, pointerEvents: 'none' }}
                    allowEscapeViewBox={{ x: false, y: true }}
                  />
                  {/* activeDot={false} on every layer so the hover doesn't
                      render four stacked colored dots — the dashed cursor
                      line is enough to mark the active stage. */}
                  <Area
                    type="monotone"
                    dataKey="low"
                    stackId="sev"
                    stroke={SEVERITY_COLORS.low}
                    strokeWidth={1}
                    strokeOpacity={0.5}
                    fill="url(#sevLow)"
                    activeDot={false}
                  />
                  <Area
                    type="monotone"
                    dataKey="medium"
                    stackId="sev"
                    stroke={SEVERITY_COLORS.medium}
                    strokeWidth={1}
                    strokeOpacity={0.6}
                    fill="url(#sevMedium)"
                    activeDot={false}
                  />
                  <Area
                    type="monotone"
                    dataKey="high"
                    stackId="sev"
                    stroke={SEVERITY_COLORS.high}
                    strokeWidth={1.25}
                    strokeOpacity={0.7}
                    fill="url(#sevHigh)"
                    activeDot={false}
                  />
                  <Area
                    type="monotone"
                    dataKey="critical"
                    stackId="sev"
                    stroke={SEVERITY_COLORS.critical}
                    strokeWidth={1.5}
                    strokeOpacity={0.8}
                    fill="url(#sevCritical)"
                    activeDot={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Second dashboard row: Top Projects leaderboard + Findings by Type donut */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          {/* Severities by Projects — horizontal stacked-by-SEVERITY bars
              (depscore-bucketed). Endor-style warm gradient surfaces the
              worst projects first; sort weights critical*100 + high*70 +
              medium*40 + low*20 so a project with one critical outranks
              one with twenty lows. */}
          <div className="lg:col-span-2 rounded-lg border border-border bg-background-card p-5">
            <h2 className="text-sm font-semibold text-foreground">Top Projects</h2>
            {topProjects.length === 0 ? (
              <p className="mt-3 text-xs text-foreground-secondary italic">
                No findings to rank yet.
              </p>
            ) : (
              // delayDuration kept short (100ms) so the breakdown popover
              // feels snappy without firing on incidental cursor passes.
              <TooltipProvider delayDuration={100} skipDelayDuration={300}>
                <ul className="mt-4 space-y-1.5">
                  {topProjects.map((p) => (
                    <UiTooltip key={p.projectId}>
                      <TooltipTrigger asChild>
                        <li
                          className="grid grid-cols-[12rem_1fr_3rem] items-center gap-3 rounded-md px-2 -mx-2 py-1 hover:bg-muted/40 transition-colors duration-150"
                        >
                          {/* Framework icon + project name */}
                          <div className="flex items-center gap-2 min-w-0">
                            <FrameworkIcon
                              frameworkId={p.framework}
                              size={14}
                              className="shrink-0 opacity-80"
                            />
                            <span className="text-sm text-foreground truncate">{p.name}</span>
                          </div>

                          {/* Stacked horizontal bar — width scales relative
                              to the biggest project; within the bar, segments
                              stack by SEVERITY (critical → high → medium →
                              low, dark red to yellow). */}
                          <div className="relative h-2">
                            <div
                              className="flex h-full rounded-sm overflow-hidden"
                              style={{
                                width:
                                  maxProjectTotal > 0
                                    ? `${(p.total / maxProjectTotal) * 100}%`
                                    : '0%',
                              }}
                            >
                              {(['critical', 'high', 'medium', 'low'] as SeverityKey[]).map(
                                (sev) => {
                                  const count = p[sev];
                                  if (count <= 0) return null;
                                  return (
                                    <div
                                      key={sev}
                                      style={{
                                        width: `${(count / p.total) * 100}%`,
                                        background: SEVERITY_COLORS[sev],
                                      }}
                                    />
                                  );
                                },
                              )}
                            </div>
                          </div>

                          {/* Total count */}
                          <span className="text-sm tabular-nums text-foreground-secondary text-right">
                            {p.total}
                          </span>
                        </li>
                      </TooltipTrigger>
                      <TooltipContent
                        side="top"
                        align="center"
                        sideOffset={6}
                        // Override the default tight tooltip styling — we
                        // want the breakdown panel to feel like the funnel
                        // tooltip: roomier, with a divider and per-severity
                        // rows. `bg-background` (vs the default
                        // bg-background-card) is the darker outer color so
                        // the tooltip pops off the card.
                        className="bg-background border-border p-3 min-w-[15rem] max-w-[20rem] text-foreground shadow-2xl"
                      >
                        <div className="flex items-baseline justify-between gap-3">
                          <div className="text-sm font-semibold text-foreground truncate">
                            {p.name}
                          </div>
                          <div className="flex items-baseline gap-1.5 shrink-0">
                            <span className="text-lg font-bold tabular-nums text-foreground leading-none">
                              {p.total}
                            </span>
                            <span className="text-[10px] text-foreground-secondary">
                              {p.total === 1 ? 'finding' : 'findings'}
                            </span>
                          </div>
                        </div>
                        <div className="my-2 h-px bg-border" />
                        <ul className="space-y-1">
                          {SEVERITY_ORDER.map((sev) => {
                            const value = p[sev];
                            const pct =
                              p.total > 0 ? Math.round((value / p.total) * 100) : 0;
                            return (
                              <li
                                key={sev}
                                className="flex items-center gap-2 text-xs"
                              >
                                <span
                                  className="h-2 w-2 rounded-sm shrink-0"
                                  style={{ background: SEVERITY_COLORS[sev] }}
                                />
                                <span className="text-foreground-secondary capitalize flex-1">
                                  {sev}
                                </span>
                                <span className="tabular-nums text-foreground">
                                  {value}
                                </span>
                                <span className="tabular-nums text-foreground-secondary w-8 text-right">
                                  {pct}%
                                </span>
                              </li>
                            );
                          })}
                        </ul>
                      </TooltipContent>
                    </UiTooltip>
                  ))}
                </ul>
              </TooltipProvider>
            )}
          </div>

          {/* Findings by Type donut */}
          <div className="rounded-lg border border-border bg-background-card p-5">
            <h2 className="text-sm font-semibold text-foreground">Findings by Type</h2>
            {/* Row pinned to h-28 (matches the donut) so the card height
                is constant regardless of which type description is shown.
                Descriptions in TYPE_DESCRIPTIONS are trimmed to ≤ 3 lines
                at this column width so they fit inside this height. */}
            <div className="mt-3 flex items-center gap-4 h-28">
              {/* Donut wrapper. Wedges drive the description panel via
                  hover (preview) + click (commit selection). `overflow-
                  visible` on both wrapper AND descendant <svg> so the +3px
                  growth on the active wedge isn't clipped at the edge. */}
              <div className="relative h-28 w-28 shrink-0 overflow-visible [&_*]:!outline-none [&_svg]:overflow-visible">
                {visibleBreakdown.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={visibleBreakdown}
                        innerRadius={DONUT_INNER_R}
                        outerRadius={DONUT_OUTER_R}
                        dataKey="value"
                        startAngle={90}
                        endAngle={-270}
                        stroke="none"
                        strokeWidth={0}
                        paddingAngle={visibleBreakdown.length > 1 ? 2 : 0}
                        isAnimationActive={false}
                        // Controlled active state. -1 sentinel when neither
                        // hovered nor selected so recharts can't fall back
                        // to its own hover handling.
                        activeIndex={activeWedge ?? (-1 as unknown as number)}
                        activeShape={renderDonutActiveShape}
                        // Hover commits the active wedge — no click, no
                        // mouseLeave reset. Active wedge sticks until
                        // another wedge is hovered, so the panel stays on
                        // whatever the user was last looking at.
                        onMouseEnter={(_, i) => setActiveWedge(i)}
                      >
                        {visibleBreakdown.map((entry, i) => {
                          const isDimmed =
                            activeWedge !== null && activeWedge !== i;
                          return (
                            <Cell
                              key={entry.key}
                              fill={entry.color}
                              fillOpacity={isDimmed ? 0.35 : 1}
                              style={{
                                // Matched to the description panel's 200ms
                                // fade-in so wedge dim + text swap move at
                                // the same pace.
                                transition: 'fill-opacity 200ms ease-out',
                              }}
                            />
                          );
                        })}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="absolute inset-0 rounded-full border-[6px] border-border" />
                )}
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-xl font-semibold tabular-nums text-foreground leading-none">
                    {allRows.length}
                  </span>
                  <span className="mt-0.5 text-[9px] uppercase tracking-wider text-foreground-secondary">
                    Total
                  </span>
                </div>
              </div>
              {/* Description panel — replaces the legend. Shows the selected
                  type by default (auto-selected to the largest on mount);
                  hover any wedge to temporarily preview a different type
                  without committing. */}
              {displayedType ? (
                // key={displayedType.key} forces React to remount this
                // block when the user switches types (click or hover) so
                // the fade-in animation re-fires on every swap. Without
                // the key, the text would just snap to the new content.
                <div
                  key={displayedType.key}
                  className="flex-1 min-w-0 animate-in fade-in-0 duration-200 ease-out"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-foreground truncate flex-1">
                      {displayedType.name}
                    </span>
                    <span className="text-sm tabular-nums text-foreground">
                      {displayedType.value}
                    </span>
                  </div>
                  <p className="mt-2 text-xs text-foreground-secondary leading-snug">
                    {TYPE_DESCRIPTIONS[displayedType.key].description}
                  </p>
                </div>
              ) : (
                <p className="flex-1 text-xs text-foreground-secondary italic">
                  No findings yet.
                </p>
              )}
            </div>
          </div>
        </div>

        {/* Flat findings table — non-embedded mode brings its own Type+Project
            filter bar, thead, and rounded card frame. Page-level search is
            deferred; the table's filters cover the common case. */}
        {loading && allRows.length === 0 ? (
          <OrganizationVulnerabilitiesTableSkeleton />
        ) : (
          <VulnerabilityExpandableTable
            organizationId={organizationId}
            rows={allRows}
            canManageFindings={!!organization?.permissions?.manage_findings}
            onStatusChange={() => void load()}
          />
        )}
      </div>
    </main>
  );
}
