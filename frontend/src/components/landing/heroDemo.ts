/**
 * heroDemo — single source of truth for the hero product showcase (founder
 * 2026-06-17). The Overview graph, the Findings table, and the Aegis chat all
 * read from this one dataset so the three tabs tell ONE coherent story: a sample
 * org with 5 projects across 2 teams; a spread of findings (vuln / secret / SAST
 * / IaC) across those projects; and Aegis fixing a reachable one. The per-project
 * label under each Overview node is the count of OPEN findings, derived from the
 * same findings + the same autoTriageRow the table uses — so the two tabs agree.
 *
 * Everything here is mock data shaped to the REAL types so it feeds the real
 * components unchanged. See [[feedback_landing_use_real_components]].
 */
import {
  autoTriageRow,
  type SecurityTableRow,
} from "../security/VulnerabilityExpandableTable";
import type {
  FindingTrackerLink,
  IaCFinding,
  IaCFramework,
  ProjectVulnerability,
  ReachabilityLevel,
  ReachableFlow,
  ReachableFlowNode,
  SecretFinding,
  SemgrepFinding,
  VulnerabilityDetail,
} from "../../lib/api";
import type { OverviewTeamWithProjects } from "../vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout";

export const HERO_ORG_ID = "demo-org";
export const HERO_ORG_NAME = "Acme Corp";
export const HERO_ORG_AVATAR = "/images/acmelogo.png";
const RUN = "run-1";
const CREATED = "2026-01-08T00:00:00.000Z";

/* ------------------------------------------------------------------ projects */
// Single project list — drives both the Overview graph nodes and the Findings
// project column. Positions are the graph layout (org center at 0,0; teams sit
// just off centre, projects fan out a little past them).
type Team = "platform" | "payments";
type HeroProject = {
  id: string;
  name: string;
  framework: string;
  team: Team;
  deps: number;
  health: number;
  x: number;
  y: number;
};

export const HERO_PROJECTS: HeroProject[] = [
  // Platform team fans DOWN below the org; Payments team sits to the RIGHT.
  { id: "storefront-api", name: "storefront-api", framework: "express", team: "platform", deps: 142, health: 47, x: -300, y: 320 },
  { id: "api-gateway", name: "api-gateway", framework: "go", team: "platform", deps: 48, health: 78, x: -85, y: 372 },
  { id: "web-dashboard", name: "web-dashboard", framework: "react", team: "platform", deps: 86, health: 68, x: 130, y: 320 },
  { id: "payments-svc", name: "payments-svc", framework: "python", team: "payments", deps: 73, health: 52, x: 400, y: -110 },
  { id: "auth-service", name: "auth-service", framework: "java", team: "payments", deps: 61, health: 88, x: 400, y: 80 },
];

const proj = (id: string): HeroProject => {
  const p = HERO_PROJECTS.find((x) => x.id === id);
  if (!p) throw new Error(`unknown hero project ${id}`);
  return p;
};

const TEAM_META: Record<Team, { teamName: string; role: string; roleColor: string; members: number; x: number; y: number }> = {
  platform: { teamName: "Platform team", role: "Owner", roleColor: "#34d08a", members: 6, x: -85, y: 182 },
  payments: { teamName: "Payments team", role: "Member", roleColor: "#60a5fa", members: 4, x: 170, y: -26 },
};

/* ------------------------------------------------------------------ findings */
// project_framework is read by the table's project column (FrameworkIcon); it's
// not on the base finding types, so each row.data is cast after we add it.

function vuln(o: {
  id: string;
  osv: string;
  cve: string;
  severity: ProjectVulnerability["severity"];
  summary: string;
  dep: string;
  version: string;
  fixed?: string;
  depscore: number;
  level: ReachabilityLevel;
  cvss?: number;
  epss?: number;
  kev?: boolean;
  status?: "open" | "ignored";
  project: string;
}): SecurityTableRow {
  const p = proj(o.project);
  return {
    type: "vulnerability",
    data: {
      id: o.id,
      finding_key: o.id,
      status: o.status ?? "open",
      osv_id: o.osv,
      severity: o.severity,
      summary: o.summary,
      details: null,
      aliases: [o.cve],
      fixed_versions: o.fixed ? [o.fixed] : [],
      published_at: null,
      modified_at: null,
      dependency_id: `dep-${o.id}`,
      dependency_name: o.dep,
      dependency_version: o.version,
      is_reachable: o.level !== "unreachable" && o.level != null,
      epss_score: o.epss,
      cvss_score: o.cvss,
      cisa_kev: o.kev ?? false,
      depscore: o.depscore,
      contextual_depscore: o.depscore,
      reachability_level: o.level,
      project_id: p.id,
      project_name: p.name,
      project_framework: p.framework,
    } as ProjectVulnerability,
  };
}

function secretRow(o: {
  id: string;
  detector: string;
  file: string;
  line: number;
  redacted: string;
  snippet: string;
  depscore: number;
  project: string;
}): SecurityTableRow {
  const p = proj(o.project);
  return {
    type: "secret",
    data: {
      id: o.id,
      finding_key: o.id,
      project_id: p.id,
      extraction_run_id: RUN,
      detector_type: o.detector,
      file_path: o.file,
      start_line: o.line,
      is_verified: true,
      is_current: true,
      description: null,
      redacted_value: o.redacted,
      code_snippet: o.snippet,
      depscore: o.depscore,
      status: "open",
      created_at: CREATED,
      project_name: p.name,
      project_framework: p.framework,
    } as SecretFinding & { project_name?: string },
  };
}

function semgrepRow(o: {
  id: string;
  rule: string;
  file: string;
  line: number;
  severity: string;
  message: string;
  category: string;
  cwe: string[];
  snippet: string;
  depscore: number;
  status?: "open" | "ignored";
  project: string;
}): SecurityTableRow {
  const p = proj(o.project);
  return {
    type: "semgrep",
    data: {
      id: o.id,
      finding_key: o.id,
      project_id: p.id,
      extraction_run_id: RUN,
      rule_id: o.rule,
      file_path: o.file,
      start_line: o.line,
      end_line: o.line + 3,
      severity: o.severity,
      message: o.message,
      cwe_ids: o.cwe,
      owasp_ids: [],
      category: o.category,
      metadata: null,
      code_snippet: o.snippet,
      depscore: o.depscore,
      status: o.status ?? "open",
      created_at: CREATED,
      project_name: p.name,
      project_framework: p.framework,
    } as SemgrepFinding & { project_name?: string },
  };
}

function iacRow(o: {
  id: string;
  rule: string;
  framework: string;
  file: string;
  line: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  message: string;
  description: string;
  snippet: string;
  depscore: number;
  project: string;
}): SecurityTableRow {
  const p = proj(o.project);
  return {
    type: "iac",
    data: {
      id: o.id,
      finding_key: o.id,
      project_id: p.id,
      organization_id: HERO_ORG_ID,
      extraction_run_id: RUN,
      scanner: "checkov",
      scanner_version: "3.2.0",
      rule_id: o.rule,
      framework: o.framework as IaCFramework,
      file_path: o.file,
      start_line: o.line,
      end_line: o.line + 6,
      severity: o.severity,
      depscore: o.depscore,
      message: o.message,
      description: o.description,
      cwe_ids: ["CWE-732"],
      code_snippet: o.snippet,
      rule_doc_url: null,
      iac_fingerprint: o.id,
      compliance_refs: { "PCI-DSS": ["1.3.1"] },
      status: "open",
      suppressed: false,
      risk_accepted: false,
      risk_accepted_reason: null,
      created_at: CREATED,
      project_name: p.name,
      project_framework: p.framework,
    } as IaCFinding,
  };
}

// Org-wide findings, mixed types across projects. The 6 open ones (critical RCE /
// secret / SAST / reachable vuln / IaC / data-flow vuln) carry colour + depscore;
// the 2 set-aside (unreachable vulns) render dimmed.
export const heroFindings: SecurityTableRow[] = [
  vuln({ id: "ejs", osv: "CVE-2022-29078", cve: "GHSA-phwq-j96m-2c2q", severity: "critical", summary: "Server-side template injection in ejs leads to remote code execution", dep: "ejs", version: "3.1.6", fixed: "3.1.7", depscore: 90, level: "confirmed", cvss: 9.8, epss: 0.91, kev: true, project: "storefront-api" }),
  secretRow({ id: "secret-stripe", detector: "Stripe", file: "src/config/credentials.py", line: 24, redacted: "sk_live_••••••3xQ2", snippet: 'STRIPE_KEY = "sk_live_51AbC...3xQ2"  # TODO: move to env', depscore: 88, project: "payments-svc" }),
  semgrepRow({ id: "sast-cmdi", rule: "python.lang.security.audit.subprocess-shell-true", file: "app/routes/export.py", line: 42, severity: "ERROR", message: "subprocess called with shell=True on user input — command injection", category: "command-injection", cwe: ["CWE-78"], snippet: 'subprocess.run(f"zip -r {user_path}", shell=True)', depscore: 81, status: "ignored", project: "storefront-api" }),
  vuln({ id: "lodash", osv: "CVE-2021-23337", cve: "GHSA-35jh-r3h4-6jhm", severity: "high", summary: "Command injection in lodash via _.template()", dep: "lodash", version: "4.17.20", fixed: "4.17.21", depscore: 72, level: "confirmed", cvss: 7.2, epss: 0.62, project: "storefront-api" }),
  iacRow({ id: "iac-s3", rule: "CKV_AWS_20", framework: "terraform", file: "infra/aws/s3.tf", line: 8, severity: "HIGH", message: "S3 bucket allows public read access", description: "The S3 bucket is created with acl = public-read, making its contents world-readable.", snippet: 'resource "aws_s3_bucket" "assets" {\n  acl = "public-read"\n}', depscore: 70, project: "api-gateway" }),
  vuln({ id: "braces", osv: "CVE-2024-4068", cve: "GHSA-grv7-fg5c-xmjg", severity: "medium", summary: "Uncontrolled resource consumption in braces", dep: "braces", version: "3.0.2", fixed: "3.0.3", depscore: 44, level: "data_flow", cvss: 5.3, epss: 0.21, project: "web-dashboard" }),
  vuln({ id: "minimist", osv: "CVE-2021-44906", cve: "GHSA-xvch-5gv4-984h", severity: "high", summary: "Prototype pollution in minimist", dep: "minimist", version: "1.2.5", fixed: "1.2.6", depscore: 0, level: "unreachable", cvss: 9.8, epss: 0.05, project: "storefront-api" }),
  vuln({ id: "py-3177", osv: "CVE-2021-3177", cve: "CVE-2021-3177", severity: "high", summary: "ctypes PyCArg buffer overflow (python 3.5)", dep: "python", version: "3.5.0", depscore: 0, level: "unreachable", project: "payments-svc" }),
];

// Demo tracker links — a few findings are linked to a Jira / Linear / GitHub issue,
// keyed by (project_id, finding_type, finding_key) to match the rows above. The two
// with external_state="done" render the resolved ✓ badge; all three drive the
// provider icon + hover tooltip in the status column. A linked finding reads as
// "Open" (a ticket has been filed), so these also vary the status spread.
export const heroTrackerLinks: FindingTrackerLink[] = [
  { id: "tl-ejs", project_id: "storefront-api", finding_type: "vulnerability", finding_key: "ejs", provider: "github", external_key: "#2451", external_url: null, title: "RCE in ejs — bump to 3.1.7", external_state: "done", created_at: CREATED },
  { id: "tl-secret", project_id: "payments-svc", finding_type: "secret", finding_key: "secret-stripe", provider: "linear", external_key: "SEC-88", external_url: null, title: "Rotate the leaked Stripe live key", external_state: "open", created_at: CREATED },
  { id: "tl-iac", project_id: "api-gateway", finding_type: "iac", finding_key: "iac-s3", provider: "jira", external_key: "OPS-310", external_url: null, title: "Lock down the public S3 bucket", external_state: "done", created_at: CREATED },
];

/* --------------------------- per-feature-page findings (dedicated pages) */
// Separate lists for the Code scanning + Infrastructure feature pages, kept OUT
// of heroFindings so the homepage Overview counts + Verified table stay
// unchanged. Built from the same row helpers, so they feed the real table.
export const codeFindings: SecurityTableRow[] = [
  semgrepRow({ id: "sast-sqli", rule: "python.django.security.audit.raw-query", file: "app/db/users.py", line: 88, severity: "ERROR", message: "SQL query built by string formatting on request data", category: "sql-injection", cwe: ["CWE-89"], snippet: "cursor.execute(f\"SELECT * FROM users WHERE email = '{email}'\")", depscore: 86, project: "storefront-api" }),
  semgrepRow({ id: "sast-cmdi", rule: "python.lang.security.audit.subprocess-shell-true", file: "app/routes/export.py", line: 42, severity: "ERROR", message: "subprocess called with shell=True on user input — command injection", category: "command-injection", cwe: ["CWE-78"], snippet: 'subprocess.run(f"zip -r {user_path}", shell=True)', depscore: 81, project: "storefront-api" }),
  secretRow({ id: "secret-stripe", detector: "Stripe", file: "src/config/credentials.py", line: 24, redacted: "sk_live_••••••3xQ2", snippet: 'STRIPE_KEY = "sk_live_51AbC...3xQ2"  # TODO: move to env', depscore: 78, project: "payments-svc" }),
  secretRow({ id: "secret-aws", detector: "AWS", file: "deploy/terraform/main.tf", line: 7, redacted: "AKIA••••••7Q4P", snippet: 'access_key = "AKIAIOSFODNN7EXAMPLE"', depscore: 74, project: "api-gateway" }),
  semgrepRow({ id: "sast-xss", rule: "javascript.react.security.audit.dangerouslysetinnerhtml", file: "src/views/Profile.jsx", line: 31, severity: "WARNING", message: "Unescaped user input passed to dangerouslySetInnerHTML", category: "xss", cwe: ["CWE-79"], snippet: "<div dangerouslySetInnerHTML={{ __html: bio }} />", depscore: 52, project: "web-dashboard" }),
];

export const infraFindings: SecurityTableRow[] = [
  iacRow({ id: "iac-sg", rule: "CKV_AWS_24", framework: "terraform", file: "infra/aws/sg.tf", line: 12, severity: "CRITICAL", message: "Security group allows 0.0.0.0/0 on port 22 (SSH)", description: "Ingress is open to the entire internet on the SSH port.", snippet: 'ingress {\n  from_port   = 22\n  cidr_blocks = ["0.0.0.0/0"]\n}', depscore: 92, project: "api-gateway" }),
  iacRow({ id: "iac-s3", rule: "CKV_AWS_20", framework: "terraform", file: "infra/aws/s3.tf", line: 8, severity: "HIGH", message: "S3 bucket allows public read access", description: "The bucket is created with acl = public-read, making its contents world-readable.", snippet: 'resource "aws_s3_bucket" "assets" {\n  acl = "public-read"\n}', depscore: 70, project: "api-gateway" }),
  iacRow({ id: "iac-docker", rule: "CKV_DOCKER_3", framework: "dockerfile", file: "Dockerfile", line: 1, severity: "HIGH", message: "Image runs as root — no USER instruction", description: "Containers should drop to a non-root user.", snippet: "FROM node:18\n# no USER instruction — defaults to root", depscore: 66, project: "web-dashboard" }),
  iacRow({ id: "iac-k8s", rule: "CKV_K8S_8", framework: "kubernetes", file: "k8s/api-deploy.yaml", line: 40, severity: "MEDIUM", message: "Container has no readiness probe", description: "Without a readiness probe, traffic can be routed to an unready pod.", snippet: "containers:\n  - name: api\n    # no readinessProbe defined", depscore: 41, project: "payments-svc" }),
];

/* ---------------------------------------------------------------------- teams */
// Per-project Overview label = count of OPEN findings (autoTriageRow === null),
// coloured by the project's worst open depscore using the same red/orange/blue/
// green band ramp as the findings table.
function rowProjectId(r: SecurityTableRow): string | undefined {
  return (r.data as { project_id?: string }).project_id;
}
function rowScore(r: SecurityTableRow): number {
  if (r.type === "vulnerability") return r.data.contextual_depscore ?? r.data.depscore ?? 0;
  return (r.data as { depscore?: number | null }).depscore ?? 0;
}
export type SeverityCounts = { critical: number; high: number; medium: number; low: number };

// Per-project OPEN-finding counts, bucketed by the same depscore band ramp as the
// findings table / SeverityPills (>=90 C / >=70 H / >=40 M / <40 L).
function projectSeverityCounts(projectId: string): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of heroFindings) {
    if (rowProjectId(r) !== projectId || autoTriageRow(r) !== null) continue;
    const s = rowScore(r);
    if (s >= 90) counts.critical++;
    else if (s >= 70) counts.high++;
    else if (s >= 40) counts.medium++;
    else counts.low++;
  }
  return counts;
}

function buildTeams(): OverviewTeamWithProjects[] {
  return (Object.keys(TEAM_META) as Team[]).map((t) => {
    const m = TEAM_META[t];
    // No statusBadge — bandCounts drives the native SeverityPills under each
    // project node (VulnProjectNode renders them at size xs).
    const projects = HERO_PROJECTS.filter((p) => p.team === t).map((p) => ({
      projectId: p.id,
      projectName: p.name,
      framework: p.framework,
      bandCounts: projectSeverityCounts(p.id),
      dependenciesCount: p.deps,
      healthScore: p.health,
      canvasPositionX: p.x,
      canvasPositionY: p.y,
    }));
    return {
      teamId: t,
      teamName: m.teamName,
      userRoleLabel: m.role,
      userRoleColor: m.roleColor,
      memberCount: m.members,
      projectCount: projects.length,
      canvasPositionX: m.x,
      canvasPositionY: m.y,
      projects,
    };
  });
}

/** Stable reference (built once) so the graph layout memo doesn't thrash. */
export const HERO_TEAMS: OverviewTeamWithProjects[] = buildTeams();

/* --------------------------------------------- reachability detail (on expand) */
function flow(o: {
  osv: string;
  purl: string;
  epFile: string;
  epMethod: string;
  epLine: number;
  epCode: string;
  sinkFile: string;
  sinkMethod: string;
  sinkLine: number;
  sinkCode: string;
  level: ReachabilityLevel;
  /** Intermediate hops between Source and Sink (the path the stepper walks).
   *  buildHops overrides hops[0]/hops[last] with the entry-point/sink fields. */
  nodes?: ReachableFlowNode[];
}): ReachableFlow {
  return {
    id: `flow-${o.osv}`,
    project_id: "storefront-api",
    extraction_run_id: RUN,
    purl: o.purl,
    dependency_id: null,
    flow_nodes: o.nodes ?? [],
    entry_point_file: o.epFile,
    entry_point_method: o.epMethod,
    entry_point_line: o.epLine,
    entry_point_tag: "http",
    entry_point_code: o.epCode,
    sink_code: o.sinkCode,
    sink_file: o.sinkFile,
    sink_method: o.sinkMethod,
    sink_line: o.sinkLine,
    sink_is_external: true,
    flow_length: 2,
    llm_prompt: null,
    created_at: CREATED,
    osv_id: o.osv,
    reachability_source: "semgrep_taint",
    reachability_level: o.level,
  };
}

const FLOWS: Record<string, ReachableFlow[]> = {
  "CVE-2022-29078": [
    flow({
      osv: "CVE-2022-29078",
      purl: "pkg:npm/ejs@3.1.6",
      epFile: "src/routes/profile.js",
      epMethod: "POST /profile/preview",
      epLine: 18,
      epCode: "router.post('/profile/preview', (req, res) => {\n  const html = renderProfile(req.body);\n  res.send(html);\n});",
      sinkFile: "src/lib/profile-view.js",
      sinkMethod: "ejs.render",
      sinkLine: 6,
      sinkCode: "function renderProfile(opts) {\n  // opts.template comes straight from the request body\n  return ejs.render(opts.template, opts.data);\n}",
      level: "confirmed",
    }),
  ],
  "CVE-2021-23337": [
    flow({
      osv: "CVE-2021-23337",
      purl: "pkg:npm/lodash@4.17.20",
      epFile: "src/routes/render.js",
      epMethod: "POST /render",
      epLine: 14,
      epCode:
        "import { handleRender } from '../controllers/render';\n" +
        "\n" +
        "// POST /render — public preview route, no auth\n" +
        "router.post('/render', (req, res) => {\n" +
        "  // template + data come straight from the client body\n" +
        "  const { tpl, data } = req.body;\n" +
        "\n" +
        "  // no validation — handed straight to the controller\n" +
        "  const html = handleRender({ tpl, data });\n" +
        "\n" +
        "  res.set('content-type', 'text/html');\n" +
        "  res.send(html);\n" +
        "});",
      sinkFile: "src/lib/render-template.js",
      sinkMethod: "_.template",
      sinkLine: 7,
      sinkCode:
        "import _ from 'lodash';\n" +
        "\n" +
        "// Compiles and runs a user-supplied template string.\n" +
        "export function renderTemplate(opts) {\n" +
        "  // opts.tpl reaches lodash _.template as a string\n" +
        "  //  → prototype pollution → command injection\n" +
        "  const compiled = _.template(opts.tpl);\n" +
        "\n" +
        "  // executing the compiled template runs attacker input\n" +
        "  return compiled(opts.data);\n" +
        "}",
      level: "confirmed",
      nodes: [
        { file: "src/routes/render.js", line: 14, label: "POST /render" },
        {
          file: "src/controllers/render.ts",
          line: 22,
          label: "handleRender",
          code:
            "import { renderTemplate } from '../lib/render-template';\n" +
            "\n" +
            "// Builds the render options from the raw request body.\n" +
            "export function handleRender(body) {\n" +
            "  // body.tpl is attacker-controlled and flows on\n" +
            "  // untouched — no schema, no escaping, no allow-list\n" +
            "  const opts = {\n" +
            "    tpl: body.tpl,\n" +
            "    data: body.data ?? {},\n" +
            "  };\n" +
            "\n" +
            "  return renderTemplate(opts);\n" +
            "}",
        },
        { file: "src/lib/render-template.js", line: 7, label: "_.template" },
      ],
    }),
  ],
  "CVE-2024-4068": [
    flow({
      osv: "CVE-2024-4068",
      purl: "pkg:npm/braces@3.0.2",
      epFile: "src/routes/search.js",
      epMethod: "GET /search",
      epLine: 9,
      epCode: "router.get('/search', (req, res) => {\n  const out = expandPattern(req.query.q);",
      sinkFile: "src/lib/glob.js",
      sinkMethod: "braces",
      sinkLine: 12,
      sinkCode: "export function expandPattern(p) {\n  return braces(p, { expand: true }); // unbounded expansion\n}",
      level: "data_flow",
    }),
  ],
};

function vulnDetail(v: ProjectVulnerability): VulnerabilityDetail {
  return {
    vulnerability: { ...v },
    affected_dependencies: [
      {
        id: v.dependency_id,
        name: v.dependency_name,
        version: v.dependency_version,
        is_direct: true,
        dependency_id: v.dependency_id,
        files_importing_count: 1,
        files: [],
      },
    ],
    version_candidates: [],
    timeline_events: [],
    reachable_flows: FLOWS[v.osv_id] ?? [],
    project_importance: 1,
  };
}

const DETAIL_BY_OSV: Record<string, VulnerabilityDetail> = Object.fromEntries(
  heroFindings
    .filter(
      (r): r is Extract<SecurityTableRow, { type: "vulnerability" }> =>
        r.type === "vulnerability",
    )
    .map((r) => [r.data.osv_id, vulnDetail(r.data)]),
);

// Drop-in for VulnerabilityExpandableTable's `fetchDetail` — resolves the mock
// detail inline instead of hitting the authenticated API.
export const heroFindingDetail = (
  _organizationId: string,
  _projectId: string,
  osvId: string,
): Promise<VulnerabilityDetail> => Promise.resolve(DETAIL_BY_OSV[osvId]!);

/* A single ready-made (vuln, detail) pair for the landing "we trace the path"
   section — the REAL VulnerabilityExpandedCard renders this unchanged, so the
   section shows the actual product reachability view (Source → Sink stepper,
   tier badge, signal badges), not a hand-built facsimile. lodash CVE-2021-23337
   is confirmed-reachable with a 2-hop taint trace. */
const TRACE_OSV = "CVE-2021-23337";
export const heroTraceVuln: ProjectVulnerability = heroFindings.find(
  (r): r is Extract<SecurityTableRow, { type: "vulnerability" }> =>
    r.type === "vulnerability" && r.data.osv_id === TRACE_OSV,
)!.data;
export const heroTraceDetail: VulnerabilityDetail = DETAIL_BY_OSV[TRACE_OSV]!;

/* A varied findings list for the "wall of findings" BACKGROUND in the Verified
   section — a diverse spread of real-looking vulns (distinct packages / CVEs /
   depscores, sorted descending by the table) so the faded, non-interactive
   table behind the flow card reads as a believable list, NOT repeated rows.
   Texture only: it's masked + dimmed, never read row-by-row. */
const BG_VULNS: {
  dep: string;
  version: string;
  osv: string;
  severity: ProjectVulnerability["severity"];
  level: ReachabilityLevel;
  depscore: number;
  summary: string;
  project: string;
}[] = [
  { dep: "ejs", version: "3.1.6", osv: "CVE-2022-29078", severity: "critical", level: "confirmed", depscore: 90, summary: "Server-side template injection in ejs leads to remote code execution", project: "storefront-api" },
  { dep: "lodash", version: "4.17.20", osv: "CVE-2021-23337", severity: "high", level: "confirmed", depscore: 72, summary: "Command injection in lodash via _.template()", project: "storefront-api" },
  { dep: "jsonwebtoken", version: "8.5.1", osv: "CVE-2022-23529", severity: "high", level: "function", depscore: 58, summary: "Insecure key handling allows JWT forgery in jsonwebtoken", project: "auth-service" },
  { dep: "express", version: "4.17.1", osv: "CVE-2022-24999", severity: "high", level: "function", depscore: 52, summary: "Prototype pollution via qs in express query parsing", project: "storefront-api" },
  { dep: "follow-redirects", version: "1.14.7", osv: "CVE-2022-0536", severity: "medium", level: "data_flow", depscore: 47, summary: "Information leak on cross-host redirect in follow-redirects", project: "payments-svc" },
  { dep: "braces", version: "3.0.2", osv: "CVE-2024-4068", severity: "medium", level: "data_flow", depscore: 44, summary: "Uncontrolled resource consumption in braces", project: "web-dashboard" },
  { dep: "moment", version: "2.29.1", osv: "CVE-2022-31129", severity: "medium", level: "data_flow", depscore: 41, summary: "Inefficient regex in moment enables ReDoS", project: "web-dashboard" },
  { dep: "semver", version: "7.3.4", osv: "CVE-2022-25883", severity: "medium", level: "module", depscore: 38, summary: "ReDoS in semver range parsing", project: "api-gateway" },
  { dep: "ws", version: "7.4.5", osv: "CVE-2021-32640", severity: "medium", level: "module", depscore: 36, summary: "ReDoS in ws when handling crafted headers", project: "api-gateway" },
  { dep: "node-fetch", version: "2.6.6", osv: "CVE-2022-0235", severity: "medium", level: "module", depscore: 33, summary: "node-fetch leaks sensitive headers across redirects", project: "web-dashboard" },
  { dep: "minimist", version: "1.2.5", osv: "CVE-2021-44906", severity: "high", level: "unreachable", depscore: 0, summary: "Prototype pollution in minimist", project: "storefront-api" },
  { dep: "glob-parent", version: "5.1.1", osv: "CVE-2020-28469", severity: "high", level: "unreachable", depscore: 0, summary: "ReDoS in glob-parent enclosure regex", project: "api-gateway" },
  { dep: "y18n", version: "4.0.0", osv: "CVE-2020-7774", severity: "high", level: "unreachable", depscore: 0, summary: "Prototype pollution in y18n", project: "web-dashboard" },
];

export const heroBackgroundFindings: SecurityTableRow[] = BG_VULNS.map((b, i) =>
  vuln({
    id: `bg-${i}`,
    osv: b.osv,
    cve: b.osv,
    severity: b.severity,
    summary: b.summary,
    dep: b.dep,
    version: b.version,
    depscore: b.depscore,
    level: b.level,
    project: b.project,
  }),
);
