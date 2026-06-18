import { ExternalLink } from 'lucide-react';
import { type ContainerFinding, type IaCFinding } from '../../lib/api';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { CodeBlockCard } from './VulnerabilityOrgSidebarExpandedContent';
import { iacRuleInfo, iacViolationToken, checkovRuleDocUrl } from './infra-format';
import { cn } from '../../lib/utils';

type IaCRow = { type: 'iac'; data: IaCFinding };
type ContainerRow = { type: 'container'; data: ContainerFinding };

type Props = IaCRow | ContainerRow;

// Format a normalized compliance benchmark key (e.g. cis_aws_v1_4 → 'CIS AWS V1.4')
// for display in the badge strip. Acronyms are upper-cased; v1_4 becomes V1.4.
function formatBenchmarkLabel(key: string): string {
  return key
    .split('_')
    .map((part) => {
      if (/^v\d+/i.test(part)) {
        return part
          .replace(/^v/i, 'V')
          .replace(/(\d+)(\d+)$/, '$1.$2');
      }
      if (/^(cis|soc|nist|pci|hipaa|fedramp|gdpr|iso|cwe|owasp)\d*$/i.test(part)) {
        return part.toUpperCase();
      }
      return part.charAt(0).toUpperCase() + part.slice(1);
    })
    .join(' ');
}

export default function InfraFindingCard(props: Props) {
  if (props.type === 'iac') {
    const f = props.data;
    const info = iacRuleInfo(f.rule_id, f.severity, f.message);
    const ruleUrl = f.rule_doc_url || checkovRuleDocUrl(f.rule_id);
    // Checkov community checks ship an empty description; fall back to the
    // rule's real impact line so the body is never blank.
    const descriptionText = f.description?.trim() || info.impact;

    // Highlight the actual violated line (e.g. `privileged: true` / `hostPath:`),
    // not the resource-block start the scanner anchors on. k8s snippets begin at
    // the resource's `start_line`; Dockerfile snippets are the whole file from
    // line 1 (so the flagged instruction shows in full context).
    const isDockerfile = f.framework === 'dockerfile';
    const snippetStart = isDockerfile ? 1 : (f.start_line ?? 1);
    let highlightLine: number | null = null;
    const token = iacViolationToken(f.rule_id);
    if (token && f.code_snippet) {
      const idx = f.code_snippet.split('\n').findIndex((l) => l.includes(token));
      if (idx >= 0) highlightLine = snippetStart + idx;
    } else if (isDockerfile && f.code_snippet && f.start_line != null) {
      // Trivy's Dockerfile rules (DS-*) carry no token but anchor precisely on the
      // offending instruction (`USER root`, the flagged `RUN` block) — highlight
      // that real file line within the whole-file snippet. (k8s missing-control
      // rules have no such line and fall through to no code block.)
      highlightLine = f.start_line;
    }

    const complianceEntries = f.compliance_refs
      ? Object.entries(f.compliance_refs).filter(([, ids]) => ids.length > 0)
      : [];

    return (
      <div className="space-y-4">
        {/* No severity / scanner / platform badges: the depscore already conveys
            priority, and "Kubernetes / Checkov" just repeats what the file and
            title already say. */}
        {f.cwe_ids != null && f.cwe_ids.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            {f.cwe_ids.slice(0, 3).map((cwe) => (
              <span
                key={cwe}
                className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20"
              >
                {cwe}
              </span>
            ))}
          </div>
        )}

        <div className="text-xs text-foreground-secondary leading-relaxed">
          {descriptionText}
        </div>

        {complianceEntries.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Compliance
            </span>
            {complianceEntries.map(([key, ids]) => (
              <Tooltip key={key}>
                <TooltipTrigger asChild>
                  <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-blue-500/10 text-blue-300 border border-blue-500/20 cursor-help">
                    {formatBenchmarkLabel(key)} · {ids.length}
                  </span>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-xs text-xs font-normal normal-case">
                  {ids.join(', ')}
                </TooltipContent>
              </Tooltip>
            ))}
          </div>
        )}

        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-0.5">
            Rule
          </div>
          {ruleUrl ? (
            <a
              href={ruleUrl}
              target="_blank"
              rel="noreferrer"
              className="text-sm font-mono text-foreground hover:underline inline-flex items-center gap-1"
              onClick={(e) => e.stopPropagation()}
            >
              {f.rule_id}
              <ExternalLink className="h-3 w-3 text-muted-foreground" />
            </a>
          ) : (
            <span className="text-sm font-mono text-foreground">{f.rule_id}</span>
          )}
        </div>

        {/* Show the manifest with the offending line highlighted ONLY when we can
            pin the exact violated line (a dangerous value is present in the
            snippet). When the violation is a MISSING control there's no line to
            point at — and the captured snippet is just the resource-block header,
            so dumping it un-highlighted only confuses. In that case show nothing
            extra: the description carries the issue, and Aegis owns the fix. */}
        {highlightLine != null && f.code_snippet && (
          // No `:line` in the header — the gutter already shows line numbers and
          // the violated line is highlighted, so repeating it reads as clutter.
          <CodeBlockCard
            file={f.file_path}
            firstLine={snippetStart}
            code={f.code_snippet}
            highlight={highlightLine}
          />
        )}
      </div>
    );
  }

  const f = props.data;
  const cveOrOsv = f.cve_id ?? f.osv_id ?? f.vulnerability_id;
  const ruleDocUrl = f.rule_doc_url;
  return (
    <div className="space-y-4">
      {/* Container CVE: depscore conveys priority, so no standalone severity pill
          — keep the specifics (CVSS, KEV) that severity alone can't say. */}
      {(f.cvss_score != null || f.is_kev) && (
        <div className="flex flex-wrap items-center gap-1.5">
          {f.cvss_score != null && (
            <span
              className={cn(
                'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border',
                f.cvss_score >= 9
                  ? 'bg-red-500/10 text-red-400 border-red-500/20'
                  : f.cvss_score >= 7
                  ? 'bg-orange-500/10 text-orange-400 border-orange-500/20'
                  : f.cvss_score >= 4
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                  : 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20'
              )}
            >
              CVSS {f.cvss_score.toFixed(1)}
            </span>
          )}
          {f.is_kev && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-500/15 text-red-400 border border-red-500/25">
              KEV
            </span>
          )}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-0.5">
            CVE / Advisory
          </div>
          {ruleDocUrl ? (
            <a
              href={ruleDocUrl}
              target="_blank"
              rel="noreferrer"
              className="text-sm font-medium text-foreground hover:underline"
              onClick={(e) => e.stopPropagation()}
            >
              {cveOrOsv}
            </a>
          ) : (
            <div className="text-sm font-medium text-foreground">{cveOrOsv}</div>
          )}
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-0.5">
            Package
          </div>
          <div className="text-sm font-mono text-foreground">
            {f.os_package_name}@{f.os_package_version}
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-0.5">
            Image
          </div>
          <div className="text-sm font-mono text-foreground truncate max-w-[28rem]">
            {f.image_reference}
          </div>
        </div>
        <div className="flex items-center self-center">
          {f.fix_versions != null && f.fix_versions.length > 0 ? (
            <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs bg-success/15 text-success border border-success/30">
              Fixed in {f.fix_versions[0]}
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs bg-red-500/10 text-red-400 border border-red-500/20">
              No fix available
            </span>
          )}
        </div>
      </div>

      {f.description && (
        <div className="text-xs text-foreground-secondary leading-relaxed line-clamp-4">
          {f.description}
        </div>
      )}
    </div>
  );
}
