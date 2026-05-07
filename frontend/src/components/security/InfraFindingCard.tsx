import { Eye, EyeOff, Loader2 } from 'lucide-react';
import { Button } from '../ui/button';
import { cn } from '../../lib/utils';
import { frameworkLabel, type ContainerFinding, type IaCFinding } from '../../lib/api';
import { CodeSnippetBlock, getLangInfo } from './VulnerabilityOrgSidebarExpandedContent';

type IaCRow = { type: 'iac'; data: IaCFinding };
type ContainerRow = { type: 'container'; data: ContainerFinding };

type Props =
  | (IaCRow & {
      isIgnored: boolean;
      busy: boolean;
      onToggleStatus: () => void;
    })
  | (ContainerRow & {
      isIgnored: boolean;
      busy: boolean;
      onToggleStatus: () => void;
    });

function severityClass(sev: string | null): string {
  switch ((sev ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'bg-red-500/10 text-red-400 border-red-500/20';
    case 'HIGH':
      return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    case 'MEDIUM':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    case 'LOW':
      return 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20';
    default:
      return 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20';
  }
}

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

function ignoreButton({
  busy,
  isIgnored,
  onClick,
}: {
  busy: boolean;
  isIgnored: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className="h-7 text-xs gap-1.5 shrink-0"
      disabled={busy}
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
    >
      {busy ? (
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
      ) : isIgnored ? (
        <Eye className="h-3.5 w-3.5" />
      ) : (
        <EyeOff className="h-3.5 w-3.5" />
      )}
      {isIgnored ? 'Unignore' : 'Ignore'}
    </Button>
  );
}

export default function InfraFindingCard(props: Props) {
  const { isIgnored, busy, onToggleStatus } = props;
  const sev = props.data.severity;
  const ruleDocUrl = props.data.rule_doc_url;
  const sevBadge = sev ? (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border',
        severityClass(sev)
      )}
    >
      {sev}
    </span>
  ) : null;

  if (props.type === 'iac') {
    const f = props.data;
    const complianceEntries = f.compliance_refs
      ? Object.entries(f.compliance_refs).filter(([, ids]) => ids.length > 0)
      : [];
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-1.5">
            {sevBadge}
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
              {frameworkLabel(f.framework)}
            </span>
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
              {f.scanner === 'checkov' ? 'Checkov' : 'Trivy'}
            </span>
            {f.cwe_ids.length > 0 &&
              f.cwe_ids.slice(0, 3).map((cwe) => (
                <span
                  key={cwe}
                  className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20"
                >
                  {cwe}
                </span>
              ))}
          </div>
          {ignoreButton({ busy, isIgnored, onClick: onToggleStatus })}
        </div>

        {complianceEntries.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Compliance
            </span>
            {complianceEntries.map(([key, ids]) => (
              <span
                key={key}
                className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-blue-500/10 text-blue-300 border border-blue-500/20"
                title={ids.join(', ')}
              >
                {formatBenchmarkLabel(key)} · {ids.length}
              </span>
            ))}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-0.5">
              Rule
            </div>
            {ruleDocUrl ? (
              <a
                href={ruleDocUrl}
                target="_blank"
                rel="noreferrer"
                className="text-sm font-medium text-foreground hover:underline"
                onClick={(e) => e.stopPropagation()}
              >
                {f.rule_id}
              </a>
            ) : (
              <div className="text-sm font-medium text-foreground">{f.rule_id}</div>
            )}
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-0.5">
              File
            </div>
            <div className="text-sm font-mono text-foreground">
              {f.file_path}
              {f.start_line != null && (
                <span className="text-muted-foreground">:{f.start_line}</span>
              )}
            </div>
          </div>
        </div>

        {(f.description || f.message) && (
          <div className="text-xs text-foreground-secondary leading-relaxed">
            {f.description ?? f.message}
          </div>
        )}

        {f.code_snippet && (
          <div className="rounded-lg border border-border overflow-hidden">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-[#0a0a0b] border-b border-zinc-800/50">
              {(() => {
                const li = getLangInfo(f.file_path);
                return (
                  <span
                    className={cn(
                      'font-mono text-[10px] font-bold tracking-tight select-none',
                      li.color
                    )}
                  >
                    {li.label}
                  </span>
                );
              })()}
              <span className="text-[11px] text-foreground truncate">{f.file_path}</span>
            </div>
            <CodeSnippetBlock
              file={f.file_path}
              line={f.start_line}
              code={f.code_snippet}
            />
          </div>
        )}
      </div>
    );
  }

  const f = props.data;
  const cveOrOsv = f.cve_id ?? f.osv_id ?? f.vulnerability_id;
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {sevBadge}
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
        {ignoreButton({ busy, isIgnored, onClick: onToggleStatus })}
      </div>

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
          {f.fix_versions.length > 0 ? (
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
