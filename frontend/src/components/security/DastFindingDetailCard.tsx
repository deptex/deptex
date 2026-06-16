// Expanded detail panel for a DAST finding inside the unified findings table.
// Reads as a first-class finding type alongside SCA / container / IaC: a short
// signal strip, the issue description, the attacked endpoint + linked rule, and
// the receiving handler code (rendered through the same CodeBlockCard every
// other finding type uses). Surfaces the runtime cross-link (handler + linked
// SCA) that is DAST's whole differentiator: a confirmed live hit traced to
// source.

import type { ReactNode } from 'react';
import { cn, cleanFilePath } from '../../lib/utils';
import { ShieldAlert, ExternalLink, CircleHelp } from 'lucide-react';
import type { DastFindingDTO } from '../../lib/api';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { CodeBlockCard } from './VulnerabilityOrgSidebarExpandedContent';
import {
  dastEndpointPathOnly,
  dastRuleDocUrl,
  stripHtmlToText,
  meaningfulHandlerName,
} from './dast-format';

const PILL = 'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border';

// The captured handler snippet leads with a couple of context lines above the
// route (an import, a blank, a comment, the `const router = …` declaration) —
// noise when the ask is "show the endpoint". The handler line carries a `→`
// marker; drop everything before it so the block opens on the route itself. The
// `→ NNNN │` markers keep the gutter line numbers correct after the trim.
function trimToEndpoint(snippet: string): string {
  const lines = snippet.split('\n');
  const handlerIdx = lines.findIndex((l) => l.startsWith('→'));
  return handlerIdx > 0 ? lines.slice(handlerIdx).join('\n') : snippet;
}

/** Field label with an optional plain-English help tooltip. */
function GridField({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-0.5">
        {hint ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="inline-flex items-center gap-1 cursor-help">
                {label}
                <CircleHelp className="h-3 w-3 opacity-70" aria-hidden />
              </span>
            </TooltipTrigger>
            <TooltipContent side="top" className="max-w-xs text-xs font-normal normal-case leading-relaxed">
              {hint}
            </TooltipContent>
          </Tooltip>
        ) : (
          label
        )}
      </div>
      {children}
    </div>
  );
}

export default function DastFindingDetailCard({ finding }: { finding: DastFindingDTO }) {
  const f = finding;

  // ZAP descriptions are HTML; flatten and keep the lead paragraph so the issue
  // explanation reads cleanly without becoming a wall.
  const descText = f.message ? stripHtmlToText(f.message) : '';
  const descLead = descText.split('\n\n')[0] ?? descText;

  const handlerFn = meaningfulHandlerName(f.handler_function_name);
  const ruleUrl = dastRuleDocUrl(f.engine, f.rule_id);

  return (
    <div className="space-y-4">
      {/* The depscore already conveys severity, so we don't repeat it as a pill,
          and we drop the scanner engine / confidence / OWASP-code jargon. Only
          KEV — "actively exploited in the wild" — earns a badge. */}
      {f.kev && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className={cn(PILL, 'bg-red-500/15 text-red-400 border-red-500/25')}>KEV</span>
        </div>
      )}

      {/* Confirmed-exploitable banner — the runtime hit reaches a known-vulnerable
          dependency through the same handler. DAST's headline signal. */}
      {f.confirmed_exploitable && f.linked_sca_osv_id && (
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="flex items-center gap-2 rounded-md border border-amber-500/25 bg-amber-500/10 px-3 py-2 cursor-default">
              <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0" />
              <span className="text-xs text-amber-200">
                Confirmed exploitable — runtime hit reaches{' '}
                <span className="font-mono font-medium">{f.linked_sca_osv_id}</span> through this handler.
              </span>
            </div>
          </TooltipTrigger>
          <TooltipContent className="max-w-md text-xs">
            This DAST finding was independently observed at runtime and cross-links to a known
            vulnerable dependency via the tree-sitter reachability graph — the same handler reaches
            both.
          </TooltipContent>
        </Tooltip>
      )}

      {/* Issue description (HTML-stripped lead paragraph). */}
      {descLead && (
        <div className="text-xs text-foreground-secondary leading-relaxed line-clamp-4 whitespace-pre-line">
          {descLead}
        </div>
      )}

      {/* The attacked endpoint (the live URL) and the scanner rule (linked). One
          weakness identifier — the rule — rather than a rule + a CWE both reading
          as "the rule". */}
      <div className="flex flex-wrap items-start gap-x-6 gap-y-3">
        <GridField label="Endpoint" hint="The live URL the scanner attacked (path only — the host and the injected value are elided).">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-[10px] font-mono uppercase text-foreground-secondary border border-border rounded px-1 py-0.5 shrink-0">
              {f.http_method}
            </span>
            <span className="text-sm font-mono text-foreground truncate max-w-[24rem]">
              {dastEndpointPathOnly(f.endpoint_url)}
            </span>
          </div>
        </GridField>
        {f.rule_id && (
          <GridField label="Rule" hint="The scanner's detection rule for this issue. Click to open its documentation.">
            {ruleUrl ? (
              <a
                href={ruleUrl}
                target="_blank"
                rel="noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="text-sm font-mono text-foreground hover:underline inline-flex items-center gap-1"
              >
                {f.rule_id}
                <ExternalLink className="h-3 w-3 text-muted-foreground" />
              </a>
            ) : (
              <span className="text-sm font-mono text-foreground">{f.rule_id}</span>
            )}
          </GridField>
        )}
      </div>

      {/* Endpoint code — the handler in the user's repo that serves this URL,
          rendered like every other finding's code block (file-typed header,
          scrollable, the route line highlighted). Where to apply the fix. */}
      {f.handler_file_path && f.handler_code_snippet ? (
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1 inline-flex items-center gap-1">
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="inline-flex items-center gap-1 cursor-help">
                  Endpoint code
                  <CircleHelp className="h-3 w-3 opacity-70" aria-hidden />
                </span>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs text-xs font-normal normal-case leading-relaxed">
                The code in your repo that serves this endpoint — where to apply the fix. Deptex
                traced the live URL back to this source.
              </TooltipContent>
            </Tooltip>
          </div>
          <CodeBlockCard
            file={f.handler_file_path}
            line={f.handler_line}
            code={trimToEndpoint(f.handler_code_snippet)}
            highlight={null}
          />
        </div>
      ) : (
        f.handler_file_path && (
          // Older runs captured no snippet — degrade to a text location.
          <GridField label="Endpoint code" hint="The function in your code that serves this endpoint — where to apply the fix.">
            <span className="text-sm font-mono text-foreground truncate max-w-[24rem] inline-block align-bottom">
              {handlerFn ? `${handlerFn}() · ` : ''}
              {cleanFilePath(f.handler_file_path)}
              {f.handler_line != null && <span className="text-muted-foreground">:{f.handler_line}</span>}
            </span>
          </GridField>
        )
      )}
    </div>
  );
}
