import { useMemo } from 'react';
import { type DataFlowFinding, type ReachableFlow, type ReachableFlowNode } from '../../lib/api';
import { PathCard } from './VulnerabilityOrgSidebarExpandedContent';
import { cn, cleanFilePath } from '../../lib/utils';

/** Expanded view for a first-party data-flow finding. The taint engine traced
 *  a complete path from an untrusted request boundary to a dangerous sink in
 *  the user's OWN code (no dependency CVE). We reuse the exact Source → Sink
 *  stepper the vulnerability detail uses (PathCard), framed by a short header
 *  that explains why a *reachable* flow is high-signal. */

const SEVERITY_BADGE: Record<DataFlowFinding['severity'], string> = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/20',
  high: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  medium: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  low: 'bg-green-500/10 text-green-400 border-green-500/20',
};

/** `framework-input:PUBLIC_UNAUTH` → "Public · unauthenticated input". The tag
 *  is the entry-point class the engine attributed the source to. */
function entryPointClassLabel(tag: string | null): string | null {
  if (!tag) return null;
  const cls = tag.includes(':') ? tag.split(':').pop()! : tag;
  switch (cls.toUpperCase()) {
    case 'PUBLIC_UNAUTH':
      return 'Public · unauthenticated input';
    case 'PUBLIC_AUTH':
      return 'Authenticated request input';
    case 'INTERNAL':
      return 'Internal input';
    default:
      return cls.replace(/_/g, ' ').toLowerCase();
  }
}

/** The taint source's short label (e.g. `searchParams.msg`) — the first
 *  real (non-synthetic) hop the engine marked as the source. */
function sourceLabel(finding: DataFlowFinding): string | null {
  const nodes = (finding.flow_nodes ?? []) as ReachableFlowNode[];
  const src = nodes.find((n) => (n as any).kind === 'source');
  return (src?.label ?? src?.name ?? null) || finding.entry_point_method || null;
}

export default function DataFlowFindingCard({ finding }: { finding: DataFlowFinding }) {
  // Adapt the finding into the ReachableFlow shape PathCard renders. The
  // flow_nodes come straight from the same JSONB the vulnerability detail
  // reads, so buildHops()/findSynthetic() handle them unchanged.
  const flow = useMemo<ReachableFlow>(
    () => ({
      id: finding.id,
      project_id: finding.project_id,
      extraction_run_id: finding.extraction_run_id,
      purl: '',
      dependency_id: null,
      flow_nodes: (finding.flow_nodes ?? []) as ReachableFlowNode[],
      entry_point_file: finding.entry_point_file,
      entry_point_method: finding.entry_point_method,
      entry_point_line: finding.entry_point_line,
      entry_point_tag: finding.entry_point_tag,
      entry_point_code: finding.entry_point_code,
      sink_code: finding.sink_code,
      sink_file: finding.sink_file,
      sink_method: finding.sink_method,
      sink_line: finding.sink_line,
      sink_is_external: false,
      flow_length: finding.flow_length ?? 0,
      llm_prompt: null,
      created_at: finding.created_at ?? '',
    }),
    [finding],
  );

  const epClass = entryPointClassLabel(finding.entry_point_tag);
  const src = sourceLabel(finding);
  const sink = finding.sink_method ?? 'a dangerous sink';
  const sinkLoc =
    finding.sink_file != null
      ? `${cleanFilePath(finding.sink_file)}${finding.sink_line != null ? `:${finding.sink_line}` : ''}`
      : null;

  return (
    <div className="space-y-4">
      {/* Badges: vuln class + severity, entry class. The reachable-path proof
          is the traced Source → Sink stepper below, so no redundant badge. */}
      <div className="flex flex-wrap items-center gap-1.5">
        <span
          className={cn(
            'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border',
            SEVERITY_BADGE[finding.severity],
          )}
        >
          {finding.title}
        </span>
        {epClass && (
          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
            {epClass}
          </span>
        )}
      </div>

      {/* Why it matters — a reachable taint path is stronger than a pattern
          match: the engine proved the data actually arrives at the sink. */}
      <div className="text-xs text-foreground-secondary leading-relaxed">
        Untrusted input{src ? <> from <code className="text-foreground font-mono">{src}</code></> : ''} flows to{' '}
        <code className="text-foreground font-mono">{sink}</code>
        {sinkLoc ? <> in <span className="font-mono">{sinkLoc}</span></> : ''} without sanitization. The taint engine
        traced a complete path from the request boundary to the sink, so this is exploitable in how the code actually
        runs — not just a pattern that looks risky.
      </div>

      {/* The traced Source → Sink path (same stepper as a reachable CVE). */}
      <PathCard flows={[flow]} level="confirmed" isFlowSuppressed={() => false} />
    </div>
  );
}
