import { cn } from '../../lib/utils';

const ROWS = 8;

/** Loading skeleton for the (non-embedded) security findings table. Mirrors the real
 *  VulnerabilityExpandableTable chrome — the Open/All pill toggle + type filter, and the
 *  Type / Finding / Project / Depscore / Status columns — and fades downward (Vercel style)
 *  like the org-sidebar projects table so it reads as "loading", not as a stalled control. */
export default function OrganizationVulnerabilitiesTableSkeleton() {
  return (
    <div className="space-y-3 pointer-events-none select-none" aria-busy="true" aria-label="Loading security findings">
      {/* Filter bar — matches the loaded view: Open/All toggle + a type filter (not two plain selects) */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="inline-flex h-8 items-center rounded-lg border border-border bg-background-card p-0.5">
          {['Open', 'All findings'].map((label, i) => (
            <span
              key={label}
              className={cn(
                'inline-flex h-7 items-center gap-1.5 rounded-md px-2.5 text-xs',
                i === 0
                  ? 'bg-background-subtle text-foreground/70 font-medium shadow-sm ring-1 ring-white/[0.06]'
                  : 'text-foreground-secondary',
              )}
            >
              {label}
              <span className="h-3 w-4 rounded bg-muted/60 animate-pulse" />
            </span>
          ))}
        </div>
        <div className="h-8 w-[120px] rounded-md border border-border bg-background-card animate-pulse" />
      </div>

      {/* Table — fades downward like the org-sidebar table */}
      <div
        className="rounded-lg border border-border bg-background-card overflow-hidden"
        style={{
          maskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
          WebkitMaskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
        }}
      >
        <table className="w-full text-sm table-fixed">
          <colgroup>
            <col className="w-16" />
            <col />
            <col className="w-[8rem]" />
            <col className="w-[18rem]" />
            <col className="w-[9rem]" />
          </colgroup>
          <thead className="bg-background-card-header border-b border-border">
            <tr>
              <th className="text-center px-2 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Type</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Finding</th>
              <th className="text-center px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Depscore</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
              <th className="text-center px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</th>
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: ROWS }, (_, i) => (
              <tr key={i} className={cn(i < ROWS - 1 && 'border-b border-border')}>
                {/* Type icon */}
                <td className="px-2 py-3">
                  <div className="h-[14px] w-[14px] rounded bg-muted/50 animate-pulse mx-auto" />
                </td>
                {/* Finding */}
                <td className="px-4 py-3 align-top min-w-0">
                  <div className="space-y-2">
                    <div className={cn(
                      'h-4 rounded-md bg-muted/55 animate-pulse',
                      i % 4 === 0 && 'w-[82%]',
                      i % 4 === 1 && 'w-[68%]',
                      i % 4 === 2 && 'w-[76%]',
                      i % 4 === 3 && 'w-[60%]',
                    )} />
                    <div className={cn(
                      'h-3 rounded-md bg-muted/40 animate-pulse',
                      i % 3 === 0 && 'w-[55%]',
                      i % 3 === 1 && 'w-[70%]',
                      i % 3 === 2 && 'w-[48%]',
                    )} />
                  </div>
                </td>
                {/* Depscore badge */}
                <td className="px-4 py-3 align-top">
                  <div className="h-6 w-8 rounded-full bg-muted/50 animate-pulse mx-auto" />
                </td>
                {/* Project */}
                <td className="px-4 py-3 align-top">
                  <div className={cn(
                    'h-4 rounded-md bg-muted/50 animate-pulse',
                    i % 3 === 0 && 'w-[65%]',
                    i % 3 === 1 && 'w-[80%]',
                    i % 3 === 2 && 'w-[55%]',
                  )} />
                </td>
                {/* Status badge */}
                <td className="px-4 py-3 align-top">
                  <div className="h-4 w-16 rounded-md bg-muted/40 animate-pulse mx-auto" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
