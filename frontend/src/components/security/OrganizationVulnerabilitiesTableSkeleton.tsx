import { cn } from '../../lib/utils';

const ROWS = 8;

/** Loading skeleton for the (non-embedded) security findings table. Mirrors the real
 *  VulnerabilityExpandableTable chrome — the status filter, and the Type / Finding /
 *  Depscore / Location / (Project) / Status columns — and fades downward (Vercel style)
 *  like the org-sidebar projects table so it reads as "loading", not as a stalled control.
 *  Pass showProjectCol={false} for the single-project view (no Project column). */
export default function OrganizationVulnerabilitiesTableSkeleton({ showProjectCol = true }: { showProjectCol?: boolean }) {
  return (
    <div className="space-y-3 pointer-events-none select-none" aria-busy="true" aria-label="Loading security findings">
      {/* Filter bar — placeholder selects (type + status). No Open/All toggle anymore. */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="h-8 w-[120px] rounded-md border border-border bg-background-card animate-pulse" />
        <div className="h-8 w-[110px] rounded-md border border-border bg-background-card animate-pulse" />
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
            {/* finding col has no explicit width so it absorbs leftover space */}
            <col />
            <col className="w-[8rem]" />
            <col className="w-[18rem]" />
            {showProjectCol && <col className="w-[18rem]" />}
            <col className="w-[11rem]" />
          </colgroup>
          <thead className="bg-background-card-header border-b border-border">
            <tr>
              <th className="text-center px-2 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Type</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Finding</th>
              <th className="text-center px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Depscore</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Location</th>
              {showProjectCol && (
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
              )}
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
                {/* Location */}
                <td className="px-4 py-3 align-top">
                  <div className={cn(
                    'h-4 rounded-md bg-muted/45 animate-pulse',
                    i % 3 === 0 && 'w-[70%]',
                    i % 3 === 1 && 'w-[52%]',
                    i % 3 === 2 && 'w-[62%]',
                  )} />
                </td>
                {/* Project */}
                {showProjectCol && (
                  <td className="px-4 py-3 align-top">
                    <div className={cn(
                      'h-4 rounded-md bg-muted/50 animate-pulse',
                      i % 3 === 0 && 'w-[65%]',
                      i % 3 === 1 && 'w-[80%]',
                      i % 3 === 2 && 'w-[55%]',
                    )} />
                  </td>
                )}
                {/* Status pill */}
                <td className="px-4 py-3 align-top">
                  <div className="h-6 w-16 rounded-full bg-muted/40 animate-pulse mx-auto" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
