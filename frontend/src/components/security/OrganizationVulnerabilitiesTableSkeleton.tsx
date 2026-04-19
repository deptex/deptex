import { cn } from '../../lib/utils';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';

const ROWS = 8;

export default function OrganizationVulnerabilitiesTableSkeleton() {
  return (
    <div className="space-y-3">
      {/* Filter bar — real dropdowns, disabled */}
      <div className="flex items-center gap-2 flex-wrap">
        <Select disabled>
          <SelectTrigger className="h-8 w-auto min-w-[120px] text-xs gap-1.5">
            <SelectValue placeholder="All types" />
          </SelectTrigger>
          <SelectContent><SelectItem value="all">All types</SelectItem></SelectContent>
        </Select>
        <Select disabled>
          <SelectTrigger className="h-8 w-auto min-w-[80px] text-xs gap-1.5">
            <SelectValue placeholder="Open" />
          </SelectTrigger>
          <SelectContent><SelectItem value="open">Open</SelectItem></SelectContent>
        </Select>
      </div>

      {/* Table skeleton */}
      <div
        className="rounded-lg border border-border bg-background-card overflow-hidden"
        aria-busy="true"
        aria-label="Loading security findings"
      >
        <table className="w-full text-sm table-fixed">
          <colgroup>
            <col className="w-8" />
            <col className="w-[45%]" />
            <col className="w-[10rem]" />
            <col className="w-[8rem]" />
            <col className="w-10" />
          </colgroup>
          <thead className="bg-background-card-header border-b border-border">
            <tr>
              <th className="text-center px-2 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Type</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Finding</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Depscore</th>
              <th className="py-3" />
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
                {/* Project */}
                <td className="px-4 py-3 align-top">
                  <div className={cn(
                    'h-4 rounded-md bg-muted/50 animate-pulse',
                    i % 3 === 0 && 'w-[65%]',
                    i % 3 === 1 && 'w-[80%]',
                    i % 3 === 2 && 'w-[55%]',
                  )} />
                </td>
                {/* Depscore badge */}
                <td className="px-4 py-3 align-top">
                  <div className="h-6 w-8 rounded-full bg-muted/50 animate-pulse" />
                </td>
                {/* Expand button */}
                <td className="px-2 py-3" />
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
