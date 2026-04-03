import { cn } from '../../lib/utils';

const ROWS = 10;

/**
 * Loading placeholder matching org-mode {@link VulnerabilityExpandableTable} layout (5 columns).
 */
export default function OrganizationVulnerabilitiesTableSkeleton() {
  return (
    <div
      className="rounded-lg border border-border bg-background-card overflow-hidden"
      aria-busy="true"
      aria-label="Loading vulnerability list"
    >
      <table className="w-full text-sm table-fixed">
        <colgroup>
          <col className="w-[26%]" />
          <col className="w-[20rem]" />
          <col className="w-[6.5rem]" />
          <col className="w-[8rem]" />
          <col />
        </colgroup>
        <thead className="bg-background-card-header border-b border-border">
          <tr>
            {['Vulnerability', 'Project', 'Severity', 'Dep score', 'Dependency'].map((label) => (
              <th
                key={label}
                className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"
              >
                {label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {Array.from({ length: ROWS }, (_, i) => (
            <tr key={i}>
              <td className="px-4 py-3 align-top min-w-0">
                <div className="space-y-2 min-w-0">
                  <div
                    className={cn(
                      'h-4 rounded-md bg-muted/55 animate-pulse max-w-full',
                      i % 4 === 0 && 'w-[88%]',
                      i % 4 === 1 && 'w-[72%]',
                      i % 4 === 2 && 'w-[80%]',
                      i % 4 === 3 && 'w-[65%]'
                    )}
                  />
                  <div className="h-3 rounded-md bg-muted/45 animate-pulse w-[90%] max-w-md" />
                </div>
              </td>
              <td className="px-4 py-3 align-top min-w-0">
                <div
                  className={cn(
                    'h-4 rounded-md bg-muted/50 animate-pulse max-w-[12rem]',
                    i % 3 === 0 && 'w-[70%]',
                    i % 3 === 1 && 'w-[85%]',
                    i % 3 === 2 && 'w-[60%]'
                  )}
                />
              </td>
              <td className="px-4 py-3 align-top">
                <div className="h-6 w-[4.25rem] rounded-md bg-muted/50 animate-pulse" />
              </td>
              <td className="px-4 py-3 align-top">
                <div className="h-4 w-12 rounded-md bg-muted/55 animate-pulse" />
              </td>
              <td className="px-4 py-3 align-top min-w-0">
                <div className="space-y-1.5 min-w-0">
                  <div className="h-3.5 rounded-md bg-muted/50 animate-pulse w-[78%] max-w-xs" />
                  <div className="h-3 rounded-md bg-muted/40 animate-pulse w-24 font-mono" />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
