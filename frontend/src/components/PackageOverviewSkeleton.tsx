import { Card, CardContent, CardHeader, CardTitle } from './ui/card';

// Skeleton colour: distinct from card (background-subtle/card) so placeholders are visible
export function PackageOverviewSkeleton() {
  return (
    <div className="space-y-6">
      {/* Header Section – matches PackageOverview: title + meta row, score button on right (no npm install, no separate score card) */}
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <div className="min-w-0 flex-1">
            <div className="h-8 w-56 bg-muted rounded animate-pulse mb-2" />
            <div className="flex items-center gap-4 flex-wrap">
              <div className="h-4 w-12 bg-muted rounded animate-pulse" />
              <div className="h-4 w-14 bg-muted rounded animate-pulse" />
              <div className="h-4 w-10 bg-muted rounded animate-pulse" />
              <div className="h-4 w-20 bg-muted rounded animate-pulse" />
            </div>
          </div>
          {/* Reliability score button (x/100) – same as real UI */}
          <div className="h-10 w-20 rounded-lg border border-border bg-muted animate-pulse shrink-0" />
        </div>

        {/* Package Description */}
        <div className="flex items-start gap-3">
          <div className="h-4 w-4 rounded bg-muted animate-pulse shrink-0 mt-0.5" />
          <div className="space-y-2 flex-1 min-w-0">
            <div className="h-4 w-full max-w-md bg-muted/80 rounded animate-pulse" />
            <div className="h-4 w-3/4 max-w-sm bg-muted/60 rounded animate-pulse" />
          </div>
        </div>
      </div>

      {/* Usage Card – mirrors real layout: darker header, border, icon + title, then status row (text left, buttons right) */}
      <Card className="border-border">
        <CardHeader className="p-4 pt-3 pb-3 rounded-t-lg bg-[#141618] border-b border-border">
          <div className="flex items-center gap-2">
            <div className="h-5 w-5 rounded bg-muted animate-pulse shrink-0" />
            <CardTitle className="text-base">
              <div className="h-4 w-16 bg-muted rounded animate-pulse" />
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent className="pt-4 space-y-4">
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div className="h-4 flex-1 min-w-0 max-w-md bg-muted/70 rounded animate-pulse" />
            <div className="flex items-center gap-2 shrink-0">
              <div className="h-8 w-24 rounded-md bg-muted animate-pulse" />
              <div className="h-8 w-36 rounded-md bg-muted animate-pulse" />
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
