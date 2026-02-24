import { memo } from 'react';
import { Loader2, Zap, ArrowUpCircle, CheckCircle2 } from 'lucide-react';
import type { LatestSafeVersionResponse } from '../../lib/api';
import { Card, CardHeader } from '../ui/card';
import { Button } from '../ui/button';

interface SafeVersionCardProps {
  data: LatestSafeVersionResponse | null;
  loading: boolean;
  severity: string;
  onSeverityChange: (severity: string) => void;
  onSimulate: (versionId: string) => void;
  canManage?: boolean;
  onBumpAll?: () => void;
  bumpingAll?: boolean;
  bumpScope?: 'org' | 'team' | 'project';
  /** When true, user is viewing the simulated safe version in the graph; show Simulate + Bump. When false, only show Simulate. */
  isViewingSimulatedSafeVersion?: boolean;
  /** When true, preview/simulate is loading; show spinner on Preview button instead of icon. */
  simulating?: boolean;
}

function SafeVersionCardComponent({ data, loading, severity, onSeverityChange, onSimulate, canManage, onBumpAll, bumpingAll, bumpScope = 'project', isViewingSimulatedSafeVersion = false, simulating = false }: SafeVersionCardProps) {
  const bumpLabel = bumpScope === 'project' ? 'Bump this project' : 'Bump all projects';

  // Loading skeleton — matches card layout (w-fit + gap-4 between text and button)
  if (loading && !data) {
    return (
      <Card className="w-fit min-w-[200px] shadow-md transition-[width] duration-200 ease-in-out">
        <div className="p-3 animate-pulse">
          <div className="flex items-center gap-4">
            <div className="space-y-1 min-w-0">
              <div className="h-3 w-20 bg-muted rounded" />
              <div className="h-3.5 w-12 bg-muted rounded" />
            </div>
            <div className="h-7 w-[72px] rounded-md bg-muted shrink-0" />
          </div>
        </div>
      </Card>
    );
  }

  if (!data) return null;

  const isCurrent = data.isCurrent;
  const hasSafeVersion = data.safeVersion !== null;
  const cardIsWide = hasSafeVersion && !isCurrent && isViewingSimulatedSafeVersion && !!onBumpAll;
  const cardWidth = cardIsWide ? 'w-fit min-w-[240px]' : 'w-fit min-w-[200px]';

  // State: Already on the latest safe version — neutral card
  if (isCurrent && hasSafeVersion) {
    return (
      <Card className="w-[220px] shadow-md transition-[width] duration-200 ease-in-out">
        <CardHeader className="p-3 pb-2">
          <div className="flex items-start gap-2">
            <div className="min-w-0">
              <p className="text-xs font-medium text-foreground leading-tight">Recommended</p>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="text-sm text-foreground-secondary">{data.safeVersion}</span>
                <CheckCircle2 className="h-3.5 w-3.5 text-success shrink-0" />
              </div>
            </div>
          </div>
        </CardHeader>
      </Card>
    );
  }

  // State: Found a safe version (different from current) — Preview (narrow) / Bump (wide)
  if (hasSafeVersion && !isCurrent) {
    return (
      <Card className={`${cardWidth} shadow-md transition-[width] duration-200 ease-in-out`}>
        <CardHeader className="p-3 pb-2">
          <div className="flex items-center gap-4">
            <div className="min-w-0">
              <p className="text-xs font-medium text-foreground leading-tight">Recommended</p>
              <p className="text-sm text-foreground-secondary mt-0.5">{data.safeVersion}</p>
            </div>
            <div className="shrink-0">
              {isViewingSimulatedSafeVersion && onBumpAll ? (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={onBumpAll}
                  disabled={bumpingAll}
                >
                  {bumpingAll ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <ArrowUpCircle className="h-3 w-3" />
                  )}
                  {bumpLabel}
                </Button>
              ) : (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => data.safeVersionId && onSimulate(data.safeVersionId)}
                  disabled={simulating}
                >
                  {simulating ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <Zap className="h-3 w-3" />
                  )}
                  Preview
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
      </Card>
    );
  }

  // State: No safe version found — neutral card
  return (
    <Card className="w-[220px] shadow-md transition-[width] duration-200 ease-in-out">
      <CardHeader className="p-3 pb-2">
        <div className="flex items-start gap-2">
          <div className="min-w-0">
            <p className="text-xs font-medium text-foreground leading-tight">No safe version found</p>
            <p className="text-[10px] text-foreground-secondary mt-0.5">
              {data.message ?? 'No version meets the severity threshold.'}
            </p>
          </div>
        </div>
      </CardHeader>
    </Card>
  );
}

export const SafeVersionCard = memo(SafeVersionCardComponent);
