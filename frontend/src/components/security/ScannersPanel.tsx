import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { api, frameworkLabel, type ScannerSummary } from '../../lib/api';
import { Button } from '../ui/button';
import { cn } from '../../lib/utils';
import RegistryCredentialsSection from './RegistryCredentialsSection';

interface Props {
  organizationId: string;
  projectId: string;
  canManage: boolean;
  onTriggerRescan?: () => Promise<void> | void;
}

function formatLastScan(iso: string | null): string {
  if (!iso) return 'Never';
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso;
  }
}

export default function ScannersPanel({
  organizationId,
  projectId,
  canManage,
  onTriggerRescan,
}: Props) {
  const [summary, setSummary] = useState<ScannerSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rescanning, setRescanning] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getProjectScannerSummary(organizationId, projectId)
      .then((s) => {
        if (cancelled) return;
        setSummary(s);
      })
      .catch((e: any) => {
        if (cancelled) return;
        setError(e?.message ?? 'Failed to load scanner summary');
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [organizationId, projectId]);

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="p-6">
          <h3 className="text-base font-semibold text-foreground mb-1">
            IaC + Container Scanners
          </h3>
          <p className="text-sm text-foreground-secondary mb-4">
            Read-only view of which scanners ran against this project at the
            last extraction. Configuration is auto-detected from the repo.
          </p>

          {loading ? (
            <div className="flex items-center gap-2 text-sm text-foreground-secondary">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading scanner status…
            </div>
          ) : error ? (
            <div className="text-sm text-destructive">{error}</div>
          ) : summary ? (
            <div className="space-y-4">
              <div>
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
                  Detected Coverage
                </div>
                {summary.infra_types.length === 0 ? (
                  <div className="text-sm text-foreground-secondary">
                    No infrastructure files detected.
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {summary.infra_types.map((t) => (
                      <span
                        key={t}
                        className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-foreground/5 text-foreground-secondary border border-border"
                      >
                        {frameworkLabel(t)}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
                    IaC Findings
                  </div>
                  <RollupChips rollup={summary.iac} />
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
                    Container Findings
                  </div>
                  <RollupChips rollup={summary.container} />
                </div>
              </div>

              <div className="flex items-center justify-between gap-4 pt-2 border-t border-border">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-0.5">
                    Last Scan
                  </div>
                  <div className="text-sm text-foreground">
                    {formatLastScan(summary.last_scan_at)}
                  </div>
                </div>
                {onTriggerRescan && (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={rescanning}
                    onClick={async () => {
                      try {
                        setRescanning(true);
                        await onTriggerRescan();
                      } finally {
                        setRescanning(false);
                      }
                    }}
                  >
                    {rescanning ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : null}
                    Trigger rescan
                  </Button>
                )}
              </div>
            </div>
          ) : null}
        </div>
      </div>

      <RegistryCredentialsSection organizationId={organizationId} canManage={canManage} />
    </div>
  );
}

function RollupChips({
  rollup,
}: {
  rollup: ScannerSummary['iac'];
}) {
  const items: Array<{ label: string; value: number; cls: string }> = [
    {
      label: 'Critical',
      value: rollup.critical,
      cls: 'bg-red-500/10 text-red-400 border-red-500/20',
    },
    {
      label: 'High',
      value: rollup.high,
      cls: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    },
    {
      label: 'Medium',
      value: rollup.medium,
      cls: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    },
    {
      label: 'Low',
      value: rollup.low,
      cls: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20',
    },
    {
      label: 'Ignored',
      value: rollup.ignored,
      cls: 'bg-foreground/5 text-foreground-secondary border-border',
    },
  ];
  const allZero = items.every((i) => i.value === 0);
  if (allZero) {
    return (
      <span className="text-sm text-foreground-secondary">
        No findings.
      </span>
    );
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((i) =>
        i.value === 0 ? null : (
          <span
            key={i.label}
            className={cn(
              'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border',
              i.cls
            )}
          >
            {i.label} <span className="tabular-nums">{i.value}</span>
          </span>
        )
      )}
    </div>
  );
}
