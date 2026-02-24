import { FileCheck, TrendingUp, Calendar } from 'lucide-react';
import { ProjectDependency } from '../lib/api';

interface ScoreBreakdownSidebarProps {
  dependency: ProjectDependency;
  organizationId: string;
  projectId: string;
  onClose: () => void;
}

export function ScoreBreakdownSidebar({ dependency, onClose }: ScoreBreakdownSidebarProps) {
  const analysis = dependency.analysis;
  const openssfScore = analysis?.openssf_score ?? null;
  const weeklyDownloads = analysis?.weekly_downloads ?? null;
  const releasesLast12Months = analysis?.releases_last_12_months ?? null;

  return (
    <div className="fixed inset-0 z-50">
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden
      />
      <div
        className="fixed right-0 top-0 h-full w-full max-w-xl bg-background border-l border-border shadow-2xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]">
          <h2 className="text-lg font-semibold text-foreground">What makes up the reputation score</h2>
        </div>
        <div className="flex-1 overflow-y-auto px-6 pt-6 pb-6 space-y-6">
          {/* OpenSSF Scorecard */}
          <section>
            <div className="flex items-center gap-2 mb-3">
              <FileCheck className="h-4 w-4 text-foreground-secondary" />
              <h3 className="text-sm font-medium text-foreground">OpenSSF Scorecard</h3>
            </div>
            {analysis?.status === 'pending' || analysis?.status === 'analyzing' ? (
              <p className="text-sm text-foreground-secondary">Analysis in progress.</p>
            ) : (
              <div className="rounded-lg border border-border bg-background-card px-4 py-3 space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-foreground-secondary">Score (0–10)</span>
                  <span className="font-mono text-foreground tabular-nums">
                    {openssfScore != null ? openssfScore.toFixed(1) : '—'}
                  </span>
                </div>
              </div>
            )}
          </section>

          {/* Popularity */}
          <section>
            <div className="flex items-center gap-2 mb-3">
              <TrendingUp className="h-4 w-4 text-foreground-secondary" />
              <h3 className="text-sm font-medium text-foreground">Popularity</h3>
            </div>
            {analysis?.status === 'pending' || analysis?.status === 'analyzing' ? (
              <p className="text-sm text-foreground-secondary">Analysis in progress.</p>
            ) : (
              <div className="rounded-lg border border-border bg-background-card px-4 py-3 space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-foreground-secondary">Weekly downloads (npm)</span>
                  <span className="font-mono text-foreground tabular-nums">
                    {weeklyDownloads != null
                      ? weeklyDownloads >= 1_000_000
                        ? `${(weeklyDownloads / 1_000_000).toFixed(1)}M`
                        : weeklyDownloads >= 1_000
                          ? `${(weeklyDownloads / 1_000).toFixed(1)}k`
                          : weeklyDownloads.toLocaleString()
                      : '—'}
                  </span>
                </div>
              </div>
            )}
          </section>

          {/* Maintenance */}
          <section>
            <div className="flex items-center gap-2 mb-3">
              <Calendar className="h-4 w-4 text-foreground-secondary" />
              <h3 className="text-sm font-medium text-foreground">Maintenance</h3>
            </div>
            {analysis?.status === 'pending' || analysis?.status === 'analyzing' ? (
              <p className="text-sm text-foreground-secondary">Analysis in progress.</p>
            ) : (
              <div className="rounded-lg border border-border bg-background-card px-4 py-3 space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-foreground-secondary">Releases in last 12 months</span>
                  <span className="font-mono text-foreground tabular-nums">
                    {releasesLast12Months != null ? releasesLast12Months : '—'}
                  </span>
                </div>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
