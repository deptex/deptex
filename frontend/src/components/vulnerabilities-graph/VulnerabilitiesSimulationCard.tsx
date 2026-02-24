import { memo } from 'react';
import { RotateCcw, GitPullRequest, Loader2, Zap } from 'lucide-react';
import { cn } from '../../lib/utils';

export type SimulationChangeItem =
  | { type: 'bump'; name: string; fromVersion: string; toVersion: string; projectDependencyId: string }
  | { type: 'removed'; name: string; projectDependencyId: string };

interface VulnerabilitiesSimulationCardProps {
  changeList: SimulationChangeItem[];
  /** Reset a single package to its original version (or restore a removed zombie) in the graph. */
  onResetItem: (projectDependencyId: string) => void;
  onCreatePr: () => void | Promise<void>;
  createPrLoading: boolean;
  organizationId: string;
  projectId: string;
  /** When list is empty, show "Preview fix" instead of Create PRs. */
  onPreviewFix?: () => void;
  canPreviewFix?: boolean;
  previewFixLoading?: boolean;
}

const transparentButtonClass =
  'flex items-center justify-center gap-1.5 rounded-lg border border-border bg-background-subtle hover:bg-table-hover hover:border-primary/40 px-3 py-2 text-xs font-medium text-foreground transition-colors disabled:opacity-60 disabled:cursor-not-allowed';

function VulnerabilitiesSimulationCardComponent({
  changeList,
  onResetItem,
  onCreatePr,
  createPrLoading,
  onPreviewFix,
  canPreviewFix = false,
  previewFixLoading = false,
}: VulnerabilitiesSimulationCardProps) {
  const bumpCount = changeList.filter((c) => c.type === 'bump').length;
  const removedCount = changeList.filter((c) => c.type === 'removed').length;
  const canCreatePr = bumpCount > 0 || removedCount > 0;
  const isEmpty = changeList.length === 0;

  return (
    <div className="absolute top-3 right-3 z-30 w-[280px] rounded-lg border border-border bg-background-card/95 backdrop-blur-sm shadow-md overflow-hidden pointer-events-auto">
      <div className="px-3.5 pt-3 pb-2">
        <p className="text-xs font-semibold text-foreground uppercase tracking-wider">Simulating</p>
      </div>
      <div className="max-h-[200px] overflow-y-auto custom-scrollbar">
        <ul className="px-3.5 pt-1 py-2 space-y-1.5">
          {isEmpty ? (
            <li className="text-xs text-foreground-muted py-2">
              Not simulating any changes
            </li>
          ) : changeList.map((item) => (
            <li
              key={item.projectDependencyId}
              className="flex items-center justify-between gap-2 text-xs text-foreground-secondary group"
            >
              <span>
                <span className="font-medium text-foreground">{item.name}</span>
                {item.type === 'bump' ? (
                  <span className="font-mono ml-1">
                    v{item.fromVersion} → v{item.toVersion}
                  </span>
                ) : (
                  <span className="ml-1 text-foreground-muted">removed</span>
                )}
              </span>
              <button
                type="button"
                onClick={() => onResetItem(item.projectDependencyId)}
                className="flex-shrink-0 p-1 rounded text-foreground-muted hover:text-foreground hover:bg-table-hover transition-colors cursor-pointer"
                title="Reset this package to current"
              >
                <RotateCcw className="h-3 w-3" />
              </button>
            </li>
          ))}
        </ul>
      </div>
      <div className="px-3.5 py-2.5 border-t border-border bg-[#141618]">
        {isEmpty ? (
          <button
            type="button"
            onClick={onPreviewFix}
            disabled={!canPreviewFix || previewFixLoading}
            className={cn('w-full', transparentButtonClass)}
          >
            {previewFixLoading ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin flex-shrink-0" />
            ) : (
              <Zap className="h-3.5 w-3.5 flex-shrink-0" />
            )}
            Preview fix
          </button>
        ) : (
          <button
            type="button"
            onClick={() => void onCreatePr()}
            disabled={createPrLoading || !canCreatePr}
            className={cn('w-full', transparentButtonClass)}
          >
            {createPrLoading ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <GitPullRequest className="h-3 w-3" />
            )}
            Create PR{bumpCount + removedCount !== 1 ? 's' : ''}
          </button>
        )}
      </div>
    </div>
  );
}

export const VulnerabilitiesSimulationCard = memo(VulnerabilitiesSimulationCardComponent);
