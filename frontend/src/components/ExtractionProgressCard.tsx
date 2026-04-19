import { useState, useEffect } from 'react';
import { AlertCircle, Loader2, RotateCw } from 'lucide-react';
import { cn } from '../lib/utils';
import { InlineExtractionLogs } from './InlineExtractionLogs';

export interface ExtractionProgressCardProps {
  title?: string;
  description?: string;
  showLogsToggle?: boolean;
  organizationId?: string;
  projectId?: string;
  onCancelled?: () => void;
  className?: string;
  /** When true, show an error state (red icon, failed messaging) instead of the in-progress spinner. */
  isError?: boolean;
  /** When provided and isError=true, shows a Retry button that calls this function. */
  onRetry?: () => Promise<void> | void;
}

export function ExtractionProgressCard({
  title,
  description,
  showLogsToggle = false,
  organizationId,
  projectId,
  onCancelled,
  className,
  isError = false,
  onRetry,
}: ExtractionProgressCardProps) {
  const defaultTitle = isError ? 'Extraction failed' : 'Project extraction still in progress';
  const defaultDescription = isError ? 'An error occurred during extraction.' : 'Content will appear here once extraction completes.';
  const resolvedTitle = title ?? defaultTitle;
  const resolvedDescription = description ?? defaultDescription;
  const canShowLogs = showLogsToggle && organizationId && projectId;
  // Auto-expand logs on error so the user sees them without having to click
  const autoExpand = !!(isError && canShowLogs);
  const [logsExpanded, setLogsExpanded] = useState(autoExpand);
  const [mounted, setMounted] = useState(autoExpand);
  const [animateOpen, setAnimateOpen] = useState(autoExpand);
  const [isRetrying, setIsRetrying] = useState(false);
  // Increments on each retry to remount InlineExtractionLogs and fetch fresh logs
  const [logKey, setLogKey] = useState(0);

  useEffect(() => {
    if (logsExpanded) {
      setMounted(true);
      requestAnimationFrame(() => {
        requestAnimationFrame(() => setAnimateOpen(true));
      });
    } else {
      setAnimateOpen(false);
    }
  }, [logsExpanded]);

  const handleTransitionEnd = () => {
    if (!logsExpanded) {
      setMounted(false);
    }
  };

  return (
    <div className={cn('rounded-lg border bg-background-card', isError ? 'border-destructive/30' : 'border-border', className)}>
      <div className="flex items-center gap-4 p-6">
        <div className="flex-1 space-y-1 min-w-0">
          <h3 className="text-sm font-semibold text-foreground">{resolvedTitle}</h3>
          <p className="text-sm text-foreground-secondary">
            {resolvedDescription}
            {canShowLogs && (
              <>
                {' '}
                <button
                  type="button"
                  onClick={() => setLogsExpanded((v) => !v)}
                  className="text-foreground-secondary underline decoration-foreground-secondary/40 underline-offset-2 hover:text-foreground hover:decoration-foreground/40 transition-colors"
                >
                  {logsExpanded ? 'Click to close logs' : 'Click to view logs'}
                </button>
              </>
            )}
          </p>
        </div>

        {isError && onRetry ? (
          <button
            type="button"
            disabled={isRetrying}
            onClick={async () => {
              setIsRetrying(true);
              try {
                await onRetry();
                setLogKey((k) => k + 1);
              } finally {
                setIsRetrying(false);
              }
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border border-destructive/40 bg-destructive/10 text-destructive hover:bg-destructive/20 transition-colors flex-shrink-0 disabled:opacity-60 disabled:pointer-events-none"
          >
            {isRetrying
              ? <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
              : <RotateCw className="h-3 w-3" aria-hidden />
            }
            Retry
          </button>
        ) : (
          <div className={cn('flex h-8 w-8 shrink-0 items-center justify-center rounded-full border', isError ? 'border-destructive/40 bg-destructive/10' : 'border-border bg-background-subtle')}>
            {isError
              ? <AlertCircle className="h-4 w-4 text-destructive" aria-hidden />
              : <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" aria-hidden />
            }
          </div>
        )}
      </div>

      {canShowLogs && mounted && !isRetrying && (
        <div
          className="grid transition-[grid-template-rows] duration-300 ease-out"
          style={{ gridTemplateRows: animateOpen ? '1fr' : '0fr' }}
          onTransitionEnd={handleTransitionEnd}
        >
          <div className="overflow-hidden">
            <div className="px-6 pb-6">
              <InlineExtractionLogs
                key={logKey}
                organizationId={organizationId}
                projectId={projectId}
                showCancelButton={false}
                onCancelled={onCancelled}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
