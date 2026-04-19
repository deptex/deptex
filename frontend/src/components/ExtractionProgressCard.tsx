import { useState, useEffect } from 'react';
import { Loader2 } from 'lucide-react';
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
}

export function ExtractionProgressCard({
  title = 'Project extraction still in progress',
  description = 'Content will appear here once extraction completes.',
  showLogsToggle = false,
  organizationId,
  projectId,
  onCancelled,
  className,
}: ExtractionProgressCardProps) {
  const [logsExpanded, setLogsExpanded] = useState(false);
  const [mounted, setMounted] = useState(false);
  const canShowLogs = showLogsToggle && organizationId && projectId;

  const [animateOpen, setAnimateOpen] = useState(false);

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
    <div className={cn('rounded-lg border border-border bg-background-card', className)}>
      <div className="flex items-center gap-4 p-6">
        <div className="flex-1 space-y-1 min-w-0">
          <h3 className="text-sm font-semibold text-foreground">{title}</h3>
          <p className="text-sm text-foreground-secondary">
            {description}
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

        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border bg-background-subtle">
          <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" aria-hidden />
        </div>
      </div>

      {canShowLogs && mounted && (
        <div
          className="grid transition-[grid-template-rows] duration-300 ease-out"
          style={{ gridTemplateRows: animateOpen ? '1fr' : '0fr' }}
          onTransitionEnd={handleTransitionEnd}
        >
          <div className="overflow-hidden">
            <div className="px-6 pb-6">
              <InlineExtractionLogs
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
