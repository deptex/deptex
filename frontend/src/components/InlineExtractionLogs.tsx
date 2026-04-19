import { useState, useEffect, useRef, useCallback } from 'react';
import { Check, Copy } from 'lucide-react';
import { cn } from '../lib/utils';
import { useToast } from '../hooks/use-toast';
import {
  useExtractionLogs,
  formatTimestamp,
  formatDuration,
  levelColor,
} from '../hooks/useExtractionLogs';

export interface InlineExtractionLogsProps {
  organizationId: string;
  projectId: string;
  runId?: string | null;
  /** Tailwind max-height class for the scrollable log area. Defaults to 'max-h-80'. */
  maxHeightClass?: string;
  /** Whether to show Cancel button when extraction is active. Defaults to false. */
  showCancelButton?: boolean;
  onCancelled?: () => void;
}

export function InlineExtractionLogs({
  organizationId,
  projectId,
  runId,
  maxHeightClass = 'max-h-80',
}: InlineExtractionLogsProps) {
  const { filteredLogs, isLoading, isComplete, hasError } = useExtractionLogs({
    projectId,
    organizationId,
    runId,
  });

  const [copied, setCopied] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const { toast } = useToast();

  // Auto-scroll to bottom only when new logs arrive
  const prevLogCount = useRef(filteredLogs.length);
  useEffect(() => {
    if (filteredLogs.length > prevLogCount.current && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
    prevLogCount.current = filteredLogs.length;
  }, [filteredLogs.length]);

  const logText = filteredLogs
    .map((l) => `${formatTimestamp(l.created_at)}  [${l.level}] ${l.message}`)
    .join('\n');

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(logText);
    setCopied(true);
    toast({ title: 'Logs copied to clipboard' });
    setTimeout(() => setCopied(false), 2000);
  }, [logText, toast]);

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950 overflow-hidden">
      {/* Header bar */}
      <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-zinc-800">
        <div className="flex items-center gap-3 text-xs shrink-0">
          {/* Copy button — skeleton while loading */}
          {isLoading ? (
            <span className="h-6 w-6 rounded bg-zinc-800/60 animate-pulse shrink-0" />
          ) : (
            filteredLogs.length > 0 && (
              <button
                type="button"
                onClick={handleCopy}
                className="h-6 w-6 rounded flex items-center justify-center text-zinc-100 hover:text-white hover:bg-zinc-800 transition-colors"
                aria-label={copied ? 'Copied' : 'Copy logs'}
              >
                {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              </button>
            )
          )}

          {/* Line count — skeleton while loading */}
          {isLoading ? (
            <span className="h-3.5 w-12 bg-zinc-800/60 rounded animate-pulse" />
          ) : (
            <span className="text-zinc-400 tabular-nums">{filteredLogs.length} lines</span>
          )}

          {isComplete && !hasError && (
            <span className="text-emerald-400 flex items-center gap-1">
              <Check className="h-3 w-3" />
              Complete
            </span>
          )}
          {isComplete && hasError && (
            <span className="text-red-400 flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-red-400 shrink-0" />
              Failed
            </span>
          )}
        </div>

      </div>

      {/* Log stream */}
      <div
        ref={scrollRef}
        className={cn(
          'overflow-y-auto p-4 font-mono text-[13px] leading-6 custom-scrollbar',
          maxHeightClass
        )}
      >
        {isLoading ? (
          <div className="space-y-1">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="flex items-center gap-4 h-6">
                <span className="h-3.5 w-[5.5rem] bg-zinc-800/60 rounded animate-pulse shrink-0" />
                <span
                  className="h-3.5 bg-zinc-800/60 rounded animate-pulse"
                  style={{ width: `${45 + (i % 3) * 18}%` }}
                />
              </div>
            ))}
          </div>
        ) : filteredLogs.length === 0 ? (
          <p className="text-zinc-400 text-[13px] font-mono">No log output.</p>
        ) : (
          filteredLogs.map((line) => (
            <div key={line.id} className="flex items-start gap-4 px-1 -mx-1">
              <span className="text-zinc-400 shrink-0 tabular-nums select-none w-[5.5rem]">
                {formatTimestamp(line.created_at)}
              </span>
              <span className={cn('break-all min-w-0 flex-1', levelColor(line.level))}>
                {line.message}
              </span>
              {line.duration_ms != null && (
                <span className="text-zinc-400 shrink-0 tabular-nums text-[12px]">
                  {formatDuration(line.duration_ms)}
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
