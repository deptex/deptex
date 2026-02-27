import { useState, useEffect, useCallback } from 'react';
import { Check, X, Copy, Download } from 'lucide-react';
import { cn } from '../lib/utils';
import { Button } from './ui/button';
import { useToast } from '../hooks/use-toast';

export interface SyncLogEntry {
  id: number;
  shortId: string;
  commit: string;
  commitMessage?: string;
  time: string;
  duration: string;
  status: 'success' | 'error';
  trigger: string;
}

interface SyncDetailSidebarProps {
  entry: SyncLogEntry;
  onClose: () => void;
}

const LOG_LINES = [
  { time: '10:42:00', msg: 'Initializing Deptex sync engine v2.4.0...', type: 'info' },
  { time: '10:42:01', msg: 'Loading configuration from .deptex.json', type: 'info' },
  { time: '10:42:01', msg: 'Authenticating with Github App... OK', type: 'success' },
  { time: '10:42:02', msg: 'Scanning repository file structure...', type: 'info' },
  { time: '10:42:02', msg: 'Found package manifest: package.json', type: 'info' },
  { time: '10:42:03', msg: 'Parsing dependencies...', type: 'info' },
  { time: '10:42:03', msg: 'Analyzed 42 files in 840ms', type: 'highlight' },
  { time: '10:42:03', msg: 'WARN: Peer dependency conflict found in react-dom@18.2.0', type: 'warn' },
  { time: '10:42:04', msg: 'Generating report...', type: 'info' },
  { time: '10:42:04', msg: 'Resolution successful. No critical vulnerabilities detected.', type: 'success' },
  { time: '10:42:04', msg: 'Sync completed. Payload size: 12KB.', type: 'info' },
];

const LOG_TEXT = LOG_LINES.map((l) => `${l.time}  ${l.msg}`).join('\n');

export function SyncDetailSidebar({ entry, onClose }: SyncDetailSidebarProps) {
  const [panelVisible, setPanelVisible] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    setPanelVisible(false);
    const raf = requestAnimationFrame(() => {
      requestAnimationFrame(() => setPanelVisible(true));
    });
    return () => cancelAnimationFrame(raf);
  }, []);

  const handleClose = useCallback(() => {
    setPanelVisible(false);
    setTimeout(onClose, 150);
  }, [onClose]);

  const handleCopyLogs = useCallback(() => {
    navigator.clipboard.writeText(LOG_TEXT);
    toast({ title: 'Logs copied to clipboard' });
  }, [toast]);

  const handleDownloadLogs = useCallback(() => {
    const blob = new Blob([LOG_TEXT], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sync-${entry.id}-${entry.commit}.log`;
    a.click();
    URL.revokeObjectURL(url);
    toast({ title: 'Logs downloaded' });
  }, [entry.id, entry.commit, toast]);

  const isSuccess = entry.status === 'success';

  return (
    <div className="fixed inset-0 z-50">
      <div
        className={cn(
          'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
          panelVisible ? 'opacity-100' : 'opacity-0'
        )}
        onClick={handleClose}
      />

      <div
        className={cn(
          'fixed right-4 top-4 bottom-4 w-full max-w-[560px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
          panelVisible ? 'translate-x-0' : 'translate-x-full'
        )}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header – commit as title, no X */}
        <div className="px-6 pt-5 pb-4 flex-shrink-0">
          <h2 className="text-xl font-semibold text-foreground font-mono">{entry.commit}</h2>
          <p className={cn(
            'text-sm mt-1 flex items-center gap-2',
            isSuccess ? 'text-success' : 'text-destructive'
          )}>
            {isSuccess ? (
              <>
                <Check className="h-4 w-4 shrink-0" />
                Completed successfully
              </>
            ) : (
              <>
                <X className="h-4 w-4 shrink-0" />
                Failed
              </>
            )}
          </p>
        </div>

        {/* Metrics – one row, no cards */}
        <div className="px-6 pb-4 flex-shrink-0">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
            <span>
              <span className="text-foreground-secondary">Triggered by</span>
              <span className="ml-2 text-foreground font-medium">{entry.trigger}</span>
            </span>
            <span>
              <span className="text-foreground-secondary">Duration</span>
              <span className="ml-2 text-foreground font-medium">{entry.duration}</span>
            </span>
            <span>
              <span className="text-foreground-secondary">Vulnerabilities</span>
              <span className="ml-2 text-foreground font-medium">0</span>
            </span>
          </div>
        </div>

        {/* System logs – no card, cleaner styling */}
        <div className="flex-1 flex flex-col min-h-0 px-6 pb-6">
          <div className="flex items-center justify-between gap-4 mb-3 flex-shrink-0">
            <h3 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">System Logs</h3>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-8 text-xs"
                onClick={handleDownloadLogs}
              >
                <Download className="h-3.5 w-3.5 mr-1.5" />
                Download
              </Button>
              <button
                type="button"
                onClick={handleCopyLogs}
                className="h-8 w-8 rounded-md flex items-center justify-center text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors"
                aria-label="Copy logs"
              >
                <Copy className="h-4 w-4" />
              </button>
            </div>
          </div>
          <div className="flex-1 min-h-0 overflow-auto custom-scrollbar">
            <div className="font-mono text-xs leading-relaxed">
              {LOG_LINES.map((line, i) => (
                <div key={i} className="flex gap-4 py-0.5">
                  <span className="text-foreground-muted shrink-0 tabular-nums">{line.time}</span>
                  <span className={cn(
                    'break-all',
                    line.type === 'success' && 'text-success',
                    line.type === 'warn' && 'text-warning',
                    line.type === 'highlight' && 'text-primary',
                    line.type === 'info' && 'text-foreground-secondary'
                  )}>
                    {line.msg}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-4 mt-3 text-xs text-foreground-muted flex-shrink-0">
            <span>Worker ID: us-east-1-worker-002a</span>
            <span>API Version: v2.4.0-alpha</span>
          </div>
        </div>
      </div>
    </div>
  );
}
