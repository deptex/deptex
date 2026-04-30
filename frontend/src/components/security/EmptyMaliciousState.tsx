import { ShieldCheck } from 'lucide-react';

interface EmptyMaliciousStateProps {
  scannerVersion?: string | null;
  lastScanAt?: string | null;
}

export function EmptyMaliciousState({ scannerVersion, lastScanAt }: EmptyMaliciousStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <div className="rounded-full bg-emerald-500/10 border border-emerald-500/20 p-3 mb-3">
        <ShieldCheck className="h-6 w-6 text-emerald-400" />
      </div>
      <div className="text-sm font-semibold text-foreground">No malicious packages detected</div>
      <div className="text-xs text-foreground-secondary mt-1">
        Scanned across 2 feeds (OSV.dev + GHSA){scannerVersion ? ` + ${scannerVersion}` : ''}
      </div>
      {lastScanAt && (
        <div className="text-[11px] text-foreground-muted mt-1">
          Last scanned {new Date(lastScanAt).toLocaleString()}
        </div>
      )}
    </div>
  );
}
