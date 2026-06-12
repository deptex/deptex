import { useEffect, useState } from 'react';
import {
  Loader2,
  Activity,
  Globe,
  Code2,
  Cpu,
  HardDrive,
  Lock,
  FileWarning,
  Wrench,
  Search,
  Wifi,
  Bell,
  KeyRound,
  Plug,
  Eye,
  Clipboard,
} from 'lucide-react';
import { api, type CapabilityKey, type PackageCapabilities } from '../lib/api';
import { cn } from '../lib/utils';

interface CapabilitiesSectionProps {
  organizationId: string;
  ecosystem: string | null | undefined;
  packageName: string;
  version: string;
}

type Signal = 'high' | 'mid' | 'low';

interface CapabilityMeta {
  label: string;
  Icon: typeof Activity;
  signal: Signal;
}

// Order chosen so the higher-signal capabilities surface first when many
// flags are true. Locked at 15 tags for v2.
const CAPABILITY_META: Record<CapabilityKey, CapabilityMeta> = {
  eval_dynamic: { label: 'Dynamic eval', Icon: Code2, signal: 'high' },
  network_io: { label: 'Network I/O', Icon: Globe, signal: 'high' },
  spawns_processes: { label: 'Spawns processes', Icon: Activity, signal: 'high' },
  native_addon_load: { label: 'Native addon load', Icon: Cpu, signal: 'high' },
  filesystem_write: { label: 'Filesystem write', Icon: HardDrive, signal: 'mid' },
  crypto_operations: { label: 'Crypto operations', Icon: Lock, signal: 'mid' },
  serialization_deser: { label: 'Unsafe deserialization', Icon: FileWarning, signal: 'mid' },
  install_script: { label: 'Install script', Icon: Wrench, signal: 'mid' },
  dns_query: { label: 'DNS query', Icon: Search, signal: 'mid' },
  websocket: { label: 'WebSocket', Icon: Wifi, signal: 'mid' },
  process_signal: { label: 'Process signal', Icon: Bell, signal: 'mid' },
  encrypted_payload: { label: 'Encrypted payload', Icon: KeyRound, signal: 'mid' },
  dynamic_import: { label: 'Dynamic import', Icon: Plug, signal: 'mid' },
  reads_env: { label: 'Reads environment', Icon: Eye, signal: 'low' },
  clipboard_access: { label: 'Clipboard access', Icon: Clipboard, signal: 'low' },
};

const TONE_BY_SIGNAL: Record<Signal, string> = {
  high: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  mid: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  low: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20',
};

/** Resolved capability-fetch result — lets callers load capabilities alongside their own data. */
export type CapabilitiesState =
  | { kind: 'loaded'; data: PackageCapabilities }
  | { kind: 'missing' }
  | { kind: 'error'; message: string };

/**
 * Fetch + classify the capability scan for a package version. Never throws:
 * 404 (not yet scanned) → 'missing', anything else → 'error'.
 */
export async function fetchCapabilitiesState(
  organizationId: string,
  ecosystem: string | null | undefined,
  packageName: string,
  version: string,
): Promise<CapabilitiesState> {
  if (!ecosystem) return { kind: 'missing' };
  try {
    const data = await api.capabilities.fetch(organizationId, ecosystem, packageName, version);
    return { kind: 'loaded', data };
  } catch (err: any) {
    const msg = String(err?.message ?? '');
    // The route returns 404 when the package hasn't been scanned yet.
    if (msg.includes('404') || /not available|not found/i.test(msg)) {
      return { kind: 'missing' };
    }
    return { kind: 'error', message: msg || 'Capability scan unavailable' };
  }
}

/**
 * Presentational chips for a pre-fetched state (overview panel loads this with the rest of its data).
 * `compact` renders chips only — pending/unavailable/empty states collapse to nothing, for inline
 * placement in tight rows (e.g. the package meta/stats row).
 */
export function CapabilitiesChips({ state, compact }: { state: CapabilitiesState; compact?: boolean }) {
  if (state.kind === 'missing') {
    return compact ? null : <div className="text-xs text-foreground-muted">Capability scan pending</div>;
  }
  if (state.kind === 'error') {
    return compact ? null : <div className="text-xs text-foreground-muted">Capability scan unavailable</div>;
  }
  if (compact) {
    const d = state.data;
    const any = !d.scan_error && (Object.keys(CAPABILITY_META) as CapabilityKey[]).some((k) => d.capabilities[k]);
    if (!any) return null;
  }
  return <CapabilityTagCloud data={state.data} />;
}

/** Self-fetching wrapper — used where capabilities load standalone (e.g. MaliciousPackageDrawer). */
export function CapabilitiesSection({
  organizationId,
  ecosystem,
  packageName,
  version,
}: CapabilitiesSectionProps) {
  const [state, setState] = useState<{ kind: 'loading' } | CapabilitiesState>({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    setState({ kind: 'loading' });
    fetchCapabilitiesState(organizationId, ecosystem, packageName, version).then((s) => {
      if (!cancelled) setState(s);
    });
    return () => {
      cancelled = true;
    };
  }, [organizationId, ecosystem, packageName, version]);

  if (state.kind === 'loading') {
    return (
      <div className="text-xs text-foreground-secondary inline-flex items-center gap-1.5">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        Loading capability scan...
      </div>
    );
  }
  return <CapabilitiesChips state={state} />;
}

function CapabilityTagCloud({ data }: { data: PackageCapabilities }) {
  const flags = data.capabilities;
  const enabled: CapabilityKey[] = (Object.keys(CAPABILITY_META) as CapabilityKey[]).filter(
    (k) => flags[k],
  );

  if (data.scan_error) {
    return (
      <div className="text-xs text-foreground-muted" title={data.scan_error}>
        Capability scan unavailable
      </div>
    );
  }

  if (enabled.length === 0) {
    return <div className="text-xs text-foreground-muted">No notable capabilities detected</div>;
  }

  return (
    <div className="flex flex-wrap gap-1.5">
      {enabled.map((k) => {
        const meta = CAPABILITY_META[k];
        const tone = TONE_BY_SIGNAL[meta.signal];
        const Icon = meta.Icon;
        return (
          <span
            key={k}
            className={cn(
              'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border',
              tone,
            )}
          >
            <Icon className="h-3 w-3 mr-1" />
            {meta.label}
          </span>
        );
      })}
    </div>
  );
}
