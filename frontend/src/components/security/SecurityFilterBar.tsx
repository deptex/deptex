import { memo, useState, useCallback, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useSearchParams } from 'react-router-dom';
import { Filter, X, Flame, Shield, CheckCircle } from 'lucide-react';
import { cn } from '../../lib/utils';

export type ReachabilityFilterLevel = 'all' | 'data_flow' | 'function' | 'module' | 'unreachable';

/** Phase 15: SLA status filter for vulnerability list/graph. */
export type SlaStatusFilter = 'all' | 'on_track' | 'warning' | 'breached' | 'exempt';

export interface SecurityFilters {
  severity: string[];
  depscoreMin: number | null;
  epssMin: number | null;
  kevOnly: boolean;
  fixAvailable: boolean;
  reachableOnly: boolean;
  reachabilityLevel: ReachabilityFilterLevel;
  depType: 'all' | 'direct' | 'transitive';
  /** Phase 15: Filter by SLA status. */
  slaStatus: SlaStatusFilter;
}

const DEFAULT_FILTERS: SecurityFilters = {
  severity: [],
  depscoreMin: null,
  epssMin: null,
  kevOnly: false,
  fixAvailable: false,
  reachableOnly: false,
  reachabilityLevel: 'all',
  depType: 'all',
  slaStatus: 'all',
};

interface SecurityFilterBarProps {
  filters: SecurityFilters;
  onFiltersChange: (filters: SecurityFilters) => void;
}

const DROPDOWN_WIDTH = 320;

function SecurityFilterBar({ filters, onFiltersChange }: SecurityFilterBarProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [isOpen, setIsOpen] = useState(false);
  const [dropdownPosition, setDropdownPosition] = useState<{ top: number; left: number } | null>(null);
  const filterButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const severity = searchParams.get('severity')?.split(',').filter(Boolean) ?? [];
    const depscoreMin = searchParams.get('depscore_min') ? Number(searchParams.get('depscore_min')) : null;
    const epssMin = searchParams.get('epss_min') ? Number(searchParams.get('epss_min')) : null;
    const kevOnly = searchParams.get('kev') === 'true';
    const fixAvailable = searchParams.get('fix') === 'true';
    const reachableOnly = searchParams.get('reachable') === 'true';
    const reachabilityLevel = (searchParams.get('reachability') as ReachabilityFilterLevel) || 'all';
    const depType = (searchParams.get('dep_type') as SecurityFilters['depType']) || 'all';
    const slaStatus = (searchParams.get('sla') as SlaStatusFilter) || 'all';

    onFiltersChange({ severity, depscoreMin, epssMin, kevOnly, fixAvailable, reachableOnly, reachabilityLevel, depType, slaStatus });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const updateFilters = useCallback((newFilters: SecurityFilters) => {
    onFiltersChange(newFilters);
    const params = new URLSearchParams();
    if (newFilters.severity.length > 0) params.set('severity', newFilters.severity.join(','));
    if (newFilters.depscoreMin != null) params.set('depscore_min', String(newFilters.depscoreMin));
    if (newFilters.epssMin != null) params.set('epss_min', String(newFilters.epssMin));
    if (newFilters.kevOnly) params.set('kev', 'true');
    if (newFilters.fixAvailable) params.set('fix', 'true');
    if (newFilters.reachableOnly) params.set('reachable', 'true');
    if (newFilters.reachabilityLevel !== 'all') params.set('reachability', newFilters.reachabilityLevel);
    if (newFilters.depType !== 'all') params.set('dep_type', newFilters.depType);
    if (newFilters.slaStatus !== 'all') params.set('sla', newFilters.slaStatus);
    setSearchParams(params, { replace: true });
  }, [onFiltersChange, setSearchParams]);

  const clearAll = useCallback(() => {
    updateFilters(DEFAULT_FILTERS);
    setIsOpen(false);
  }, [updateFilters]);

  const activeCount = [
    filters.severity.length > 0,
    filters.depscoreMin != null,
    filters.epssMin != null,
    filters.kevOnly,
    filters.fixAvailable,
    filters.reachableOnly,
    filters.reachabilityLevel !== 'all',
    filters.depType !== 'all',
    filters.slaStatus !== 'all',
  ].filter(Boolean).length;

  const toggleSeverity = (sev: string) => {
    const newSev = filters.severity.includes(sev)
      ? filters.severity.filter(s => s !== sev)
      : [...filters.severity, sev];
    updateFilters({ ...filters, severity: newSev });
  };

  useEffect(() => {
    if (!isOpen) {
      setDropdownPosition(null);
      return;
    }
    if (!filterButtonRef.current) return;
    const rect = filterButtonRef.current.getBoundingClientRect();
    setDropdownPosition({
      top: rect.bottom + 8,
      left: Math.max(8, rect.right - DROPDOWN_WIDTH),
    });
  }, [isOpen]);

  const dropdownContent = isOpen && dropdownPosition && (
    <div
      className="fixed w-80 bg-background-card border border-border rounded-xl shadow-2xl p-4 space-y-4"
      style={{
        top: dropdownPosition.top,
        left: dropdownPosition.left,
        zIndex: 9999,
      }}
    >
      {/* Severity */}
      <div>
        <div className="text-xs font-medium text-zinc-400 mb-2">Severity</div>
        <div className="flex gap-2 flex-wrap">
          {['critical', 'high', 'medium', 'low'].map(sev => (
            <button
              key={sev}
              onClick={() => toggleSeverity(sev)}
              className={cn(
                'px-2 py-1 rounded text-xs capitalize transition-colors border',
                filters.severity.includes(sev)
                  ? sev === 'critical' ? 'border-red-500/30 bg-red-500/10 text-red-400'
                    : sev === 'high' ? 'border-orange-500/30 bg-orange-500/10 text-orange-400'
                    : sev === 'medium' ? 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400'
                    : 'border-zinc-500/30 bg-zinc-500/10 text-zinc-400'
                  : 'border-border text-zinc-500 hover:text-zinc-400'
              )}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Depscore Range */}
      <div>
        <div className="text-xs font-medium text-zinc-400 mb-2">Minimum Depscore</div>
        <input
          type="number"
          min="0"
          max="100"
          placeholder="e.g. 40"
          value={filters.depscoreMin ?? ''}
          onChange={(e) => updateFilters({ ...filters, depscoreMin: e.target.value ? Number(e.target.value) : null })}
          className="w-full px-3 py-1.5 bg-background border border-border rounded-lg text-xs text-foreground focus:ring-1 focus:ring-primary focus:border-transparent"
        />
      </div>

      {/* EPSS Threshold */}
      <div>
        <div className="text-xs font-medium text-zinc-400 mb-2">Minimum EPSS (%)</div>
        <input
          type="number"
          min="0"
          max="100"
          step="0.1"
          placeholder="e.g. 1"
          value={filters.epssMin ?? ''}
          onChange={(e) => updateFilters({ ...filters, epssMin: e.target.value ? Number(e.target.value) : null })}
          className="w-full px-3 py-1.5 bg-background border border-border rounded-lg text-xs text-foreground focus:ring-1 focus:ring-primary focus:border-transparent"
        />
      </div>

      {/* Reachability Level (Phase 6B) */}
      <div>
        <div className="text-xs font-medium text-zinc-400 mb-2">Reachability Level</div>
        <div className="flex gap-2 flex-wrap">
          {([
            { value: 'all', label: 'All', color: 'primary' },
            { value: 'data_flow', label: 'Data flow', color: 'orange' },
            { value: 'function', label: 'Function', color: 'yellow' },
            { value: 'module', label: 'Module', color: 'zinc' },
            { value: 'unreachable', label: 'Unreachable', color: 'green' },
          ] as const).map(({ value, label, color }) => (
            <button
              key={value}
              onClick={() => updateFilters({ ...filters, reachabilityLevel: value })}
              className={cn(
                'px-2 py-1 rounded text-xs transition-colors border',
                filters.reachabilityLevel === value
                  ? color === 'orange' ? 'border-orange-500/30 bg-orange-500/10 text-orange-400'
                    : color === 'yellow' ? 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400'
                    : color === 'green' ? 'border-green-500/30 bg-green-500/10 text-green-400'
                    : color === 'zinc' ? 'border-zinc-500/30 bg-zinc-500/10 text-zinc-400'
                    : 'border-primary/30 bg-primary/10 text-primary'
                  : 'border-border text-zinc-500 hover:text-zinc-400'
              )}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Dependency Type */}
      <div>
        <div className="text-xs font-medium text-zinc-400 mb-2">Dependency Type</div>
        <div className="flex gap-2">
          {(['all', 'direct', 'transitive'] as const).map(type => (
            <button
              key={type}
              onClick={() => updateFilters({ ...filters, depType: type })}
              className={cn(
                'px-2 py-1 rounded text-xs capitalize transition-colors border',
                filters.depType === type
                  ? 'border-primary/30 bg-primary/10 text-primary'
                  : 'border-border text-zinc-500 hover:text-zinc-400'
              )}
            >
              {type}
            </button>
          ))}
        </div>
      </div>

      {/* Phase 15: SLA Status */}
      <div>
        <div className="text-xs font-medium text-zinc-400 mb-2">SLA Status</div>
        <div className="flex gap-2 flex-wrap">
          {([
            { value: 'all' as const, label: 'All' },
            { value: 'on_track' as const, label: 'On track' },
            { value: 'warning' as const, label: 'Warning' },
            { value: 'breached' as const, label: 'Breached' },
            { value: 'exempt' as const, label: 'Exempt' },
          ]).map(({ value, label }) => (
            <button
              key={value}
              onClick={() => updateFilters({ ...filters, slaStatus: value })}
              className={cn(
                'px-2 py-1 rounded text-xs transition-colors border',
                filters.slaStatus === value
                  ? value === 'breached' ? 'border-red-500/30 bg-red-500/10 text-red-400'
                    : value === 'warning' ? 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                    : 'border-primary/30 bg-primary/10 text-primary'
                  : 'border-border text-zinc-500 hover:text-zinc-400'
              )}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );

  return (
    <div className="relative">
      <div className="flex items-center gap-2">
        <button
          ref={filterButtonRef}
          onClick={() => setIsOpen(!isOpen)}
          className={cn(
            'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border',
            activeCount > 0
              ? 'border-primary/30 bg-primary/10 text-primary'
              : 'border-border bg-background-card text-zinc-400 hover:text-zinc-300'
          )}
        >
          <Filter className="h-3 w-3" />
          Filters
          {activeCount > 0 && (
            <span className="ml-1 px-1.5 py-0.5 rounded-full text-[10px] bg-primary/20 text-primary">{activeCount}</span>
          )}
        </button>

        {/* Quick toggle pills */}
        <button
          onClick={() => updateFilters({ ...filters, reachableOnly: !filters.reachableOnly })}
          className={cn(
            'px-2 py-1 rounded-md text-[11px] transition-colors border',
            filters.reachableOnly
              ? 'border-primary/30 bg-primary/10 text-primary'
              : 'border-border bg-transparent text-zinc-500 hover:text-zinc-400'
          )}
        >
          <Shield className="h-3 w-3 inline mr-1" />Reachable
        </button>
        <button
          onClick={() => updateFilters({ ...filters, kevOnly: !filters.kevOnly })}
          className={cn(
            'px-2 py-1 rounded-md text-[11px] transition-colors border',
            filters.kevOnly
              ? 'border-red-500/30 bg-red-500/10 text-red-400'
              : 'border-border bg-transparent text-zinc-500 hover:text-zinc-400'
          )}
        >
          <Flame className="h-3 w-3 inline mr-1" />KEV
        </button>
        <button
          onClick={() => updateFilters({ ...filters, fixAvailable: !filters.fixAvailable })}
          className={cn(
            'px-2 py-1 rounded-md text-[11px] transition-colors border',
            filters.fixAvailable
              ? 'border-green-500/30 bg-green-500/10 text-green-400'
              : 'border-border bg-transparent text-zinc-500 hover:text-zinc-400'
          )}
        >
          <CheckCircle className="h-3 w-3 inline mr-1" />Fix Available
        </button>

        {activeCount > 0 && (
          <button onClick={clearAll} className="text-xs text-zinc-500 hover:text-zinc-300 flex items-center gap-0.5">
            <X className="h-3 w-3" /> Clear all
          </button>
        )}
      </div>

      {typeof document !== 'undefined' && dropdownContent && createPortal(dropdownContent, document.body)}
    </div>
  );
}

export { DEFAULT_FILTERS };
export default memo(SecurityFilterBar);
