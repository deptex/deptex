import { memo, useState, useCallback, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Filter, X, Flame, Shield, CheckCircle } from 'lucide-react';
import { cn } from '../../lib/utils';

export interface SecurityFilters {
  severity: string[];
  depscoreMin: number | null;
  epssMin: number | null;
  kevOnly: boolean;
  fixAvailable: boolean;
  reachableOnly: boolean;
  depType: 'all' | 'direct' | 'transitive';
}

const DEFAULT_FILTERS: SecurityFilters = {
  severity: [],
  depscoreMin: null,
  epssMin: null,
  kevOnly: false,
  fixAvailable: false,
  reachableOnly: false,
  depType: 'all',
};

interface SecurityFilterBarProps {
  filters: SecurityFilters;
  onFiltersChange: (filters: SecurityFilters) => void;
}

function SecurityFilterBar({ filters, onFiltersChange }: SecurityFilterBarProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const severity = searchParams.get('severity')?.split(',').filter(Boolean) ?? [];
    const depscoreMin = searchParams.get('depscore_min') ? Number(searchParams.get('depscore_min')) : null;
    const epssMin = searchParams.get('epss_min') ? Number(searchParams.get('epss_min')) : null;
    const kevOnly = searchParams.get('kev') === 'true';
    const fixAvailable = searchParams.get('fix') === 'true';
    const reachableOnly = searchParams.get('reachable') === 'true';
    const depType = (searchParams.get('dep_type') as SecurityFilters['depType']) || 'all';

    onFiltersChange({ severity, depscoreMin, epssMin, kevOnly, fixAvailable, reachableOnly, depType });
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
    if (newFilters.depType !== 'all') params.set('dep_type', newFilters.depType);
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
    filters.depType !== 'all',
  ].filter(Boolean).length;

  const toggleSeverity = (sev: string) => {
    const newSev = filters.severity.includes(sev)
      ? filters.severity.filter(s => s !== sev)
      : [...filters.severity, sev];
    updateFilters({ ...filters, severity: newSev });
  };

  return (
    <div className="relative">
      <div className="flex items-center gap-2">
        <button
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

      {/* Dropdown panel */}
      {isOpen && (
        <div className="absolute top-full left-0 mt-2 w-80 bg-background-card border border-border rounded-xl shadow-2xl z-40 p-4 space-y-4">
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
        </div>
      )}
    </div>
  );
}

export { DEFAULT_FILTERS };
export default memo(SecurityFilterBar);
