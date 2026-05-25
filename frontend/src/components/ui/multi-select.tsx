import * as React from 'react';
import { Check, ChevronDown, Search } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from './popover';
import { cn } from '../../lib/utils';

export interface MultiSelectOption {
  value: string;
  label: string;
  icon?: React.ReactNode;
}

export interface MultiSelectProps {
  options: MultiSelectOption[];
  selected: string[];
  onChange: (values: string[]) => void;
  renderLabel: (count: number, total: number) => string;
  triggerClassName?: string;
  contentClassName?: string;
  align?: 'start' | 'center' | 'end';
  disabled?: boolean;
  searchable?: boolean;
  searchPlaceholder?: string;
}

export function MultiSelect({
  options,
  selected,
  onChange,
  renderLabel,
  triggerClassName,
  contentClassName,
  align = 'start',
  disabled = false,
  searchable = false,
  searchPlaceholder = 'Search…',
}: MultiSelectProps) {
  const total = options.length;
  const allSelected = total > 0 && selected.length === total;
  const label = renderLabel(selected.length, total);

  const [query, setQuery] = React.useState('');
  const filteredOptions = React.useMemo(() => {
    if (!searchable || query.trim() === '') return options;
    const q = query.trim().toLowerCase();
    return options.filter((o) => o.label.toLowerCase().includes(q));
  }, [options, searchable, query]);

  const toggle = (value: string) => {
    if (selected.includes(value)) {
      onChange(selected.filter((v) => v !== value));
    } else {
      onChange([...selected, value]);
    }
  };

  const toggleAll = () => {
    if (allSelected) onChange([]);
    else onChange(options.map((o) => o.value));
  };

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          disabled={disabled}
          className={cn(
            'flex h-9 items-center justify-between gap-2 rounded-md border border-border bg-background-card px-3 text-sm text-foreground',
            'hover:bg-background-subtle transition-colors',
            'focus:outline-none focus:ring-1 focus:ring-ring',
            'disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:bg-background-card',
            triggerClassName,
          )}
        >
          <span className="truncate text-left">{label}</span>
          <ChevronDown className="h-4 w-4 shrink-0 text-foreground-secondary" />
        </button>
      </PopoverTrigger>
      <PopoverContent
        className={cn('w-[240px] p-0', contentClassName)}
        align={align}
        onOpenAutoFocus={(e) => {
          if (!searchable) return;
          // Let the search input grab focus on open.
        }}
      >
        {searchable && (
          <div className="flex items-center border-b border-border px-3 py-2">
            <Search className="h-3.5 w-3.5 shrink-0 text-foreground-secondary" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={searchPlaceholder}
              autoFocus
              className={cn(
                'flex-1 border-0 bg-transparent text-sm text-foreground placeholder:text-foreground-secondary',
                'outline-none ring-0 focus:outline-none focus:ring-0 focus-visible:outline-none focus-visible:ring-0',
              )}
            />
          </div>
        )}
        <button
          type="button"
          onClick={toggleAll}
          className={cn(
            'flex w-full items-center justify-between border-b border-border px-3 py-2 text-sm font-medium text-foreground',
            'hover:bg-background-subtle transition-colors',
          )}
        >
          <span>Select all</span>
          <CheckboxIndicator checked={allSelected} />
        </button>
        <div className="max-h-[280px] overflow-y-auto py-1">
          {filteredOptions.length === 0 ? (
            <div className="px-3 py-2 text-sm text-foreground-secondary">No matches</div>
          ) : (
            filteredOptions.map((opt) => {
              const isSelected = selected.includes(opt.value);
              return (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => toggle(opt.value)}
                  className={cn(
                    'flex w-full items-center gap-2.5 px-3 py-1.5 text-left text-sm text-foreground',
                    'hover:bg-background-subtle transition-colors',
                  )}
                >
                  <CheckboxIndicator checked={isSelected} />
                  {opt.icon && (
                    <span className="flex h-4 w-4 shrink-0 items-center justify-center text-foreground-secondary">
                      {opt.icon}
                    </span>
                  )}
                  <span className="truncate">{opt.label}</span>
                </button>
              );
            })
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}

function CheckboxIndicator({ checked }: { checked: boolean }) {
  return (
    <span
      aria-hidden
      className={cn(
        'flex h-4 w-4 shrink-0 items-center justify-center rounded-sm border transition-colors',
        checked ? 'border-white bg-white' : 'border-border bg-transparent',
      )}
    >
      {checked && <Check className="h-3 w-3 text-black" strokeWidth={3} />}
    </span>
  );
}
