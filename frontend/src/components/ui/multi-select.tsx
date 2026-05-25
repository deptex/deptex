import * as React from 'react';
import { Check, ChevronDown } from 'lucide-react';
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
}

export function MultiSelect({
  options,
  selected,
  onChange,
  renderLabel,
  triggerClassName,
  contentClassName,
  align = 'start',
}: MultiSelectProps) {
  const total = options.length;
  const allSelected = total > 0 && selected.length === total;
  const label = renderLabel(selected.length, total);

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
          className={cn(
            'flex h-9 items-center justify-between gap-2 rounded-md border border-border bg-background-card px-3 text-sm text-foreground',
            'hover:bg-background-subtle transition-colors',
            'focus:outline-none focus:ring-1 focus:ring-ring',
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
      >
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
          {options.map((opt) => {
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
          })}
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
        checked ? 'border-foreground bg-foreground' : 'border-border bg-transparent',
      )}
    >
      {checked && <Check className="h-3 w-3 text-background" strokeWidth={3} />}
    </span>
  );
}
