import React, { useState } from 'react';
import { Calendar as CalendarIcon, ChevronDown } from 'lucide-react';
import { DateRange as DayPickerRange } from 'react-day-picker';
import { format } from 'date-fns';
import { Popover, PopoverContent, PopoverTrigger } from '../ui/popover';
import { Calendar } from '../ui/calendar';
import { Button } from '../ui/button';
import { cn } from '../../lib/utils';
import type { DateRange, DateRangePreset } from './usage-types';

const PRESETS: Array<{ id: DateRangePreset; label: string; compute: () => { start: Date; end: Date } }> = [
  {
    id: 'last_7d',
    label: 'Last 7 days',
    compute: () => ({ start: addDays(new Date(), -7), end: new Date() }),
  },
  {
    id: 'last_30d',
    label: 'Last 30 days',
    compute: () => ({ start: addDays(new Date(), -30), end: new Date() }),
  },
  {
    id: 'this_month',
    label: 'This month',
    compute: () => {
      const end = new Date();
      const start = new Date(end.getFullYear(), end.getMonth(), 1);
      return { start, end };
    },
  },
  {
    id: 'last_month',
    label: 'Last month',
    compute: () => {
      const now = new Date();
      const start = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      const end = new Date(now.getFullYear(), now.getMonth(), 0, 23, 59, 59);
      return { start, end };
    },
  },
  {
    id: 'last_90d',
    label: 'Last 90 days',
    compute: () => ({ start: addDays(new Date(), -90), end: new Date() }),
  },
];

function addDays(d: Date, days: number): Date {
  const copy = new Date(d);
  copy.setDate(copy.getDate() + days);
  return copy;
}

function triggerLabel(range: DateRange): string {
  if (range.preset !== 'custom') {
    const preset = PRESETS.find((p) => p.id === range.preset);
    if (preset) return preset.label;
  }
  return `${format(range.start, 'MMM d, yyyy')} – ${format(range.end, 'MMM d, yyyy')}`;
}

interface DateRangePickerProps {
  value: DateRange;
  onChange: (range: DateRange) => void;
}

export function DateRangePicker({ value, onChange }: DateRangePickerProps) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<DayPickerRange | undefined>({ from: value.start, to: value.end });

  const applyPreset = (preset: typeof PRESETS[number]) => {
    const r = preset.compute();
    setDraft({ from: r.start, to: r.end });
    onChange({ start: r.start, end: r.end, preset: preset.id });
    setOpen(false);
  };

  const applyDraft = () => {
    if (!draft?.from || !draft?.to) return;
    const start = new Date(draft.from);
    start.setHours(0, 0, 0, 0);
    const end = new Date(draft.to);
    end.setHours(23, 59, 59, 999);
    onChange({ start, end, preset: 'custom' });
    setOpen(false);
  };

  return (
    <Popover
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) setDraft({ from: value.start, to: value.end });
      }}
    >
      <PopoverTrigger asChild>
        <button
          type="button"
          className={cn(
            'flex h-9 items-center justify-between gap-2 rounded-md border border-border bg-background-card px-3 text-sm text-foreground',
            'hover:bg-background-subtle transition-colors',
            'focus:outline-none focus:ring-1 focus:ring-ring',
            'min-w-[230px]',
          )}
        >
          <span className="flex items-center gap-2">
            <CalendarIcon className="h-4 w-4 text-foreground-secondary" />
            <span>{triggerLabel(value)}</span>
          </span>
          <ChevronDown className="h-4 w-4 text-foreground-secondary" />
        </button>
      </PopoverTrigger>
      <PopoverContent className="flex w-auto p-0" align="start">
        <div className="flex flex-col border-r border-border p-2 sm:w-44">
          <p className="px-2 py-1 text-[11px] font-medium uppercase tracking-wider text-foreground-secondary">
            Quick ranges
          </p>
          <div className="flex flex-col">
            {PRESETS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                onClick={() => applyPreset(preset)}
                className={cn(
                  'rounded-md px-3 py-1.5 text-left text-sm text-foreground transition-colors',
                  'hover:bg-background-subtle',
                  value.preset === preset.id && 'bg-background-subtle font-medium',
                )}
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>
        <div className="flex flex-col">
          <Calendar
            mode="range"
            selected={draft}
            onSelect={setDraft}
            numberOfMonths={2}
            defaultMonth={addDays(new Date(new Date().getFullYear(), new Date().getMonth(), 1), -1)}
            endMonth={new Date()}
            disabled={{ after: new Date() }}
            captionLayout="label"
          />
          <div className="flex items-center justify-end px-3 py-2">
            <Button
              variant="green"
              size="sm"
              onClick={applyDraft}
              disabled={!draft?.from || !draft?.to}
            >
              Apply
            </Button>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}
