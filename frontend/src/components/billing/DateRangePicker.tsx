import React, { useState } from 'react';
import { Calendar, ChevronDown } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from '../ui/popover';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { cn } from '../../lib/utils';
import type { DateRange, DateRangePreset } from './usage-types';

const PRESETS: Array<{ id: DateRangePreset; label: string; computeRange: () => { start: Date; end: Date } }> = [
  {
    id: 'last_7d',
    label: 'Last 7 days',
    computeRange: () => ({
      start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      end: new Date(),
    }),
  },
  {
    id: 'last_30d',
    label: 'Last 30 days',
    computeRange: () => ({
      start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      end: new Date(),
    }),
  },
  {
    id: 'this_month',
    label: 'This month',
    computeRange: () => {
      const end = new Date();
      const start = new Date(end.getFullYear(), end.getMonth(), 1);
      return { start, end };
    },
  },
  {
    id: 'last_month',
    label: 'Last month',
    computeRange: () => {
      const now = new Date();
      const start = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      const end = new Date(now.getFullYear(), now.getMonth(), 0, 23, 59, 59);
      return { start, end };
    },
  },
  {
    id: 'last_90d',
    label: 'Last 90 days',
    computeRange: () => ({
      start: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000),
      end: new Date(),
    }),
  },
];

function presetLabel(range: DateRange): string {
  if (range.preset === 'custom') {
    return `${range.start.toLocaleDateString()} – ${range.end.toLocaleDateString()}`;
  }
  return PRESETS.find((p) => p.id === range.preset)?.label ?? 'Custom';
}

interface DateRangePickerProps {
  value: DateRange;
  onChange: (range: DateRange) => void;
}

export function DateRangePicker({ value, onChange }: DateRangePickerProps) {
  const [open, setOpen] = useState(false);
  const [customStart, setCustomStart] = useState(value.start.toISOString().slice(0, 10));
  const [customEnd, setCustomEnd] = useState(value.end.toISOString().slice(0, 10));

  const applyCustom = () => {
    const start = new Date(customStart);
    const end = new Date(customEnd + 'T23:59:59');
    if (isNaN(start.getTime()) || isNaN(end.getTime()) || start > end) return;
    onChange({ start, end, preset: 'custom' });
    setOpen(false);
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          className={cn(
            'flex h-9 min-w-[200px] items-center justify-between gap-2 rounded-md border border-border bg-background-card px-3 text-sm text-foreground hover:bg-background-card-hover',
          )}
        >
          <span className="flex items-center gap-2">
            <Calendar className="h-4 w-4 text-foreground-secondary" />
            <span>{presetLabel(value)}</span>
          </span>
          <ChevronDown className="h-4 w-4 text-foreground-secondary" />
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-72 p-0" align="start">
        <div className="border-b border-border p-1">
          {PRESETS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => {
                const range = preset.computeRange();
                onChange({ ...range, preset: preset.id });
                setOpen(false);
              }}
              className={cn(
                'flex w-full items-center rounded-sm px-3 py-1.5 text-left text-sm text-foreground hover:bg-background-card-hover',
                value.preset === preset.id && 'bg-background-card-hover',
              )}
            >
              {preset.label}
            </button>
          ))}
        </div>
        <div className="space-y-2 p-3">
          <p className="text-xs font-medium text-foreground-secondary">Custom range</p>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <Label htmlFor="dr-start" className="text-xs text-foreground-secondary">From</Label>
              <Input id="dr-start" type="date" value={customStart} onChange={(e) => setCustomStart(e.target.value)} />
            </div>
            <div>
              <Label htmlFor="dr-end" className="text-xs text-foreground-secondary">To</Label>
              <Input id="dr-end" type="date" value={customEnd} onChange={(e) => setCustomEnd(e.target.value)} />
            </div>
          </div>
          <Button variant="green" size="sm" className="w-full" onClick={applyCustom}>
            Apply custom range
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
