import * as React from 'react';
import * as SliderPrimitive from '@radix-ui/react-slider';
import { cn } from '../lib/utils';

const IMP_MIN = 0.5;
const IMP_MAX = 2.0;
const IMP_STEP = 0.1;
const IMP_DEFAULT = 1.0;

const TICKS = [0.5, 1.0, 1.5, 2.0] as const;

function clamp(v: number): number {
  if (!Number.isFinite(v)) return IMP_DEFAULT;
  return Math.max(IMP_MIN, Math.min(IMP_MAX, Math.round(v * 10) / 10));
}

interface ImportanceSliderProps {
  value: number;
  onChange: (next: number) => void;
  disabled?: boolean;
  className?: string;
  /** Hide the internal title + value row (use when a wrapper renders its own header). */
  hideHeader?: boolean;
}

export function ImportanceSlider({ value, onChange, disabled, className, hideHeader }: ImportanceSliderProps) {
  const v = clamp(value);

  return (
    <div className={cn('w-full', className)}>
      {!hideHeader && (
        <div className="flex items-center justify-between mb-3">
          <label className="text-sm font-medium text-foreground">Project importance</label>
          <span className="text-sm tabular-nums text-foreground">
            {v.toFixed(1)}×
          </span>
        </div>
      )}

      <SliderPrimitive.Root
        className="relative flex w-full touch-none select-none items-center"
        value={[v]}
        onValueChange={(arr) => onChange(clamp(arr[0] ?? IMP_DEFAULT))}
        min={IMP_MIN}
        max={IMP_MAX}
        step={IMP_STEP}
        disabled={disabled}
        aria-label="Project importance"
      >
        <SliderPrimitive.Track className="relative h-1.5 w-full grow overflow-hidden rounded-full bg-background-subtle">
          <SliderPrimitive.Range className="absolute h-full rounded-full bg-foreground" />
        </SliderPrimitive.Track>
        <SliderPrimitive.Thumb
          className={cn(
            'block h-4 w-4 rounded-full border border-border bg-foreground shadow-md ring-offset-background transition-transform',
            'hover:scale-110',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
            'disabled:pointer-events-none disabled:opacity-50',
            'cursor-grab active:cursor-grabbing active:scale-110',
          )}
        />
      </SliderPrimitive.Root>

      <div className="mt-3 flex items-center justify-between text-xs tabular-nums text-foreground-secondary">
        {TICKS.map((t) => (
          <span key={t}>{t.toFixed(1)}×</span>
        ))}
      </div>
    </div>
  );
}

export { IMP_MIN, IMP_MAX, IMP_STEP, IMP_DEFAULT };
