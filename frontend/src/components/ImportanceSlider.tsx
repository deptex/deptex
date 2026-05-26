import * as React from 'react';
import * as SliderPrimitive from '@radix-ui/react-slider';
import { cn } from '../lib/utils';
import { importanceColorClasses } from '../lib/scoring/depscore';

/**
 * Importance picker — a draggable slider in [0.5, 2.0] with step 0.1.
 * The number IS the depscore multiplier — there's no enum, no tier table.
 *
 * 1.0 is the default ("treat this like any other project").
 * Move it up to 2.0 to amplify findings on a critical project; down to 0.5
 * to dampen them on a low-priority experiment.
 */

const IMP_MIN = 0.5;
const IMP_MAX = 2.0;
const IMP_STEP = 0.1;
const IMP_DEFAULT = 1.0;

function clamp(v: number): number {
  if (!Number.isFinite(v)) return IMP_DEFAULT;
  return Math.max(IMP_MIN, Math.min(IMP_MAX, Math.round(v * 10) / 10));
}

function describe(v: number): string {
  if (v >= 1.8) return 'Most critical — findings amplified';
  if (v >= 1.4) return 'High importance';
  if (v >= 1.1) return 'Above default';
  if (v >= 0.9) return 'Default — treat like any project';
  if (v >= 0.7) return 'Lower priority';
  return 'Least critical — findings dampened';
}

interface ImportanceSliderProps {
  value: number;
  onChange: (next: number) => void;
  disabled?: boolean;
  className?: string;
}

export function ImportanceSlider({ value, onChange, disabled, className }: ImportanceSliderProps) {
  const v = clamp(value);
  const colors = importanceColorClasses(v);
  const percent = ((v - IMP_MIN) / (IMP_MAX - IMP_MIN)) * 100;

  return (
    <div className={cn('w-full', className)}>
      <div className="flex items-baseline justify-between mb-2">
        <label className="text-sm font-medium text-foreground">Project importance</label>
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md border text-sm font-medium tabular-nums',
            colors.bg,
            colors.border,
            colors.text,
          )}
        >
          <span
            className="inline-block w-1.5 h-1.5 rounded-full bg-current"
            style={{ opacity: colors.dotOpacity }}
            aria-hidden
          />
          {v.toFixed(1)}×
        </span>
      </div>

      <SliderPrimitive.Root
        className="relative flex w-full touch-none select-none items-center py-1.5"
        value={[v]}
        onValueChange={(arr) => onChange(clamp(arr[0] ?? IMP_DEFAULT))}
        min={IMP_MIN}
        max={IMP_MAX}
        step={IMP_STEP}
        disabled={disabled}
        aria-label="Project importance"
      >
        <SliderPrimitive.Track className="relative h-2 w-full grow overflow-hidden rounded-full bg-background-subtle">
          {/* Faint marker at the default position (1.0) */}
          <span
            className="absolute top-0 h-full w-px bg-border"
            style={{ left: `${((IMP_DEFAULT - IMP_MIN) / (IMP_MAX - IMP_MIN)) * 100}%` }}
            aria-hidden
          />
          <SliderPrimitive.Range className={cn('absolute h-full rounded-full', colors.bg.replace('/10', '/40'))} />
        </SliderPrimitive.Track>
        <SliderPrimitive.Thumb
          className={cn(
            'block h-4 w-4 rounded-full border-2 bg-background shadow-sm ring-offset-background transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
            'disabled:pointer-events-none disabled:opacity-50 cursor-grab active:cursor-grabbing',
            colors.border.replace('/40', ''),
          )}
        />
      </SliderPrimitive.Root>

      <div className="flex justify-between mt-1.5 text-xs text-foreground-muted tabular-nums">
        <span>0.5×</span>
        <span style={{ marginLeft: `${percent}%`, transform: 'translateX(-50%)' }} className="font-medium text-foreground-secondary whitespace-nowrap">
          {describe(v)}
        </span>
        <span>2.0×</span>
      </div>
    </div>
  );
}

export { IMP_MIN, IMP_MAX, IMP_STEP, IMP_DEFAULT };
