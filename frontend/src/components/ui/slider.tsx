import * as React from "react"
import * as SliderPrimitive from "@radix-ui/react-slider"

import { cn } from "../../lib/utils"

const Slider = React.forwardRef<
  React.ElementRef<typeof SliderPrimitive.Root>,
  React.ComponentPropsWithoutRef<typeof SliderPrimitive.Root> & {
    /** Single value mode - pass number for value and (n: number) => void for onValueChange */
    value?: number
    onValueChange?: (value: number) => void
  }
>(
  (
    {
      className,
      value: valueProp,
      onValueChange: onValueChangeProp,
      defaultValue,
      min = 0,
      max = 100,
      step = 1,
      ...props
    },
    ref
  ) => {
    // Support both Radix array API and our simpler number API
    const value = valueProp !== undefined ? [valueProp] : undefined
    const defaultVal = defaultValue !== undefined ? (Array.isArray(defaultValue) ? defaultValue : [defaultValue]) : undefined
    const onValueChange = onValueChangeProp
      ? (v: number[]) => onValueChangeProp(v[0] ?? min)
      : undefined

    return (
      <SliderPrimitive.Root
        ref={ref}
        className={cn("relative flex w-full touch-none select-none items-center", className)}
        value={value}
        defaultValue={defaultVal}
        onValueChange={onValueChange}
        min={min}
        max={max}
        step={step}
        {...props}
      >
        <SliderPrimitive.Track className="relative h-2.5 w-full grow overflow-hidden rounded-full bg-muted">
          <SliderPrimitive.Range className="absolute h-full rounded-full bg-primary" />
        </SliderPrimitive.Track>
        <SliderPrimitive.Thumb className="block h-5 w-5 rounded-full border-2 border-primary bg-background shadow-md ring-offset-background transition-colors hover:border-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 cursor-grab active:cursor-grabbing" />
      </SliderPrimitive.Root>
    )
  }
)
Slider.displayName = SliderPrimitive.Root.displayName

export { Slider }
