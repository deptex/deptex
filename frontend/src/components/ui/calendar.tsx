import * as React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { DayPicker } from 'react-day-picker';
import 'react-day-picker/style.css';

import { cn } from '../../lib/utils';
import { buttonVariants } from './button';

export type CalendarProps = React.ComponentProps<typeof DayPicker>;

export function Calendar({
  className,
  classNames,
  showOutsideDays = true,
  ...props
}: CalendarProps) {
  return (
    <DayPicker
      showOutsideDays={showOutsideDays}
      className={cn('p-3', className)}
      classNames={{
        months: 'flex flex-col gap-4 sm:flex-row sm:gap-6',
        month: 'flex flex-col gap-3',
        month_caption: 'flex items-center justify-center pt-1 relative h-7',
        caption_label: 'text-sm font-medium text-foreground',
        nav: 'flex items-center gap-1',
        button_previous: cn(
          buttonVariants({ variant: 'outline' }),
          'absolute left-1 top-1 size-7 bg-transparent p-0 opacity-60 hover:opacity-100',
        ),
        button_next: cn(
          buttonVariants({ variant: 'outline' }),
          'absolute right-1 top-1 size-7 bg-transparent p-0 opacity-60 hover:opacity-100',
        ),
        month_grid: 'w-full border-collapse',
        weekdays: 'flex',
        weekday: 'w-9 text-center text-[11px] font-medium text-foreground-secondary',
        week: 'flex w-full mt-1',
        day: cn(
          'relative h-9 w-9 p-0 text-center text-sm focus-within:relative focus-within:z-20',
        ),
        day_button: cn(
          'inline-flex h-9 w-9 items-center justify-center rounded-md text-sm font-normal text-foreground',
          'hover:bg-background-subtle hover:text-foreground transition-colors',
          'aria-selected:opacity-100',
          'data-[selected-single=true]:bg-foreground data-[selected-single=true]:text-background data-[selected-single=true]:hover:bg-foreground',
          'data-[range-start=true]:bg-foreground data-[range-start=true]:text-background data-[range-start=true]:hover:bg-foreground',
          'data-[range-end=true]:bg-foreground data-[range-end=true]:text-background data-[range-end=true]:hover:bg-foreground',
          'data-[range-middle=true]:bg-transparent data-[range-middle=true]:text-foreground data-[range-middle=true]:hover:bg-background-subtle',
        ),
        range_start: 'rounded-l-md bg-background-subtle',
        range_middle: 'bg-background-subtle',
        range_end: 'rounded-r-md bg-background-subtle',
        today: 'font-semibold',
        outside: 'text-foreground-secondary/40 opacity-50',
        disabled: 'text-foreground-secondary/30 opacity-40 pointer-events-none',
        hidden: 'invisible',
        ...classNames,
      }}
      components={{
        Chevron: ({ orientation, ...rest }: any) =>
          orientation === 'left' ? (
            <ChevronLeft className="h-4 w-4" {...rest} />
          ) : (
            <ChevronRight className="h-4 w-4" {...rest} />
          ),
      }}
      {...props}
    />
  );
}
