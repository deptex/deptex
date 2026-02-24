import * as React from "react"
import { ChevronLeft, ChevronRight } from "lucide-react"
import { DayPicker, DayPickerRangeProps, DayPickerSingleProps } from "react-day-picker"

import { cn } from "../../lib/utils"

export type CalendarProps =
    | (DayPickerSingleProps & { mode: "single" })
    | (DayPickerRangeProps & { mode: "range" })

function Calendar({
    className,
    classNames,
    showOutsideDays = true,
    ...props
}: CalendarProps) {
    return (
        <DayPicker
            showOutsideDays={showOutsideDays}
            className={cn("p-3", className)}
            classNames={{
                months: "flex flex-col sm:flex-row space-y-4 sm:space-x-4 sm:space-y-0",
                month: "space-y-4",
                caption: "flex justify-center pt-1 relative items-center",
                caption_label: "text-sm font-medium text-foreground",
                nav: "space-x-1 flex items-center",
                nav_button: cn(
                    "h-7 w-7 bg-transparent p-0 opacity-50 hover:opacity-100",
                    "inline-flex items-center justify-center rounded-md text-sm font-medium",
                    "transition-colors hover:bg-background-subtle focus-visible:outline-none",
                    "focus-visible:ring-2 focus-visible:ring-primary disabled:pointer-events-none disabled:opacity-50"
                ),
                nav_button_previous: "absolute left-1",
                nav_button_next: "absolute right-1",
                table: "w-full border-collapse space-y-1",
                head_row: "flex",
                head_cell: "text-foreground-secondary rounded-md w-9 font-normal text-[0.8rem]",
                row: "flex w-full mt-2",
                cell: cn(
                    "relative p-0 text-center text-sm focus-within:relative focus-within:z-20",
                    "[&:has([aria-selected])]:bg-background-subtle",
                    "[&:has([aria-selected].day-range-end)]:rounded-r-md",
                    "[&:has([aria-selected].day-range-start)]:rounded-l-md",
                    "[&:has([aria-selected].day-outside)]:bg-background-subtle/50"
                ),
                day: cn(
                    "h-9 w-9 p-0 font-normal aria-selected:opacity-100",
                    "inline-flex items-center justify-center rounded-md text-sm",
                    "hover:bg-background-subtle hover:text-foreground transition-colors",
                    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                ),
                day_range_start: "day-range-start",
                day_range_end: "day-range-end",
                day_selected: cn(
                    "bg-primary text-primary-foreground hover:bg-primary hover:text-primary-foreground",
                    "focus:bg-primary focus:text-primary-foreground"
                ),
                day_today: "bg-background-subtle text-foreground font-semibold",
                day_outside: "day-outside text-foreground-secondary/50 opacity-50",
                day_disabled: "text-foreground-secondary/50 opacity-50",
                day_range_middle: cn(
                    "aria-selected:bg-background-subtle aria-selected:text-foreground",
                    "rounded-none"
                ),
                day_hidden: "invisible",
                ...classNames,
            }}
            components={{
                IconLeft: ({ ...props }) => <ChevronLeft className="h-4 w-4" />,
                IconRight: ({ ...props }) => <ChevronRight className="h-4 w-4" />,
            }}
            {...props}
        />
    )
}
Calendar.displayName = "Calendar"

export { Calendar }
