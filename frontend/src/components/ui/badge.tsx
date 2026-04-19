import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "../../lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-border bg-background-subtle/50 text-foreground-secondary",
        secondary:
          "border-transparent bg-secondary text-secondary-foreground",
        success:
          "border-green-500/20 bg-green-500/10 text-green-500",
        warning:
          "border-amber-500/20 bg-amber-500/10 text-amber-500",
        destructive:
          "border-destructive/20 bg-destructive/10 text-destructive",
        outline:
          "border-border text-foreground-secondary bg-transparent",
        muted:
          "border-transparent bg-muted text-muted-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
