import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "../../lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground border border-primary/50 shadow hover:bg-primary/90 hover:border-primary/70",
        solid:
          "bg-foreground text-background hover:bg-foreground/90 rounded-lg",
        destructive:
          "relative !h-8 !px-3 !rounded-lg bg-error/95 text-error-foreground shadow-sm hover:bg-error disabled:bg-error/30 disabled:text-error-foreground/60 disabled:opacity-100",
        outline:
          "border border-input bg-background-card shadow-sm hover:bg-background-card/80 hover:text-foreground",
        secondary:
          "bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/80",
        white:
          "relative !h-8 !px-3 !rounded-lg bg-foreground text-background shadow-sm hover:bg-foreground/85 disabled:bg-secondary disabled:text-foreground-secondary disabled:opacity-100",
        green:
          "relative !h-8 !px-3 !rounded-lg bg-emerald-700 text-white shadow-sm hover:bg-emerald-800 disabled:bg-emerald-700/30 disabled:text-white/60 disabled:opacity-100",
        ghost: "hover:bg-background-subtle hover:text-foreground",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-4 py-2",
        sm: "h-8 rounded-md px-3 text-xs",
        lg: "h-10 rounded-md px-8",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button, buttonVariants };
