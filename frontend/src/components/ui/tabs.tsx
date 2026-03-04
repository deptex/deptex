import * as React from "react"
import { cn } from "../../lib/utils"

const TabsContext = React.createContext<{ value: string; onValueChange: (v: string) => void } | null>(null)
const TabsListVariantContext = React.createContext<"default" | "line">("default")

const Tabs = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & { value?: string; defaultValue?: string; onValueChange?: (value: string) => void }
>(({ className, value: controlledValue, defaultValue, onValueChange, ...props }, ref) => {
  const [uncontrolled, setUncontrolled] = React.useState(defaultValue ?? "")
  const value = controlledValue !== undefined ? controlledValue : uncontrolled
  const setValue = React.useCallback((v: string) => {
    if (controlledValue === undefined) setUncontrolled(v)
    onValueChange?.(v)
  }, [controlledValue, onValueChange])
  return (
    <TabsContext.Provider value={{ value, onValueChange: setValue }}>
      <div ref={ref} className={cn("", className)} data-state={value} {...props} />
    </TabsContext.Provider>
  )
})
Tabs.displayName = "Tabs"

const TabsList = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & { variant?: "default" | "line" }
>(({ className, variant = "default", ...props }, ref) => (
  <TabsListVariantContext.Provider value={variant}>
    <div
      ref={ref}
      data-variant={variant}
      className={cn(
        "inline-flex items-center text-muted-foreground",
        variant === "default" && "h-9 justify-center rounded-lg bg-muted p-1",
        variant === "line" && "gap-0 border-b border-border rounded-none",
        className
      )}
      {...props}
    />
  </TabsListVariantContext.Provider>
))
TabsList.displayName = "TabsList"

const TabsTrigger = React.forwardRef<
  HTMLButtonElement,
  React.ButtonHTMLAttributes<HTMLButtonElement> & { value: string; variant?: "default" | "line" }
>(({ className, value, variant: triggerVariant, children, ...props }, ref) => {
  const ctx = React.useContext(TabsContext)
  const listVariant = React.useContext(TabsListVariantContext)
  if (!ctx) throw new Error("TabsTrigger must be used within Tabs")
  const isSelected = ctx.value === value
  const variant = triggerVariant ?? listVariant
  return (
    <button
      ref={ref}
      type="button"
      role="tab"
      aria-selected={isSelected}
      data-state={isSelected ? "active" : "inactive"}
      className={cn(
        "inline-flex items-center justify-center whitespace-nowrap text-sm font-medium ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
        variant === "default" && "rounded-md px-3 py-1",
        variant === "default" && isSelected && "bg-background text-foreground shadow",
        variant === "line" && "rounded-none px-4 py-3 -mb-px",
        variant === "line" && isSelected && "text-foreground",
        variant === "line" && !isSelected && "text-foreground-secondary hover:text-foreground",
        className
      )}
      onClick={() => ctx.onValueChange(value)}
      {...props}
    >
      {variant === "line" ? (
        <span className="inline-block">{children}</span>
      ) : (
        children
      )}
    </button>
  )
})
TabsTrigger.displayName = "TabsTrigger"

const TabsContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & { value: string }
>(({ className, value, ...props }, ref) => {
  const ctx = React.useContext(TabsContext)
  if (!ctx) throw new Error("TabsContent must be used within Tabs")
  if (ctx.value !== value) return null
  return (
    <div
      ref={ref}
      role="tabpanel"
      className={cn(
        "mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
        className
      )}
      {...props}
    />
  )
})
TabsContent.displayName = "TabsContent"

export { Tabs, TabsList, TabsTrigger, TabsContent }
