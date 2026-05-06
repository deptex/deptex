import { cn } from '../lib/utils';

interface PageHeaderProps {
  /** Page title. ReactNode so callers can inline counts or badges. */
  title: React.ReactNode;
  /** Optional supporting copy under the title. */
  description?: React.ReactNode;
  /** Right-side toolbar (buttons, switchers, etc). */
  actions?: React.ReactNode;
  /** Extra classes for the outer band. */
  className?: string;
}

/**
 * Per-page title bar that sits at the top of the SidebarInset content area on
 * organization pages. Replaces the visual weight previously provided by the
 * removed top AppHeader on org routes — at h-12 minimum so single-line headers
 * line up across pages, expanding when a description is present.
 */
export default function PageHeader({ title, description, actions, className }: PageHeaderProps) {
  return (
    <header className={cn('border-b border-border bg-background', className)}>
      <div className="mx-auto flex w-full max-w-7xl items-center justify-between gap-4 px-4 sm:px-6 lg:px-8 min-h-12 py-3">
        <div className="min-w-0 flex-1">
          <h1 className="flex items-baseline gap-3 text-base font-semibold text-foreground">
            {title}
          </h1>
          {description && (
            <p className="mt-0.5 max-w-2xl text-sm text-foreground-secondary">
              {description}
            </p>
          )}
        </div>
        {actions && <div className="flex flex-shrink-0 items-center gap-2">{actions}</div>}
      </div>
    </header>
  );
}
