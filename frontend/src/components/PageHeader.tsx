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
  /** Full-bleed work surfaces (findings, tables): span the content area instead
   *  of centering in the max-w-7xl reading column. */
  fullWidth?: boolean;
  /** Center the title in the band (Vercel-style). Meant for action-less headers —
   *  with `actions` present the title centers in the remaining space only. */
  centerTitle?: boolean;
}

/**
 * Per-page title bar that sits at the top of the SidebarInset content area on
 * organization pages. Replaces the visual weight previously provided by the
 * removed top AppHeader on org routes — at h-12 minimum so single-line headers
 * line up across pages, expanding when a description is present.
 */
export default function PageHeader({ title, description, actions, className, fullWidth, centerTitle }: PageHeaderProps) {
  return (
    <header className={cn('border-b border-border bg-background', className)}>
      <div
        className={cn(
          'flex w-full items-center justify-between gap-4 px-4 sm:px-6 min-h-12 py-3',
          !fullWidth && 'mx-auto max-w-7xl lg:px-8',
        )}
      >
        <div className={cn('min-w-0 flex-1', centerTitle && 'text-center')}>
          <h1 className={cn('flex items-baseline gap-3 text-base font-semibold text-foreground', centerTitle && 'justify-center')}>
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
