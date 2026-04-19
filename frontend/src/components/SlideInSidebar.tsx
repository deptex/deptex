import { useState, useEffect, useCallback } from 'react';
import { cn } from '../lib/utils';

export interface SlideInSidebarProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  footerClassName?: string;
  maxWidth?: 'max-w-[420px]' | 'max-w-[560px]' | 'max-w-[680px]';
}

export function SlideInSidebar({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  footerClassName,
  maxWidth = 'max-w-[420px]',
}: SlideInSidebarProps) {
  const [panelVisible, setPanelVisible] = useState(false);

  useEffect(() => {
    if (open) {
      setPanelVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setPanelVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setPanelVisible(false);
    }
  }, [open]);

  const handleClose = useCallback(() => {
    setPanelVisible(false);
    setTimeout(onClose, 150);
  }, [onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      <div
        className={cn(
          'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
          panelVisible ? 'opacity-100' : 'opacity-0'
        )}
        onClick={handleClose}
      />

      <div
        className={cn(
          'fixed right-4 top-4 bottom-4 w-full bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
          maxWidth,
          panelVisible ? 'translate-x-0' : 'translate-x-full'
        )}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-6 pt-5 pb-3 flex-shrink-0">
          <h2 className="text-xl font-semibold text-foreground">{title}</h2>
          {description && (
            <p className="text-sm text-foreground-secondary mt-1">{description}</p>
          )}
        </div>

        <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">
          {children}
        </div>

        {footer !== undefined && (
          <div className={cn('px-6 py-4 flex items-center gap-3 flex-shrink-0 border-t border-border bg-background-card-header', footerClassName ?? 'justify-end')}>
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
