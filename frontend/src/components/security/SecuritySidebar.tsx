import { memo, useState, useEffect, useCallback, ReactNode } from 'react';
import { cn } from '../../lib/utils';

export type ActiveSidebar = {
  type: 'vulnerability' | 'dependency' | 'project';
  id: string;
} | null;

interface SecuritySidebarProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  footer?: ReactNode;
  children: ReactNode;
}

function SecuritySidebar({ isOpen, onClose, title, subtitle, footer, children }: SecuritySidebarProps) {
  const [panelVisible, setPanelVisible] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setPanelVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setPanelVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setPanelVisible(false);
    }
  }, [isOpen]);

  const handleClose = useCallback(() => {
    setPanelVisible(false);
    setTimeout(onClose, 150);
  }, [onClose]);

  if (!isOpen) return null;

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
          'fixed right-4 top-4 bottom-4 w-full max-w-[560px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
          panelVisible ? 'translate-x-0' : 'translate-x-full'
        )}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-6 pt-5 pb-3 flex-shrink-0">
          <h2 className="text-xl font-semibold text-foreground">{title}</h2>
          {subtitle && (
            <p className="text-sm text-foreground-secondary mt-1">{subtitle}</p>
          )}
        </div>

        <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">
          {children}
        </div>

        {footer && (
          <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}

export default memo(SecuritySidebar);
