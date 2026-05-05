import { createContext, useContext, useCallback, useEffect, useState, type ReactNode } from 'react';

interface PlanPanelContextValue {
  activeFixId: string | null;
  openPlan: (fixId: string) => void;
  closePlan: () => void;
  togglePlan: (fixId: string) => void;
}

const PlanPanelContext = createContext<PlanPanelContextValue | null>(null);

interface PlanPanelProviderProps {
  children: ReactNode;
  // When this key changes (e.g. the user switches chat threads or navigates to
  // a different screen), the panel auto-closes — a plan from a previous
  // context shouldn't bleed into the new one.
  resetKey?: string;
}

export function PlanPanelProvider({ children, resetKey }: PlanPanelProviderProps) {
  const [activeFixId, setActiveFixId] = useState<string | null>(null);

  const openPlan = useCallback((fixId: string) => setActiveFixId(fixId), []);
  const closePlan = useCallback(() => setActiveFixId(null), []);
  const togglePlan = useCallback((fixId: string) => {
    setActiveFixId((curr) => (curr === fixId ? null : fixId));
  }, []);

  useEffect(() => {
    setActiveFixId(null);
  }, [resetKey]);

  return (
    <PlanPanelContext.Provider value={{ activeFixId, openPlan, closePlan, togglePlan }}>
      {children}
    </PlanPanelContext.Provider>
  );
}

export function usePlanPanel() {
  const ctx = useContext(PlanPanelContext);
  if (!ctx) throw new Error('usePlanPanel must be used within PlanPanelProvider');
  return ctx;
}
