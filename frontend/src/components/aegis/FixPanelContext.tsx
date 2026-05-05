import { createContext, useContext, useCallback, useEffect, useState, type ReactNode } from 'react';

export type FixPanelView = 'detail' | 'list';

interface FixPanelContextValue {
  // Currently focused fix when view === 'detail'.
  activeFixId: string | null;
  // 'detail' shows a single fix; 'list' shows every fix registered in this scope.
  view: FixPanelView;
  // Fixes that have been seen in the current scope (chat thread). Order is
  // registration order — drives the list view's row order.
  registeredFixIds: string[];

  // Imperative actions a chat-side surface or breadcrumb can call.
  openFix: (fixId: string) => void;
  closeFix: () => void;
  toggleFix: (fixId: string) => void;
  showList: () => void;
  // Called by chat-side fix surfaces (PlanCard pill) on mount so the panel
  // knows every fix in the thread. Also drives auto-open: the FIRST fix
  // registered after a thread reset opens the panel, unless the user has
  // explicitly dismissed it. Subsequent fixes appear in the list but don't
  // steal focus.
  registerFix: (fixId: string) => void;
}

const FixPanelContext = createContext<FixPanelContextValue | null>(null);

interface FixPanelProviderProps {
  children: ReactNode;
  // When this key changes (e.g. the user switches chat threads or navigates
  // to a different screen), the panel auto-closes and registered fixes
  // clear — a plan from a previous context shouldn't bleed into the new one.
  resetKey?: string;
}

export function FixPanelProvider({ children, resetKey }: FixPanelProviderProps) {
  const [activeFixId, setActiveFixId] = useState<string | null>(null);
  const [view, setView] = useState<FixPanelView>('detail');
  const [registeredFixIds, setRegisteredFixIds] = useState<string[]>([]);
  const [userDismissed, setUserDismissed] = useState(false);

  const openFix = useCallback((fixId: string) => {
    setActiveFixId(fixId);
    setView('detail');
    setUserDismissed(false);
  }, []);

  const closeFix = useCallback(() => {
    setActiveFixId(null);
    setView('detail');
    setUserDismissed(true);
  }, []);

  const toggleFix = useCallback((fixId: string) => {
    setActiveFixId((curr) => {
      if (curr === fixId) {
        setUserDismissed(true);
        return null;
      }
      setView('detail');
      setUserDismissed(false);
      return fixId;
    });
  }, []);

  const showList = useCallback(() => {
    setView('list');
    setUserDismissed(false);
  }, []);

  const registerFix = useCallback((fixId: string) => {
    setRegisteredFixIds((prev) => (prev.includes(fixId) ? prev : [...prev, fixId]));
    setActiveFixId((curr) => {
      if (curr || userDismissed) return curr;
      setView('detail');
      return fixId;
    });
  }, [userDismissed]);

  useEffect(() => {
    setActiveFixId(null);
    setView('detail');
    setRegisteredFixIds([]);
    setUserDismissed(false);
  }, [resetKey]);

  return (
    <FixPanelContext.Provider
      value={{
        activeFixId,
        view,
        registeredFixIds,
        openFix,
        closeFix,
        toggleFix,
        showList,
        registerFix,
      }}
    >
      {children}
    </FixPanelContext.Provider>
  );
}

export function useFixPanel() {
  const ctx = useContext(FixPanelContext);
  if (!ctx) throw new Error('useFixPanel must be used within FixPanelProvider');
  return ctx;
}
