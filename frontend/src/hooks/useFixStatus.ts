import { useState, useEffect, useCallback, createContext, useContext, ReactNode } from 'react';
import { supabase } from '../lib/supabase';
import { api, FixJob } from '../lib/api';
import React from 'react';

// ---------- Project-level fix status ----------

interface ProjectFixStatus {
  fixes: FixJob[];
  runningCount: number;
  queuedCount: number;
  isLoading: boolean;
  refresh: () => void;
  getFixForVuln: (osvId: string) => FixJob | null;
  getFixForSemgrep: (findingId: string) => FixJob | null;
  getFixForSecret: (findingId: string) => FixJob | null;
  getFixesForDep: (osvIds: string[]) => FixJob[];
}

export function useProjectFixStatus(
  orgId: string | undefined,
  projectId: string | undefined,
): ProjectFixStatus {
  const [fixes, setFixes] = useState<FixJob[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const refresh = useCallback(async () => {
    if (!orgId || !projectId) return;
    try {
      const data = await api.getFixStatus(orgId, projectId);
      setFixes(data);
    } catch {
      // silent
    } finally {
      setIsLoading(false);
    }
  }, [orgId, projectId]);

  useEffect(() => {
    if (!projectId) return;
    refresh();

    const channel = supabase
      .channel(`fix-status:${projectId}`)
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'project_security_fixes',
          filter: `project_id=eq.${projectId}`,
        },
        () => { refresh(); },
      )
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, [projectId, refresh]);

  const active = fixes.filter(f => f.status === 'queued' || f.status === 'running');
  const runningCount = fixes.filter(f => f.status === 'running').length;
  const queuedCount = fixes.filter(f => f.status === 'queued').length;

  const getFixForVuln = useCallback((osvId: string) => {
    return active.find(f => f.osv_id === osvId) || fixes.find(f => f.osv_id === osvId && f.status === 'completed') || null;
  }, [active, fixes]);

  const getFixForSemgrep = useCallback((findingId: string) => {
    return active.find(f => f.semgrep_finding_id === findingId) || null;
  }, [active]);

  const getFixForSecret = useCallback((findingId: string) => {
    return active.find(f => f.secret_finding_id === findingId) || null;
  }, [active]);

  const getFixesForDep = useCallback((osvIds: string[]) => {
    return active.filter(f => f.osv_id && osvIds.includes(f.osv_id));
  }, [active]);

  return { fixes, runningCount, queuedCount, isLoading, refresh, getFixForVuln, getFixForSemgrep, getFixForSecret, getFixesForDep };
}

// ---------- Target-level fix status ----------

interface TargetFixStatus {
  activeFix: FixJob | null;
  recentFixes: FixJob[];
  canStartNewFix: boolean;
  blockReason?: string;
}

export function useTargetFixStatus(target: {
  osvId?: string;
  semgrepFindingId?: string;
  secretFindingId?: string;
  orgId?: string;
  projectId?: string;
}): TargetFixStatus {
  const [fixes, setFixes] = useState<FixJob[]>([]);

  useEffect(() => {
    if (!target.orgId || !target.projectId) return;
    const params: any = {};
    if (target.osvId) params.osvId = target.osvId;
    if (target.semgrepFindingId) params.semgrepFindingId = target.semgrepFindingId;
    if (target.secretFindingId) params.secretFindingId = target.secretFindingId;

    api.getFixes(target.orgId, target.projectId, params).then(setFixes).catch(() => {});
  }, [target.orgId, target.projectId, target.osvId, target.semgrepFindingId, target.secretFindingId]);

  const activeFix = fixes.find(f => f.status === 'queued' || f.status === 'running') || null;
  const recentFixes = fixes.slice(0, 5);

  const failedIn24h = fixes.filter(f => {
    if (f.status !== 'failed') return false;
    const age = Date.now() - new Date(f.created_at).getTime();
    return age < 24 * 60 * 60 * 1000;
  });

  let canStartNewFix = !activeFix;
  let blockReason: string | undefined;

  if (activeFix) {
    blockReason = `Fix is ${activeFix.status === 'queued' ? 'queued' : 'in progress'}`;
    canStartNewFix = false;
  } else if (failedIn24h.length >= 3) {
    blockReason = `${failedIn24h.length} fix attempts failed in 24 hours. Manual intervention required.`;
    canStartNewFix = false;
  }

  return { activeFix, recentFixes, canStartNewFix, blockReason };
}

// ---------- Context providers ----------

const FixStatusContext = createContext<ProjectFixStatus | null>(null);

export function FixStatusProvider({ orgId, projectId, children }: {
  orgId: string;
  projectId: string;
  children: ReactNode;
}) {
  const status = useProjectFixStatus(orgId, projectId);
  return React.createElement(FixStatusContext.Provider, { value: status }, children);
}

export function useFixStatusContext(): ProjectFixStatus | null {
  return useContext(FixStatusContext);
}
