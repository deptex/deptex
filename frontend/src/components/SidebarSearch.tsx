import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  LayoutDashboard,
  Bug,
  MessageSquare,
  Settings,
  Users,
} from 'lucide-react';

import { FrameworkIcon } from './framework-icon';
import { cn } from '../lib/utils';
import { api, RolePermissions, TeamWithRole, Project } from '../lib/api';
import { buildOrgSettingsSections } from '../lib/orgSettingsSections';

interface SidebarSearchProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The sidebar "Find..." bar — the panel expands out of this element's box. */
  anchorRef: React.RefObject<HTMLElement>;
  organizationId: string;
  /** Effective (owner-expanded) org permissions — gates which destinations appear. */
  permissions: RolePermissions | null;
}

type SearchEntry = {
  id: string;
  label: string;
  subtitle: string;
  icon: React.ReactNode;
  run: () => void;
};

/** Panel grows wider than the narrow sidebar (per the reference), but never off-screen. */
const PANEL_MAX_WIDTH = 480;
/** Open/close transition length — keep in sync with the duration-200 class. */
const ANIM_MS = 200;

/**
 * Sidebar search palette. It does NOT pop up in the center of the screen — it
 * expands in place out of the sidebar "Find..." bar: the input lands exactly
 * where the bar was and the results drop below it. Opens from the bar, the `F`
 * key, or ⌘/Ctrl+K; closes on Esc or click-outside (animating both ways).
 *
 * Searchable surfaces: nav destinations, the org's projects and teams, and the
 * permission-aware settings sections — every row is a real, live route. There's
 * no fuzzy / full-text search backend yet; this is plain substring matching.
 */
export default function SidebarSearch({
  open,
  onOpenChange,
  anchorRef,
  organizationId,
  permissions,
}: SidebarSearchProps) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const [teams, setTeams] = useState<TeamWithRole[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [box, setBox] = useState<{
    top: number;
    left: number;
    barWidth: number;
    barHeight: number;
    width: number;
    maxHeight: number;
  } | null>(null);
  // `render` keeps the panel mounted through the close animation; `expanded`
  // drives the unfold (false = collapsed onto the bar, true = full panel).
  const [render, setRender] = useState(false);
  const [expanded, setExpanded] = useState(false);
  // Measured target height so width + height animate the same distance in sync.
  const [contentHeight, setContentHeight] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const headerRef = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  const go = (path: string) => {
    onOpenChange(false);
    navigate(path);
  };

  // Open a project/team panel. The overview page handles these events when it's
  // already mounted; the ?sidebar= params restore the panel on a fresh mount
  // when jumping in from another page.
  const openProject = (p: Project) => {
    onOpenChange(false);
    navigate(`/organizations/${organizationId}?sidebar=project&projectId=${p.id}&tab=findings`);
    window.dispatchEvent(new CustomEvent('organization:openProject', { detail: { project: p } }));
  };
  const openTeam = (t: TeamWithRole) => {
    onOpenChange(false);
    navigate(`/organizations/${organizationId}?sidebar=team&teamId=${t.id}&tab=findings`);
    window.dispatchEvent(new CustomEvent('organization:openTeam', { detail: { teamId: t.id, teamName: t.name } }));
  };

  const canUseAegis = permissions?.interact_with_aegis === true;

  // Pull the org's projects + teams when the palette opens so they're searchable.
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    Promise.all([api.getProjects(organizationId), api.getTeams(organizationId)])
      .then(([p, t]) => {
        if (cancelled) return;
        setProjects(p);
        setTeams(t);
      })
      .catch(() => {
        /* Non-fatal — nav + settings search still works without these. */
      });
    return () => {
      cancelled = true;
    };
  }, [open, organizationId]);

  // Real nav + project + team + settings destinations, permission-gated.
  const entries = useMemo<SearchEntry[]>(() => {
    const base = `/organizations/${organizationId}`;
    const iconCls = 'h-4 w-4';
    const list: SearchEntry[] = [
      { id: 'nav-overview', label: 'Overview', subtitle: 'Organization', icon: <LayoutDashboard className={iconCls} />, run: () => go(base) },
      { id: 'nav-findings', label: 'Findings', subtitle: 'Organization', icon: <Bug className={iconCls} />, run: () => go(`${base}/findings`) },
    ];
    if (canUseAegis) {
      list.push({ id: 'nav-aegis', label: 'Aegis', subtitle: 'AI security agent', icon: <MessageSquare className={iconCls} />, run: () => go(`${base}/aegis`) });
    }
    list.push({ id: 'nav-settings', label: 'Settings', subtitle: 'Organization', icon: <Settings className={iconCls} />, run: () => go(`${base}/settings`) });

    for (const p of projects) {
      list.push({ id: `project-${p.id}`, label: p.name, subtitle: 'Project', icon: <FrameworkIcon frameworkId={p.framework} size={16} />, run: () => openProject(p) });
    }
    for (const t of teams) {
      list.push({ id: `team-${t.id}`, label: t.name, subtitle: 'Team', icon: <Users className={iconCls} />, run: () => openTeam(t) });
    }

    for (const entry of buildOrgSettingsSections(permissions)) {
      if (entry.isCategory) continue;
      list.push({
        id: `settings-${entry.id}`,
        label: entry.label,
        subtitle: 'Settings',
        icon: entry.icon,
        run: () => go(`${base}/settings/${entry.id}`),
      });
    }
    return list;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [organizationId, permissions, canUseAegis, projects, teams]);

  const q = query.trim().toLowerCase();
  const visible = useMemo(() => {
    if (!q) return entries;
    return entries.filter(
      (e) => e.label.toLowerCase().includes(q) || e.subtitle.toLowerCase().includes(q),
    );
  }, [entries, q]);

  // Reset selection whenever the visible set changes (typing, opening).
  useEffect(() => {
    setActiveIndex(0);
  }, [q, open]);

  useEffect(() => {
    if (open) {
      setQuery('');
      const t = setTimeout(() => inputRef.current?.focus(), 0);
      return () => clearTimeout(t);
    }
  }, [open]);

  // Mount + measure + unfold on open; collapse + unmount on close.
  useLayoutEffect(() => {
    if (open) {
      setRender(true);
      const measure = () => {
        const el = anchorRef.current;
        if (!el) return;
        const r = el.getBoundingClientRect();
        const width = Math.max(r.width, Math.min(PANEL_MAX_WIDTH, window.innerWidth - r.left - 16));
        setBox({
          top: r.top,
          left: r.left,
          barWidth: r.width,
          barHeight: r.height,
          width,
          maxHeight: Math.max(220, window.innerHeight - r.top - 24),
        });
      };
      measure();
      setExpanded(false);
      // Expand on the next frame so the width/height transition runs out of the bar.
      const raf = requestAnimationFrame(() => requestAnimationFrame(() => setExpanded(true)));
      window.addEventListener('resize', measure);
      return () => {
        cancelAnimationFrame(raf);
        window.removeEventListener('resize', measure);
      };
    }
    // Closing: collapse back onto the bar, then unmount once the animation ends.
    setExpanded(false);
    const t = setTimeout(() => setRender(false), ANIM_MS);
    return () => clearTimeout(t);
  }, [open, anchorRef]);

  // Measure the real content height (header + full results list, clamped) so the
  // panel animates to an exact height — width and height stay in sync — and so it
  // stays roughly square rather than a tall narrow column.
  useLayoutEffect(() => {
    if (!open || !box) return;
    const headerH = headerRef.current?.offsetHeight ?? 0;
    const bodyH = bodyRef.current?.scrollHeight ?? 0;
    setContentHeight(Math.min(headerH + bodyH, box.maxHeight, box.width));
  }, [open, box, visible.length, query]);

  // Global open shortcuts + Esc; ⌘/Ctrl+K toggles, bare `F` opens (unless typing).
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        onOpenChange(!open);
        return;
      }
      if (!open) {
        if (e.metaKey || e.ctrlKey || e.altKey) return;
        if (e.key.toLowerCase() !== 'f') return;
        const t = e.target as HTMLElement | null;
        if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) {
          return;
        }
        e.preventDefault();
        onOpenChange(true);
      } else if (e.key === 'Escape') {
        e.preventDefault();
        onOpenChange(false);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, onOpenChange]);

  const onInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((i) => (visible.length ? (i + 1) % visible.length : 0));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex((i) => (visible.length ? (i - 1 + visible.length) % visible.length : 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      visible[activeIndex]?.run();
    }
  };

  if (!render || !box) return null;

  return createPortal(
    <>
      {/* Dim the rest of the screen so the panel is the only thing in focus. */}
      <div
        className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm transition-opacity duration-200"
        style={{ opacity: expanded ? 1 : 0 }}
        onClick={() => onOpenChange(false)}
      />
      <div
        role="dialog"
        aria-label="Search"
        style={{
          top: box.top,
          left: box.left,
          width: expanded ? box.width : box.barWidth,
          height: expanded ? contentHeight || box.barHeight : box.barHeight,
          opacity: expanded ? 1 : 0,
        }}
        className="fixed z-50 flex flex-col overflow-hidden rounded-xl border border-border bg-background-card shadow-2xl origin-top-left transition-[height,width,opacity] duration-200 ease-out"
      >
        {/* Input sits where the "Find..." bar was — the bar visually becomes this. */}
        <div ref={headerRef} className="flex items-center gap-3 px-4 h-12 border-b border-border shrink-0">
          <Search className="h-4 w-4 text-foreground-secondary shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Find..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onInputKeyDown}
            className="flex-1 bg-transparent text-sm text-foreground placeholder:text-foreground-secondary border-0 outline-none focus:outline-none focus:ring-0"
          />
          <kbd className="inline-flex items-center justify-center h-5 px-1.5 rounded border border-border font-medium text-[10px] text-foreground-secondary bg-background shrink-0">
            Esc
          </kbd>
        </div>

        <div ref={bodyRef} className="flex-1 min-h-0 overflow-y-auto custom-scrollbar p-1.5">
          {visible.length === 0 ? (
            <p className="px-3 py-6 text-center text-sm text-foreground-secondary">
              No results for “{query.trim()}”.
            </p>
          ) : (
            visible.map((entry, index) => {
              const isActive = index === activeIndex;
              return (
                <button
                  key={entry.id}
                  type="button"
                  onClick={entry.run}
                  onMouseEnter={() => setActiveIndex(index)}
                  className={cn(
                    'w-full flex items-center gap-3 px-2.5 py-2 rounded-lg text-left transition-colors',
                    isActive ? 'bg-background-subtle' : 'hover:bg-background-subtle/60',
                  )}
                >
                  <span
                    className={cn(
                      'flex items-center justify-center h-8 w-8 shrink-0 transition-colors',
                      isActive ? 'text-foreground' : 'text-foreground-secondary',
                    )}
                  >
                    {entry.icon}
                  </span>
                  <span className="flex flex-col min-w-0 flex-1">
                    <span className="text-sm font-medium text-foreground truncate">{entry.label}</span>
                    <span className="text-xs text-foreground-secondary truncate">{entry.subtitle}</span>
                  </span>
                </button>
              );
            })
          )}
        </div>
      </div>
    </>,
    document.body,
  );
}
