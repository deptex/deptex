import { useEffect, useRef, type Dispatch, type SetStateAction } from 'react';
import { ChevronRight, Loader2, Lock } from 'lucide-react';
import { SiDocker } from '@icons-pack/react-simple-icons';
import { api } from '../lib/api';
import { cn } from '../lib/utils';
import { FrameworkIcon } from './framework-icon';
import { Tooltip, TooltipTrigger, TooltipContent } from './ui/tooltip';

const FRAMEWORK_LABELS: Record<string, string> = {
  npm: 'JavaScript',
  node: 'JavaScript',
  javascript: 'JavaScript',
  pypi: 'Python',
  python: 'Python',
  maven: 'Java',
  java: 'Java',
  cargo: 'Rust',
  rust: 'Rust',
  gem: 'Ruby',
  ruby: 'Ruby',
  composer: 'PHP',
  php: 'PHP',
  nuget: 'C# / .NET',
  dotnet: 'C# / .NET',
  go: 'Go',
  golang: 'Go',
  nextjs: 'Next.js',
  react: 'React',
  vue: 'Vue',
  nuxt: 'Nuxt',
  svelte: 'Svelte',
  angular: 'Angular',
  express: 'Express',
  django: 'Django',
  fastapi: 'FastAPI',
  flask: 'Flask',
  'spring-boot': 'Spring Boot',
  quarkus: 'Quarkus',
  gin: 'Gin',
  echo: 'Echo',
  fiber: 'Fiber',
  actix: 'Actix',
  axum: 'Axum',
  rocket: 'Rocket',
  rails: 'Rails',
  sinatra: 'Sinatra',
  laravel: 'Laravel',
  symfony: 'Symfony',
  aspnet: 'ASP.NET',
};

function frameworkLabel(id?: string | null): string {
  if (!id) return 'No framework detected';
  return FRAMEWORK_LABELS[id] ?? id;
}

type EntryType = 'tree' | 'file' | 'submodule';

interface DirEntry {
  name: string;
  path: string;
  type: EntryType;
  ecosystem?: string;
  /** Framework resolved from the folder's manifest (e.g. "nextjs"), when detectable. */
  framework?: string;
  hasDocker?: boolean;
  isLinked?: boolean;
  linkedByProjectName?: string;
}

export interface NodeState {
  loading: boolean;
  entries: DirEntry[] | null;
  expanded: boolean;
  error: string | null;
}

interface RepoTreePickerProps {
  organizationId: string;
  repoFullName: string;
  defaultBranch: string;
  integrationId: string;
  selectedPath: string;
  onSelect: (path: string, ecosystem?: string, framework?: string) => void;
  /** Folder-expansion state, lifted to the parent so it survives the dialog
   * closing/reopening (otherwise every reopen re-collapses and re-fetches). */
  tree: Map<string, NodeState>;
  setTree: Dispatch<SetStateAction<Map<string, NodeState>>>;
  /** Display name for the root row. */
  rootName: string;
  /** Repo-level framework, used to color the root row icon. */
  rootFramework?: string | null;
  /** Repo-level ecosystem, used as a fallback for the root icon. */
  rootEcosystem?: string | null;
  /** True if the repo root contains a Dockerfile / Containerfile / compose file.
   * Populated from the cheap peek so the root row paints a Docker badge without needing
   * the full scan to run. */
  rootDockerized?: boolean;
  /** Ecosystem hints keyed by folder path — used to paint folder framework icons without a backend probe. */
  pathHints?: Record<string, string | undefined>;
  /** Folder paths that have a Dockerfile / docker-compose; renders a small container badge. */
  dockerizedPaths?: string[];
}

export const ROOT_PATH = '';
const INDENT_PX = 16;

/** Fresh tree state — a single collapsed root node. Used by the parent that owns
 * the lifted `tree` state to seed / reset it. */
export function makeInitialTree(): Map<string, NodeState> {
  return new Map([[ROOT_PATH, { loading: false, entries: null, expanded: false, error: null }]]);
}

export function RepoTreePicker({
  organizationId,
  repoFullName,
  defaultBranch,
  integrationId,
  selectedPath,
  onSelect,
  tree,
  setTree,
  rootName,
  rootFramework,
  rootEcosystem,
  rootDockerized,
  pathHints,
  dockerizedPaths,
}: RepoTreePickerProps) {
  const dockerSet = new Set(dockerizedPaths ?? []);
  const abortRef = useRef<AbortController | null>(null);

  // The tree state is owned by the parent (so expansion persists across
  // open/close); we only manage the abort controller here. The parent resets
  // `tree` when the repo identity changes.
  useEffect(() => {
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    return () => {
      abortRef.current?.abort();
    };
  }, [organizationId, repoFullName, defaultBranch, integrationId]);

  async function toggleExpand(path: string) {
    // Decide what to do based on the LATEST tree state (inside the setter), not a
    // render-time snapshot — a rapid second click could otherwise read a stale entry.
    let needsFetch = false;
    setTree((prev) => {
      const current = prev.get(path);
      const next = new Map(prev);
      if (current?.expanded) {
        next.set(path, { ...current, expanded: false });
      } else if (current?.entries) {
        next.set(path, { ...current, expanded: true });
      } else {
        needsFetch = true;
        next.set(path, { loading: true, entries: null, expanded: false, error: null });
      }
      return next;
    });
    if (!needsFetch) return;
    const signal = abortRef.current?.signal;
    try {
      const data = await api.listRepositoryDirectory(
        organizationId,
        repoFullName,
        defaultBranch,
        integrationId,
        path,
        signal ? { signal } : undefined,
      );
      if (signal?.aborted) return;
      const hasChildren = data.entries.some((e) => e.type !== 'file');
      setTree((prev) => {
        const next = new Map(prev);
        next.set(path, { loading: false, entries: data.entries, expanded: hasChildren, error: null });
        return next;
      });
    } catch (err: any) {
      if (signal?.aborted || err?.name === 'AbortError') return;
      setTree((prev) => {
        const next = new Map(prev);
        next.set(path, {
          loading: false,
          entries: null,
          expanded: true,
          error: 'Couldn’t load this folder.',
        });
        return next;
      });
    }
  }

  function RadioDot({ selected }: { selected: boolean }) {
    return (
      <span
        className={cn(
          'h-[18px] w-[18px] rounded-full border-2 flex items-center justify-center flex-shrink-0 transition-colors',
          selected ? 'border-foreground' : 'border-foreground/70',
        )}
      >
        {selected && <span className="h-2 w-2 rounded-full bg-foreground" />}
      </span>
    );
  }

  function renderRow(entry: DirEntry, depth: number) {
    const state = tree.get(entry.path);
    const isSelected = selectedPath === entry.path;
    const isFolder = entry.type === 'tree' || entry.type === 'submodule';
    const disabled = !!entry.isLinked;
    const resolvedEcosystem = entry.ecosystem || pathHints?.[entry.path];
    const resolvedFramework = entry.framework;
    // Prefer the resolved framework (e.g. "nextjs") over the generic ecosystem ("npm") for the badge.
    const badgeId = resolvedFramework || resolvedEcosystem;
    const showDocker = !!entry.hasDocker || dockerSet.has(entry.path);

    return (
      <div key={entry.path}>
        <div
          role="radio"
          aria-checked={isSelected}
          tabIndex={disabled ? -1 : 0}
          aria-disabled={disabled}
          aria-label={entry.name + (disabled && entry.linkedByProjectName ? ` (linked to ${entry.linkedByProjectName})` : '')}
          onClick={() => {
            if (disabled) return;
            onSelect(entry.path, resolvedEcosystem, resolvedFramework);
          }}
          onKeyDown={(e) => {
            if (disabled) return;
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onSelect(entry.path, resolvedEcosystem, resolvedFramework);
            }
          }}
          style={{ paddingLeft: 10 + depth * INDENT_PX }}
          className={cn(
            'group w-full rounded-md pr-3 py-3 flex items-center gap-3 text-left transition-colors',
            disabled
              ? 'opacity-50 cursor-not-allowed'
              : isSelected
                ? 'bg-background-subtle/80 cursor-pointer'
                : 'hover:bg-background-subtle/50 cursor-pointer',
          )}
        >
          {isFolder ? (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                void toggleExpand(entry.path);
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  e.stopPropagation();
                  void toggleExpand(entry.path);
                }
              }}
              className="h-6 w-6 flex items-center justify-center rounded text-foreground/70 hover:text-foreground hover:bg-background-subtle/80 transition-colors flex-shrink-0"
              aria-label={state?.expanded ? 'Collapse folder' : 'Expand folder'}
              aria-expanded={!!state?.expanded}
            >
              {state?.loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <ChevronRight
                  className={cn('h-4 w-4 transition-transform duration-150', state?.expanded && 'rotate-90')}
                />
              )}
            </button>
          ) : (
            <span className="h-6 w-6 flex-shrink-0" />
          )}

          <RadioDot selected={isSelected} />

          <span className="text-[15px] font-medium text-foreground truncate flex-1">{entry.name}</span>

          {disabled ? (
            <span className="flex items-center gap-1 text-xs text-foreground/80 flex-shrink-0">
              <Lock className="h-3.5 w-3.5" />
              {entry.linkedByProjectName || 'Linked'}
            </span>
          ) : (
            <span className="flex items-center gap-2 flex-shrink-0">
              {showDocker && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="flex items-center">
                      <SiDocker className="h-[18px] w-[18px] text-foreground/70" title="" />
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>Container scanning available</TooltipContent>
                </Tooltip>
              )}
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="h-5 w-5 flex-shrink-0 flex items-center justify-center">
                    {badgeId ? (
                      <FrameworkIcon frameworkId={badgeId} size={18} />
                    ) : (
                      <img src="/images/logo_white.png" alt="" className="h-[18px] w-[18px] object-contain block opacity-60" />
                    )}
                  </span>
                </TooltipTrigger>
                <TooltipContent>{frameworkLabel(badgeId)}</TooltipContent>
              </Tooltip>
            </span>
          )}
        </div>

        {isFolder && (
          <div
            className={cn(
              'grid transition-[grid-template-rows] duration-200 ease-out',
              state?.expanded ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]',
            )}
          >
            <div className="overflow-hidden">
              {state?.entries
                ? state.entries
                    .filter((c) => c.type !== 'file')
                    .map((child) => renderRow(child, depth + 1))
                : null}
              {state?.error && (
                <div
                  className="text-xs text-foreground-secondary py-1.5"
                  style={{ paddingLeft: 8 + (depth + 1) * INDENT_PX + 28 }}
                >
                  {state.error}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  }

  const rootState = tree.get(ROOT_PATH);
  const rootSelected = selectedPath === ROOT_PATH;

  return (
    <div className="py-1" role="radiogroup" aria-label="Project root directory">
      <div
        role="radio"
        aria-checked={rootSelected}
        tabIndex={0}
        aria-label={rootName}
        onClick={() => onSelect(ROOT_PATH, rootEcosystem ?? undefined, rootFramework ?? undefined)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onSelect(ROOT_PATH, rootEcosystem ?? undefined, rootFramework ?? undefined);
          }
        }}
        className={cn(
          'group w-full rounded-md px-2.5 py-3 flex items-center gap-3 text-left transition-colors cursor-pointer',
          rootSelected ? 'bg-background-subtle/80' : 'hover:bg-background-subtle/50',
        )}
      >
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            void toggleExpand(ROOT_PATH);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              e.stopPropagation();
              void toggleExpand(ROOT_PATH);
            }
          }}
          className="h-6 w-6 flex items-center justify-center rounded text-foreground/70 hover:text-foreground hover:bg-background-subtle/80 transition-colors flex-shrink-0"
          aria-label={rootState?.expanded ? 'Collapse folder' : 'Expand folder'}
          aria-expanded={!!rootState?.expanded}
        >
          {rootState?.loading && !rootState?.entries ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <ChevronRight
              className={cn('h-4 w-4 transition-transform duration-150', rootState?.expanded && 'rotate-90')}
            />
          )}
        </button>

        <RadioDot selected={rootSelected} />

        <span className="text-[15px] font-medium text-foreground truncate flex-1">{rootName}</span>

        <span className="flex items-center gap-2 flex-shrink-0">
          {(rootDockerized || dockerSet.has(ROOT_PATH)) && (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="flex items-center">
                  <SiDocker className="h-[18px] w-[18px] text-foreground/70" title="" />
                </span>
              </TooltipTrigger>
              <TooltipContent>Container scanning available</TooltipContent>
            </Tooltip>
          )}
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="h-5 w-5 flex-shrink-0 flex items-center justify-center">
                {rootFramework || rootEcosystem ? (
                  <FrameworkIcon frameworkId={rootFramework || rootEcosystem || undefined} size={18} />
                ) : (
                  <img src="/images/logo_white.png" alt="" className="h-[18px] w-[18px] object-contain block opacity-60" />
                )}
              </span>
            </TooltipTrigger>
            <TooltipContent>{frameworkLabel(rootFramework || rootEcosystem)}</TooltipContent>
          </Tooltip>
        </span>
      </div>

      <div
        className={cn(
          'grid transition-[grid-template-rows] duration-200 ease-out',
          rootState?.expanded ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]',
        )}
      >
        <div className="overflow-hidden">
          {rootState?.entries
            ? rootState.entries.filter((e) => e.type !== 'file').map((entry) => renderRow(entry, 1))
            : null}
          {rootState?.error && (
            <div className="text-xs text-foreground-secondary py-1.5" style={{ paddingLeft: 8 + INDENT_PX + 28 }}>
              {rootState.error}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
