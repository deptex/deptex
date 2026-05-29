import { MANIFEST_FILES, MANIFEST_EXTENSIONS, IGNORED_DIRS, ECOSYSTEM_DEFAULTS, detectFrameworkForEcosystem } from './ecosystems';

/** Minimal provider interface for monorepo detection (avoids coupling to ee git-provider). */
export interface MonorepoGitProvider {
  getFileContent(repo: string, filePath: string, ref: string): Promise<string>;
  getTreeRecursive(repo: string, ref: string): Promise<{ entries: Array<{ path: string; type: string }>; truncated: boolean }>;
  getRootContents(repo: string, ref: string): Promise<Array<{ path: string; type: string }>>;
}

export type MonorepoConfidence = 'high' | 'medium';

export interface PotentialProject {
  name: string;
  path: string;
  ecosystem: string;
  manifestFile: string;
}

export interface DetectMonorepoResult {
  isMonorepo: boolean;
  confidence?: MonorepoConfidence;
  potentialProjects: PotentialProject[];
  /** True when the provider returned a truncated tree (provider-side entry/size cap
   * or our pagination/depth cap). Detection is incomplete; show a warning. */
  treeTruncated?: boolean;
}

/** True if any path segment matches an ignored directory name. Segment match (not substring)
 * so `not_node_modules/Dockerfile` and `vendor-extras/foo` aren't dropped. */
function isPathIgnored(path: string): boolean {
  const segments = path.split('/');
  return IGNORED_DIRS.some((d) => segments.includes(d));
}

/** Suffixes that mean the file is a template/doc/backup, not a buildable Dockerfile. */
const DOCKERFILE_TEMPLATE_SUFFIXES = new Set([
  'j2', 'template', 'tpl', 'tmpl', 'in', 'example', 'sample',
  'md', 'txt', 'rst', 'bak', 'orig', 'swp', 'old', 'disabled',
]);

/** True if the file is a deployable Dockerfile/Containerfile/compose file.
 * Single source of truth shared by `findDockerizedPaths` (full scan), `peekRepoRoot`
 * (cheap root peek), and the `/list-dir` per-layer probe. Accepts `Dockerfile.<env>`
 * variants (Dockerfile.prod, etc.) and the Compose Spec v2 default filenames. */
export function isDockerFile(fileName: string): boolean {
  if (fileName === 'Dockerfile' || fileName === 'Containerfile') return true;
  const lower = fileName.toLowerCase();
  // Dockerfile.<env> — allow environment-style suffixes, reject template/doc suffixes.
  if (lower.startsWith('dockerfile.')) {
    const suffix = lower.slice('dockerfile.'.length);
    if (!suffix || suffix.includes('.')) return false;
    return !DOCKERFILE_TEMPLATE_SUFFIXES.has(suffix);
  }
  // docker-compose.yml / docker-compose.<env>.yml (legacy).
  if (lower === 'docker-compose.yml' || lower === 'docker-compose.yaml') return true;
  if (/^docker-compose\.[^.]+\.ya?ml$/.test(lower)) return true;
  // compose.yaml / compose.yml / compose.<env>.yml (Compose Specification v2 default).
  if (lower === 'compose.yml' || lower === 'compose.yaml') return true;
  if (/^compose\.[^.]+\.ya?ml$/.test(lower)) return true;
  return false;
}

/** Root-level filenames that strongly suggest a monorepo workspace. */
const MONOREPO_ROOT_MARKERS = new Set([
  'pnpm-workspace.yaml',
  'lerna.json',
  'nx.json',
  'rush.json',
  'turbo.json',
]);

export interface RepoPeek {
  framework: string;
  ecosystem: string;
  hasRootManifest: boolean;
  /** Heuristic: root contains a workspace marker (pnpm-workspace, lerna.json, nx.json, etc.)
   * or top-level `apps/` / `packages/` directories. Used to decide whether to pre-warm the
   * full monorepo scan in the background. */
  looksLikeMonorepo: boolean;
  /** Root contains a Dockerfile / Containerfile / compose file. */
  rootDockerized: boolean;
}

/**
 * Cheap root-only peek for the create-project picker. At most one root-contents call
 * plus one manifest file read — typically ~200–500ms vs the full scan's 5–10s on big
 * repos. The full `detectMonorepo` + `findDockerizedPaths` walk is deferred to when the
 * user actually opens the path picker.
 */
export async function peekRepoRoot(
  provider: MonorepoGitProvider,
  repoFullName: string,
  defaultBranch: string,
): Promise<RepoPeek> {
  const rootFiles = await provider.getRootContents(repoFullName, defaultBranch);
  const rootBlobNames = new Set<string>();
  const rootTreeNames = new Set<string>();
  for (const f of rootFiles) {
    const name = f.path.split('/').pop() || f.path;
    if (f.type === 'blob') rootBlobNames.add(name);
    else if (f.type === 'tree') rootTreeNames.add(name);
  }

  let framework = 'unknown';
  let ecosystem = 'unknown';
  let hasRootManifest = false;

  // Exact-name manifest match in priority order (MANIFEST_FILES insertion order).
  for (const [fileName, eco] of Object.entries(MANIFEST_FILES)) {
    if (!rootBlobNames.has(fileName)) continue;
    hasRootManifest = true;
    ecosystem = eco;
    try {
      const content = await provider.getFileContent(repoFullName, fileName, defaultBranch);
      framework = detectFrameworkForEcosystem(eco, content);
    } catch {
      framework = ECOSYSTEM_DEFAULTS[eco] || 'unknown';
    }
    break;
  }

  // Extension-based manifest fallback (.csproj etc. — name varies, content rules don't apply).
  if (!hasRootManifest) {
    for (const name of rootBlobNames) {
      const dotIdx = name.lastIndexOf('.');
      if (dotIdx === -1) continue;
      const eco = MANIFEST_EXTENSIONS[name.slice(dotIdx)];
      if (!eco) continue;
      hasRootManifest = true;
      ecosystem = eco;
      framework = ECOSYSTEM_DEFAULTS[eco] || 'unknown';
      break;
    }
  }

  let looksLikeMonorepo = false;
  for (const marker of MONOREPO_ROOT_MARKERS) {
    if (rootBlobNames.has(marker)) { looksLikeMonorepo = true; break; }
  }
  if (!looksLikeMonorepo && (rootTreeNames.has('apps') || rootTreeNames.has('packages'))) {
    looksLikeMonorepo = true;
  }

  let rootDockerized = false;
  for (const name of rootBlobNames) {
    if (isDockerFile(name)) { rootDockerized = true; break; }
  }

  return { framework, ecosystem, hasRootManifest, looksLikeMonorepo, rootDockerized };
}

/**
 * Walk the repo tree and return the set of directory paths that contain a Dockerfile,
 * Containerfile, or docker-compose / compose.yaml file at their root. Used to flag rows
 * that will have container-scan coverage so the picker can show a Docker badge next to them.
 */
export async function findDockerizedPaths(
  provider: MonorepoGitProvider,
  repoFullName: string,
  defaultBranch: string,
): Promise<{ paths: string[]; truncated: boolean }> {
  try {
    const { entries, truncated } = await provider.getTreeRecursive(repoFullName, defaultBranch);
    const dirs = new Set<string>();
    for (const node of entries) {
      if (node.type !== 'blob') continue;
      if (isPathIgnored(node.path)) continue;
      const fileName = node.path.split('/').pop() || '';
      if (!isDockerFile(fileName)) continue;
      const dirPath = node.path === fileName ? '' : node.path.slice(0, -(fileName.length + 1));
      dirs.add(dirPath);
    }
    return { paths: [...dirs], truncated };
  } catch {
    return { paths: [], truncated: false };
  }
}

/** Match directory path against a glob like 'packages/*' or 'apps/*'. */
function matchGlob(dirPath: string, pattern: string): boolean {
  const normalized = pattern.replace(/\/\*$/, '');
  if (pattern.endsWith('/*')) {
    return dirPath === normalized || (dirPath.startsWith(normalized + '/') && !dirPath.slice(normalized.length + 1).includes('/'));
  }
  return dirPath === pattern || dirPath.startsWith(pattern + '/');
}

/** Parse pnpm-workspace.yaml or package.json workspaces into list of glob patterns. */
function getWorkspaceGlobs(yamlOrJson: { packages?: string[]; workspaces?: string[] | { packages?: string[] } }): string[] {
  const packages = yamlOrJson.packages;
  if (Array.isArray(packages)) return packages;
  const workspaces = (yamlOrJson as { workspaces?: string[] | { packages?: string[] } }).workspaces;
  if (Array.isArray(workspaces)) return workspaces;
  if (workspaces && typeof workspaces === 'object' && Array.isArray(workspaces.packages)) return workspaces.packages;
  return [];
}

/** From tree entries, get unique directory paths that contain a package.json (path = dir, no trailing slash; root = ''). */
function getPackageJsonDirsFromTree(tree: Array<{ path: string; type: string }>): Array<{ dirPath: string; filePath: string }> {
  const dirs: Array<{ dirPath: string; filePath: string }> = [];
  for (const node of tree) {
    if (node.type !== 'blob' || !node.path.endsWith('package.json')) continue;
    if (isPathIgnored(node.path)) continue;
    const dirPath = node.path === 'package.json' ? '' : node.path.slice(0, -'package.json'.length).replace(/\/$/, '');
    dirs.push({ dirPath, filePath: node.path });
  }
  return dirs;
}

/** From tree entries, find directories containing any registered manifest file. */
function getManifestDirsFromTree(
  tree: Array<{ path: string; type: string }>
): Array<{ dirPath: string; filePath: string; ecosystem: string }> {
  const dirs: Array<{ dirPath: string; filePath: string; ecosystem: string }> = [];
  const seen = new Set<string>();

  for (const node of tree) {
    if (node.type !== 'blob') continue;
    if (isPathIgnored(node.path)) continue;

    const fileName = node.path.split('/').pop() || '';
    const ext = fileName.includes('.') ? fileName.slice(fileName.lastIndexOf('.')) : '';
    const ecosystem = MANIFEST_FILES[fileName] || MANIFEST_EXTENSIONS[ext];
    if (!ecosystem) continue;

    const dirPath = node.path === fileName ? '' : node.path.slice(0, -(fileName.length + 1));
    const key = `${dirPath}::${ecosystem}`;
    if (seen.has(key)) continue;
    seen.add(key);

    dirs.push({ dirPath, filePath: node.path, ecosystem });
  }
  return dirs;
}

async function getPackageName(
  provider: MonorepoGitProvider,
  repoFullName: string,
  ref: string,
  filePath: string
): Promise<string> {
  try {
    const content = await provider.getFileContent(repoFullName, filePath, ref);
    const pkg = JSON.parse(content) as { name?: string };
    return typeof pkg.name === 'string' ? pkg.name : '';
  } catch {
    return '';
  }
}

/** Simple YAML parse for pnpm-workspace (only need packages: [...]). */
function parsePnpmWorkspaceYaml(content: string): string[] {
  const lines = content.split('\n');
  let inPackages = false;
  const patterns: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('packages:')) {
      inPackages = true;
      const rest = trimmed.slice(8).trim();
      if (rest.startsWith('[')) {
        const arr = rest.slice(1).replace(/\]/, '').split(',').map((s) => s.trim().replace(/^['"]|['"]$/g, ''));
        patterns.push(...arr);
      }
      continue;
    }
    if (inPackages && (trimmed.startsWith('- ') || trimmed.includes('-'))) {
      const item = trimmed.replace(/^-\s*/, '').trim().replace(/^['"]|['"]$/g, '');
      if (item) patterns.push(item);
    } else if (trimmed && !trimmed.startsWith(' ') && !trimmed.startsWith('\t')) {
      inPackages = false;
    }
  }
  return patterns;
}

/**
 * Detect monorepo and return potential projects.
 * Accepts a GitProvider so it works for GitHub, GitLab, and Bitbucket.
 */
export async function detectMonorepo(
  provider: MonorepoGitProvider,
  repoFullName: string,
  defaultBranch: string
): Promise<DetectMonorepoResult> {
  const rootFiles = await provider.getRootContents(repoFullName, defaultBranch);
  const rootNames = new Set(rootFiles.map((f) => f.path.split('/').pop() || f.path));

  // 1) pnpm-workspace.yaml (high confidence -- npm monorepo)
  if (rootNames.has('pnpm-workspace.yaml')) {
    try {
      const yamlContent = await provider.getFileContent(repoFullName, 'pnpm-workspace.yaml', defaultBranch);
      const globs = parsePnpmWorkspaceYaml(yamlContent);
      if (globs.length > 0) {
        const { entries: tree, truncated } = await provider.getTreeRecursive(repoFullName, defaultBranch);
        const allDirs = getPackageJsonDirsFromTree(tree);
        const matched = allDirs.filter(({ dirPath }) => globs.some((g) => matchGlob(dirPath, g)));
        const potentialProjects: PotentialProject[] = [];
        for (const { dirPath, filePath } of matched) {
          const name = await getPackageName(provider, repoFullName, defaultBranch, filePath)
            || (dirPath ? dirPath.split('/').pop()! : 'root');
          potentialProjects.push({ name, path: dirPath, ecosystem: 'npm', manifestFile: 'package.json' });
        }
        const hasRoot = allDirs.some(({ dirPath }) => dirPath === '');
        if (hasRoot && !potentialProjects.some((p) => p.path === '')) {
          const rootName = await getPackageName(provider, repoFullName, defaultBranch, 'package.json') || 'root';
          potentialProjects.unshift({ name: rootName, path: '', ecosystem: 'npm', manifestFile: 'package.json' });
        }
        return {
          isMonorepo: potentialProjects.length > 1,
          confidence: 'high',
          potentialProjects: potentialProjects.length > 0 ? potentialProjects : (await fallbackTreeScan(provider, repoFullName, defaultBranch)).potentialProjects,
          treeTruncated: truncated,
        };
      }
    } catch {
      // Fall through to next check
    }
  }

  // 2) package.json workspaces (high confidence -- npm monorepo)
  if (rootNames.has('package.json')) {
    try {
      const pkgContent = await provider.getFileContent(repoFullName, 'package.json', defaultBranch);
      const pkg = JSON.parse(pkgContent) as { workspaces?: string[] | { packages?: string[] }; name?: string };
      const globs = getWorkspaceGlobs(pkg);
      if (globs.length > 0) {
        const { entries: tree, truncated } = await provider.getTreeRecursive(repoFullName, defaultBranch);
        const allDirs = getPackageJsonDirsFromTree(tree);
        const matched = allDirs.filter(({ dirPath }) => globs.some((g) => matchGlob(dirPath, g)));
        const potentialProjects: PotentialProject[] = [];
        for (const { dirPath, filePath } of matched) {
          const name = await getPackageName(provider, repoFullName, defaultBranch, filePath)
            || (dirPath ? dirPath.split('/').pop()! : 'root');
          potentialProjects.push({ name, path: dirPath, ecosystem: 'npm', manifestFile: 'package.json' });
        }
        const hasRoot = allDirs.some(({ dirPath }) => dirPath === '');
        if (hasRoot && !potentialProjects.some((p) => p.path === '')) {
          const rootName = (pkg.name as string) || await getPackageName(provider, repoFullName, defaultBranch, 'package.json') || 'root';
          potentialProjects.unshift({ name: rootName, path: '', ecosystem: 'npm', manifestFile: 'package.json' });
        }
        return {
          isMonorepo: potentialProjects.length > 1,
          confidence: 'high',
          potentialProjects: potentialProjects.length > 0 ? potentialProjects : (await fallbackTreeScan(provider, repoFullName, defaultBranch)).potentialProjects,
          treeTruncated: truncated,
        };
      }
    } catch {
      // Fall through
    }
  }

  // 3) Fallback: scan all manifest types (medium confidence)
  return fallbackTreeScan(provider, repoFullName, defaultBranch);
}

async function fallbackTreeScan(
  provider: MonorepoGitProvider,
  repoFullName: string,
  defaultBranch: string
): Promise<DetectMonorepoResult> {
  const { entries: tree, truncated } = await provider.getTreeRecursive(repoFullName, defaultBranch);
  const allDirs = getManifestDirsFromTree(tree);
  const potentialProjects: PotentialProject[] = [];
  for (const { dirPath, filePath, ecosystem } of allDirs) {
    let name = '';
    if (ecosystem === 'npm') {
      name = await getPackageName(provider, repoFullName, defaultBranch, filePath);
    }
    if (!name) {
      name = dirPath ? dirPath.split('/').pop()! : 'root';
    }
    const manifestFile = filePath.split('/').pop() || filePath;
    potentialProjects.push({ name, path: dirPath, ecosystem, manifestFile });
  }
  potentialProjects.sort((a, b) => (a.path === '' ? -1 : b.path === '' ? 1 : 0));
  return {
    isMonorepo: potentialProjects.length > 1,
    confidence: potentialProjects.length > 1 ? 'medium' : undefined,
    potentialProjects,
    treeTruncated: truncated,
  };
}
