import type { GitProvider } from './git-provider';
import { MANIFEST_FILES, MANIFEST_EXTENSIONS, IGNORED_DIRS } from './ecosystems';

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
    if (node.path.includes('node_modules')) continue;
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
    if (IGNORED_DIRS.some((d) => node.path.includes(d + '/'))) continue;

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
  provider: GitProvider,
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
  provider: GitProvider,
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
        const tree = await provider.getTreeRecursive(repoFullName, defaultBranch);
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
        const tree = await provider.getTreeRecursive(repoFullName, defaultBranch);
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
  provider: GitProvider,
  repoFullName: string,
  defaultBranch: string
): Promise<DetectMonorepoResult> {
  const tree = await provider.getTreeRecursive(repoFullName, defaultBranch);
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
  return {
    isMonorepo: potentialProjects.length > 1,
    confidence: potentialProjects.length > 1 ? 'medium' : undefined,
    potentialProjects,
  };
}
