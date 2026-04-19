export type EcosystemId = 'npm' | 'python' | 'go' | 'java' | 'rust' | 'ruby' | 'dotnet' | 'php';

export interface ManifestPattern {
  ecosystem: EcosystemId;
  filename: string;
  isLockfile: boolean;
}

export const MANIFEST_PATTERNS: ManifestPattern[] = [
  { ecosystem: 'npm', filename: 'package.json', isLockfile: false },
  { ecosystem: 'npm', filename: 'package-lock.json', isLockfile: true },
  { ecosystem: 'npm', filename: 'yarn.lock', isLockfile: true },
  { ecosystem: 'npm', filename: 'pnpm-lock.yaml', isLockfile: true },
  { ecosystem: 'python', filename: 'requirements.txt', isLockfile: false },
  { ecosystem: 'python', filename: 'Pipfile', isLockfile: false },
  { ecosystem: 'python', filename: 'Pipfile.lock', isLockfile: true },
  { ecosystem: 'python', filename: 'pyproject.toml', isLockfile: false },
  { ecosystem: 'python', filename: 'poetry.lock', isLockfile: true },
  { ecosystem: 'python', filename: 'setup.py', isLockfile: false },
  { ecosystem: 'python', filename: 'setup.cfg', isLockfile: false },
  { ecosystem: 'go', filename: 'go.mod', isLockfile: false },
  { ecosystem: 'go', filename: 'go.sum', isLockfile: true },
  { ecosystem: 'java', filename: 'pom.xml', isLockfile: false },
  { ecosystem: 'java', filename: 'build.gradle', isLockfile: false },
  { ecosystem: 'java', filename: 'build.gradle.kts', isLockfile: false },
  { ecosystem: 'java', filename: 'gradle.lockfile', isLockfile: true },
  { ecosystem: 'java', filename: 'settings.gradle', isLockfile: false },
  { ecosystem: 'java', filename: 'settings.gradle.kts', isLockfile: false },
  { ecosystem: 'rust', filename: 'Cargo.toml', isLockfile: false },
  { ecosystem: 'rust', filename: 'Cargo.lock', isLockfile: true },
  { ecosystem: 'ruby', filename: 'Gemfile', isLockfile: false },
  { ecosystem: 'ruby', filename: 'Gemfile.lock', isLockfile: true },
  { ecosystem: 'dotnet', filename: 'Directory.Packages.props', isLockfile: false },
  { ecosystem: 'dotnet', filename: 'packages.config', isLockfile: false },
  { ecosystem: 'dotnet', filename: 'packages.lock.json', isLockfile: true },
  { ecosystem: 'php', filename: 'composer.json', isLockfile: false },
  { ecosystem: 'php', filename: 'composer.lock', isLockfile: true },
];

const MANIFEST_FILENAMES = new Set(MANIFEST_PATTERNS.map(p => p.filename));

const DOTNET_EXTENSIONS = ['.csproj', '.fsproj', '.vbproj'];

export function matchManifestFile(filePath: string): {
  workspace: string;
  manifest: ManifestPattern;
} | null {
  const filename = filePath.includes('/') ? filePath.split('/').pop()! : filePath;

  if (DOTNET_EXTENSIONS.some(ext => filename.endsWith(ext))) {
    const dirPart = filePath.includes('/') ? filePath.slice(0, filePath.lastIndexOf('/')) : '';
    return {
      workspace: dirPart,
      manifest: { ecosystem: 'dotnet', filename, isLockfile: false },
    };
  }

  if (!MANIFEST_FILENAMES.has(filename)) return null;
  const manifest = MANIFEST_PATTERNS.find(p => p.filename === filename);
  if (!manifest) return null;
  const dirPart = filePath.includes('/') ? filePath.slice(0, filePath.lastIndexOf('/')) : '';
  return { workspace: dirPart, manifest };
}

export function detectAffectedWorkspaces(
  changedFiles: string[]
): Map<string, Set<EcosystemId>> {
  const result = new Map<string, Set<EcosystemId>>();
  for (const filePath of changedFiles) {
    const match = matchManifestFile(filePath);
    if (!match) continue;
    if (!result.has(match.workspace)) result.set(match.workspace, new Set());
    result.get(match.workspace)!.add(match.manifest.ecosystem);
  }
  return result;
}

export function isFileInWorkspace(filePath: string, workspace: string): boolean {
  if (workspace === '') return true;
  return filePath.startsWith(workspace + '/');
}
