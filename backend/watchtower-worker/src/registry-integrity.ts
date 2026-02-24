import * as pacote from 'pacote';
import * as dircompare from 'dir-compare';
import simpleGit from 'simple-git';
import * as fs from 'fs';
import * as path from 'path';
import { parseRepositoryUrl } from './github';

export interface RegistryIntegrityResult {
  status: 'pass' | 'warning' | 'fail';
  modifiedFiles: Array<{
    path: string;
    reason: string;
  }>;
  tagUsed: string | null;
  npmFilesCount: number;
  gitFilesCount: number;
  error?: string;
}

// Files and directories to ignore during comparison
const IGNORE_PATTERNS = [
  '.git',
  '.gitignore',
  '.npmignore',
  '.npmrc',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'node_modules',
  'dist',
  'build',
  '.DS_Store',
  'Thumbs.db',
  '.github',
  '.circleci',
  '.travis.yml',
  'CHANGELOG.md',
  'CHANGELOG',
  'HISTORY.md',
  'CHANGES.md',
];

/**
 * Check registry integrity by comparing npm tarball vs git source
 * 
 * Steps:
 * 1. Download npm tarball to tmpDir/npm
 * 2. Clone git repo to tmpDir/git
 * 3. Checkout the matching version tag
 * 4. Compare directories using dir-compare
 */
export async function checkRegistryIntegrity(
  packageName: string,
  version: string,
  repoUrl: string | undefined,
  tmpDir: string
): Promise<RegistryIntegrityResult> {
  console.log(`[${new Date().toISOString()}] 🔍 Checking registry integrity for ${packageName}@${version}`);

  const npmDir = path.join(tmpDir, 'npm');
  const gitDir = path.join(tmpDir, 'git');

  try {
    // Step A: Download npm tarball
    console.log(`[${new Date().toISOString()}] 📦 Downloading npm tarball...`);
    fs.mkdirSync(npmDir, { recursive: true });
    
    await pacote.extract(`${packageName}@${version}`, npmDir);
    console.log(`[${new Date().toISOString()}] ✅ npm tarball extracted to ${npmDir}`);

    // Check if we have a repo URL
    if (!repoUrl) {
      console.log(`[${new Date().toISOString()}] ⚠️ No repository URL found, skipping git comparison`);
      return {
        status: 'warning',
        modifiedFiles: [],
        tagUsed: null,
        npmFilesCount: countFiles(npmDir),
        gitFilesCount: 0,
        error: 'No repository URL found in package metadata',
      };
    }

    // Parse the repo URL
    const githubUrl = parseRepositoryUrl(repoUrl);
    if (!githubUrl) {
      console.log(`[${new Date().toISOString()}] ⚠️ Could not parse GitHub URL: ${repoUrl}`);
      return {
        status: 'warning',
        modifiedFiles: [],
        tagUsed: null,
        npmFilesCount: countFiles(npmDir),
        gitFilesCount: 0,
        error: `Could not parse repository URL: ${repoUrl}`,
      };
    }

    // Step B: Clone git repository - fetch only the specific tag we need
    console.log(`[${new Date().toISOString()}] 📂 Cloning git repository...`);
    fs.mkdirSync(gitDir, { recursive: true });
    
    const git = simpleGit();
    const gitInRepo = simpleGit(gitDir);
    
    // Try to clone just the specific tag (much faster than full clone)
    const tagFormats = [`v${version}`, version];
    let tagUsed: string | null = null;
    
    for (const tag of tagFormats) {
      try {
        console.log(`[${new Date().toISOString()}] 🏷️ Trying to clone tag: ${tag}...`);
        await git.clone(githubUrl, gitDir, [
          '--depth', '1',
          '--branch', tag,
          '--single-branch',
        ]);
        tagUsed = tag;
        console.log(`[${new Date().toISOString()}] ✅ Cloned tag ${tag} successfully`);
        break;
      } catch (e: any) {
        // Tag might not exist, try next format
        console.log(`[${new Date().toISOString()}] ⚠️ Tag ${tag} not found, trying next...`);
        // Clean up failed clone attempt
        if (fs.existsSync(gitDir)) {
          fs.rmSync(gitDir, { recursive: true, force: true });
          fs.mkdirSync(gitDir, { recursive: true });
        }
      }
    }

    // Step C: Check if we found a tag
    
    if (!tagUsed) {
      console.log(`[${new Date().toISOString()}] ⚠️ Could not find matching version tag for ${version}`);
      return {
        status: 'warning',
        modifiedFiles: [],
        tagUsed: null,
        npmFilesCount: countFiles(npmDir),
        gitFilesCount: countFiles(gitDir),
        error: `Could not find version tag matching ${version}`,
      };
    }

    console.log(`[${new Date().toISOString()}] ✅ Git repository ready with tag: ${tagUsed}`);

    // Resolve git subpath for monorepos (e.g. React: repository.directory = "packages/react")
    let gitCompareDir = gitDir;
    try {
      const pkgPath = path.join(npmDir, 'package.json');
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const repo = pkg.repository;
        const dir = typeof repo === 'object' && repo && typeof repo.directory === 'string' ? repo.directory : null;
        if (dir) {
          const subPath = path.join(gitDir, dir.replace(/^\/+|\/+$/g, '').replace(/\//g, path.sep));
          if (fs.existsSync(subPath)) {
            gitCompareDir = subPath;
            console.log(`[${new Date().toISOString()}] 📁 Comparing to monorepo subpath: ${dir}`);
          }
        }
      }
    } catch (_) {
      // ignore; compare to repo root
    }

    // Step D: Compare directories
    console.log(`[${new Date().toISOString()}] 🔄 Comparing npm tarball vs git source...`);
    const modifiedFiles = await compareDirectories(npmDir, gitCompareDir);

    // Status: fail only on "only in npm" that are suspicious; build-artifact-only = warning.
    const suspiciousOnlyInNpm = modifiedFiles.filter(f => f.reason === REASON_ONLY_IN_NPM);
    const onlyInNpmBuildArtifact = modifiedFiles.filter(f => f.reason === REASON_ONLY_IN_NPM_BUILD_ARTIFACT);
    const contentDiffers = modifiedFiles.filter(f => f.reason === REASON_CONTENT_DIFFERS);

    let status: 'pass' | 'warning' | 'fail' = 'pass';
    if (suspiciousOnlyInNpm.length > 0) {
      status = 'fail';
      console.log(`[${new Date().toISOString()}] 📊 Registry integrity: fail (${suspiciousOnlyInNpm.length} file(s) in npm but NOT in git - possible supply chain risk)`);
    } else if (onlyInNpmBuildArtifact.length > 0) {
      status = 'warning';
      console.log(`[${new Date().toISOString()}] 📊 Registry integrity: warning (${onlyInNpmBuildArtifact.length} file(s) in npm but NOT in git - likely build artifacts e.g. cjs/umd/esm)`);
    } else if (contentDiffers.length > 0) {
      status = 'warning';
      console.log(`[${new Date().toISOString()}] 📊 Registry integrity: warning (${contentDiffers.length} file(s) differ from git - may be build artifacts)`);
    } else {
      console.log(`[${new Date().toISOString()}] 📊 Registry integrity: pass`);
    }

    return {
      status,
      modifiedFiles,
      tagUsed,
      npmFilesCount: countFiles(npmDir),
      gitFilesCount: countFiles(gitDir),
    };
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Registry integrity check failed:`, error.message);
    return {
      status: 'fail',
      modifiedFiles: [],
      tagUsed: null,
      npmFilesCount: 0,
      gitFilesCount: 0,
      error: error.message,
    };
  }
}

/** Reason used when a file exists only in npm (suspicious - possible supply chain risk) */
export const REASON_ONLY_IN_NPM = 'File in npm tarball but NOT in git source (possible supply chain risk)';
/** Reason when file is only in npm but path looks like build output (cjs/umd/esm, *.production.js, etc.) */
export const REASON_ONLY_IN_NPM_BUILD_ARTIFACT = 'File in npm but not in git (likely build artifact)';
const REASON_CONTENT_DIFFERS = 'Content differs between npm tarball and git source';

/** Path prefixes that commonly indicate built output (generated at publish, not committed to git) */
const BUILD_OUTPUT_DIRS = ['cjs/', 'umd/', 'esm/', 'es/', 'amd/'];

/** Filename suffixes that indicate built/minified variants (e.g. React's .development.js, .production.js, .shared-subset.js) */
const BUILD_OUTPUT_SUFFIXES = ['.development.js', '.production.js', '.profiling.js', '.min.js', '.min.mjs', '.development.mjs', '.production.mjs', '.shared-subset.js', '.shared-subset.mjs'];

/** Root-level entry/stub filenames that are often build outputs or re-exports (e.g. React's index.js, jsx-runtime.js) */
const BUILD_ENTRY_FILES = new Set([
  'index.js', 'index.mjs', 'compiler-runtime.js', 'jsx-runtime.js', 'jsx-dev-runtime.js',
  'jsx-runtime.react-server.js', 'jsx-dev-runtime.react-server.js', 'react.react-server.js',
]);

/** Doc/license filenames that are often only in npm (packaging) and not a supply chain risk */
const HARMLESS_ONLY_IN_NPM_FILES = new Set(['license', 'license.md', 'readme.md', 'readme']);

/**
 * Classify an "only in npm" path: returns REASON_ONLY_IN_NPM (suspicious → fail) or
 * REASON_ONLY_IN_NPM_BUILD_ARTIFACT (likely build output → warning). Exported for tests.
 */
export function classifyOnlyInNpmPath(relativePath: string): string {
  return isLikelyBuildArtifact(relativePath) ? REASON_ONLY_IN_NPM_BUILD_ARTIFACT : REASON_ONLY_IN_NPM;
}

/**
 * Returns true if the path looks like a build artifact (e.g. cjs/, umd/, or *.production.js).
 * These often exist only in npm because they're generated at publish time from source in the repo.
 */
function isLikelyBuildArtifact(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/').replace(/^\/+/, '');
  const lower = normalized.toLowerCase();
  const segments = lower.split('/').filter(Boolean);
  const firstSegment = segments[0] ?? '';
  if (BUILD_OUTPUT_DIRS.some(d => firstSegment === d.replace('/', '') || lower.startsWith(d))) return true;
  const base = segments[segments.length - 1] ?? '';
  if (BUILD_OUTPUT_SUFFIXES.some(s => base.toLowerCase().endsWith(s))) return true;
  // Root-level entry/stub files (single segment) that are typical build outputs
  if (segments.length === 1 && BUILD_ENTRY_FILES.has(base)) return true;
  // Doc/license files often only in npm tarball (packaging difference, not malicious)
  if (segments.length === 1 && HARMLESS_ONLY_IN_NPM_FILES.has(base)) return true;
  return false;
}

/**
 * Compare two directories and return list of modified files.
 * Reports two cases that matter for security:
 * 1. File only in npm (left): CRITICAL - possible injected malware → we fail.
 * 2. File in both but content differs: may be build artifacts or tampering → we warn only.
 */
async function compareDirectories(
  npmDir: string,
  gitDir: string
): Promise<Array<{ path: string; reason: string }>> {
  const modifiedFiles: Array<{ path: string; reason: string }> = [];

  try {
    const options: dircompare.Options = {
      compareContent: true,
      compareSize: true,
      excludeFilter: IGNORE_PATTERNS.join(','),
    };

    const result = await dircompare.compare(npmDir, gitDir, options);
    // dircompare: left = first dir (npm), right = second dir (git)

    for (const diff of result.diffSet || []) {
      const relativePath = diff.relativePath
        ? path.join(diff.relativePath, diff.name1 || diff.name2 || '')
        : (diff.name1 || diff.name2 || '');

      if (shouldIgnorePath(relativePath)) continue;

      // File exists ONLY in npm (not in git): fail if suspicious, warning if likely build artifact
      if (diff.state === 'left' && diff.type1 === 'file') {
        modifiedFiles.push({
          path: relativePath,
          reason: isLikelyBuildArtifact(relativePath) ? REASON_ONLY_IN_NPM_BUILD_ARTIFACT : REASON_ONLY_IN_NPM,
        });
        continue;
      }

      // File in both but content differs (could be build artifacts or tampering)
      if (diff.state === 'distinct' && diff.type1 === 'file' && diff.type2 === 'file') {
        modifiedFiles.push({
          path: relativePath,
          reason: REASON_CONTENT_DIFFERS,
        });
      }
      // We do NOT fail on "right" (only in git) - packages often publish a subset.
    }
  } catch (error: any) {
    console.warn(`[${new Date().toISOString()}] ⚠️ Directory comparison error:`, error.message);
  }

  return modifiedFiles;
}

/**
 * Check if a path should be ignored
 */
function shouldIgnorePath(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
  
  for (const pattern of IGNORE_PATTERNS) {
    if (normalizedPath.includes(pattern.toLowerCase())) {
      return true;
    }
  }
  
  return false;
}

/**
 * Count files in a directory recursively
 */
function countFiles(dir: string): number {
  if (!fs.existsSync(dir)) return 0;
  
  let count = 0;
  const items = fs.readdirSync(dir);
  
  for (const item of items) {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);
    
    if (stat.isDirectory()) {
      if (!IGNORE_PATTERNS.includes(item)) {
        count += countFiles(fullPath);
      }
    } else {
      count++;
    }
  }
  
  return count;
}
