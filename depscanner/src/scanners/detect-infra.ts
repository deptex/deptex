import * as fs from 'fs';
import * as path from 'path';
import { IAC_FRAMEWORKS, type IaCFramework } from './types';

// InfraType is structurally IaCFramework — kept as a re-export for callers that
// import the legacy name.
export type InfraType = IaCFramework;

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'depscan-reports',
  'vendor',
  '.next',
  '.terraform',
]);

function shouldSkipDir(name: string): boolean {
  return SKIP_DIRS.has(name) || name.startsWith('.cache');
}

// Hard ceiling on files yielded by a single walk. A malicious repo can't be
// allowed to make the worker enumerate an unbounded tree; 200k comfortably
// covers any legitimate repo.
const MAX_WALK_FILES = 200_000;

function* walk(
  root: string,
  depth = 0,
  maxDepth = 8,
  counter: { n: number } = { n: 0 }
): Generator<string> {
  if (depth > maxDepth) return;
  if (counter.n >= MAX_WALK_FILES) return;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (counter.n >= MAX_WALK_FILES) return;
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      // Never descend into symlinked directories — following them is a
      // path-traversal read primitive on a malicious repo (e.g. a symlink
      // pointing at `/` or `/etc`).
      if (entry.isSymbolicLink()) continue;
      if (shouldSkipDir(entry.name)) continue;
      yield* walk(full, depth + 1, maxDepth, counter);
    } else if (entry.isFile()) {
      counter.n++;
      yield full;
    }
  }
}

function readHead(filePath: string, bytes = 4096): string | null {
  try {
    return fs.readFileSync(filePath, 'utf8').slice(0, bytes);
  } catch {
    return null;
  }
}

function looksLikeKubernetesYaml(filePath: string): boolean {
  const head = readHead(filePath);
  if (!head) return false;
  if (!/^\s*apiVersion\s*:/m.test(head)) return false;
  const kindMatch = head.match(/^\s*kind\s*:\s*([A-Z][A-Za-z0-9]+)/m);
  if (!kindMatch) return false;
  // Ignore generic 'Document' (AsciiDoc front-matter) and empty kind values.
  if (kindMatch[1] === 'Document') return false;
  return true;
}

function looksLikeCloudFormation(filePath: string): boolean {
  const head = readHead(filePath);
  if (!head) return false;
  if (/AWSTemplateFormatVersion\s*[:=]/.test(head)) return true;
  if (/^\s*"?Resources"?\s*:/m.test(head) && /Type\s*[:=]\s*"?AWS::/.test(head)) {
    return true;
  }
  return false;
}

const ARM_SCHEMA_RE =
  /https?:\/\/schema\.management\.azure\.com\/schemas\/[^"'\s]+\/deploymentTemplate\.json/;

function looksLikeArmTemplate(filePath: string): boolean {
  const head = readHead(filePath);
  if (!head) return false;
  return ARM_SCHEMA_RE.test(head);
}

function isHelmChart(base: string): boolean {
  return /^Chart\.ya?ml$/i.test(base);
}

function isKustomizationFile(base: string): boolean {
  return /^kustomization\.ya?ml$/i.test(base);
}

function isServerlessConfig(base: string): boolean {
  return /^serverless\.(ya?ml|json)$/i.test(base);
}

function isBicep(base: string): boolean {
  return /\.bicep$/i.test(base);
}

// Repo-root-only — vendored sub-repos' workflows must not trigger scans
// (MTD-r2-8). Required path shape: `.github/workflows/<file>.{yml,yaml}` with
// no nested directories.
function isGithubActionWorkflow(absPath: string, repoRoot: string): boolean {
  const rel = path.relative(repoRoot, absPath);
  const norm = rel.split(path.sep).join('/');
  if (!norm.startsWith('.github/workflows/')) return false;
  const tail = norm.slice('.github/workflows/'.length);
  if (tail.includes('/')) return false;
  return /\.ya?ml$/i.test(tail);
}

/**
 * Walk the cloned repo and return the set of infra types we should scan.
 *
 * Detection rules — kept conservative; false positives trigger spurious
 * scanner invocations.
 *   - terraform — *.tf / *.tf.json
 *   - kubernetes — apiVersion + non-Document kind in *.yaml/*.yml, OR a
 *     kustomization.yaml file (kustomize tagged as kubernetes — Checkov's
 *     kubernetes framework scans them; no separate kustomize value)
 *   - dockerfile — basename Dockerfile(.<suffix>)?
 *   - helm — basename Chart.yaml (Helm chart root marker)
 *   - cloudformation — AWSTemplateFormatVersion: OR Resources: + Type: AWS::*
 *     in the first 4kb (covers SAM templates via Transform: AWS::Serverless
 *     header). CDK is NOT scanned — it compiles to CFN via `cdk synth` which
 *     we don't run.
 *   - arm — JSON with Azure ARM deploymentTemplate $schema in the first 4kb
 *   - bicep — *.bicep
 *   - serverless — basename serverless.{yml,yaml,json}
 *   - github_actions — files under `.github/workflows/` at the repo root only
 *
 * Pure function: does no DB writes. The pipeline writes projects.infra_types
 * AFTER finalize_extraction returns successfully (architect-f5).
 */
export function detectInfraTypes(repoRoot: string): InfraType[] {
  const found = new Set<InfraType>();
  const target = IAC_FRAMEWORKS.length;

  for (const file of walk(repoRoot)) {
    if (found.size === target) break;
    const base = path.basename(file);

    // Order: specific basename checks first, then extension, then content sniff.
    if (/^Dockerfile(\..+)?$/i.test(base)) {
      found.add('dockerfile');
      continue;
    }
    if (isHelmChart(base)) {
      found.add('helm');
      continue;
    }
    if (isKustomizationFile(base)) {
      found.add('kubernetes');
      continue;
    }
    if (isServerlessConfig(base)) {
      found.add('serverless');
      continue;
    }
    if (isBicep(base)) {
      found.add('bicep');
      continue;
    }
    if (isGithubActionWorkflow(file, repoRoot)) {
      found.add('github_actions');
      continue;
    }
    if (/\.tf(\.json)?$/.test(base)) {
      found.add('terraform');
      continue;
    }
    if (/\.ya?ml$/i.test(base)) {
      if (looksLikeKubernetesYaml(file)) {
        found.add('kubernetes');
        continue;
      }
      if (looksLikeCloudFormation(file)) {
        found.add('cloudformation');
        continue;
      }
    } else if (/\.json$/i.test(base)) {
      if (looksLikeArmTemplate(file)) {
        found.add('arm');
        continue;
      }
      if (looksLikeCloudFormation(file)) {
        found.add('cloudformation');
        continue;
      }
    }
  }

  return Array.from(found).sort();
}

/**
 * Find all Dockerfile paths in the repo. Returned absolute. Used by the
 * Trivy container-scan step to pick a final-stage image to pull.
 */
export function findDockerfiles(repoRoot: string): string[] {
  const out: string[] = [];
  for (const file of walk(repoRoot)) {
    const base = path.basename(file);
    if (/^Dockerfile(\..+)?$/i.test(base)) {
      out.push(file);
    }
  }
  return out;
}
