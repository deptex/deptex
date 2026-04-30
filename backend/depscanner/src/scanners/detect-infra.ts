import * as fs from 'fs';
import * as path from 'path';

export type InfraType = 'terraform' | 'kubernetes' | 'dockerfile';

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

function* walk(root: string, depth = 0, maxDepth = 8): Generator<string> {
  if (depth > maxDepth) return;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (shouldSkipDir(entry.name)) continue;
      yield* walk(full, depth + 1, maxDepth);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

function looksLikeKubernetesYaml(filePath: string): boolean {
  try {
    const head = fs.readFileSync(filePath, 'utf8').slice(0, 4096);
    if (!/^\s*apiVersion\s*:/m.test(head)) return false;
    const kindMatch = head.match(/^\s*kind\s*:\s*([A-Z][A-Za-z0-9]+)/m);
    if (!kindMatch) return false;
    // Ignore generic 'Document' (AsciiDoc front-matter) and empty kind values.
    if (kindMatch[1] === 'Document') return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Walk the cloned repo and return the set of infra types we should scan.
 *
 * Detection rules (kept conservative — false positives are worse than false
 * negatives because each infra type triggers a separate scanner invocation):
 *   - terraform — any *.tf or *.tf.json under the repo
 *   - kubernetes — *.yaml/*.yml whose first 4kb has both `apiVersion:` and a
 *     non-`Document` `kind:` value
 *   - dockerfile — any file whose basename matches /^Dockerfile(\..+)?$/i
 *
 * Pure function: does no DB writes. The pipeline writes projects.infra_types
 * AFTER finalize_extraction returns successfully (architect-f5).
 */
export function detectInfraTypes(repoRoot: string): InfraType[] {
  const found = new Set<InfraType>();

  for (const file of walk(repoRoot)) {
    if (found.size === 3) break;
    const base = path.basename(file);

    if (/^Dockerfile(\..+)?$/i.test(base)) {
      found.add('dockerfile');
      continue;
    }
    if (/\.tf(\.json)?$/.test(base)) {
      found.add('terraform');
      continue;
    }
    if (/\.ya?ml$/i.test(base) && looksLikeKubernetesYaml(file)) {
      found.add('kubernetes');
      continue;
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
