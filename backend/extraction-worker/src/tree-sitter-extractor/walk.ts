import * as fs from 'fs';
import * as path from 'path';

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'target', 'out',
  '.next', '.nuxt', '.turbo', '.cache', 'coverage',
  '.vscode', '.idea', '__pycache__', '.venv', 'venv', 'env',
  '.mypy_cache', '.pytest_cache', '.tox', 'vendor',
]);

export function walkSourceFiles(root: string, supports: (filePath: string) => boolean): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name.startsWith('.git')) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name)) continue;
        walk(full);
      } else if (entry.isFile() && supports(full)) {
        out.push(full);
      }
    }
  };
  walk(root);
  return out;
}
