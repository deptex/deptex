/**
 * Auto-detect an ecosystem from the manifest files present in a workspace.
 *
 * Used by the CLI so `deptex-scan run ./some-repo` doesn't require the
 * caller to pass --ecosystem explicitly. If multiple manifests are present
 * (monorepo root, polyglot project) we pick the first match in
 * ECOSYSTEM_PRIORITY order and let the user override with --ecosystem.
 */

import * as fs from 'fs';
import * as path from 'path';

export type Ecosystem =
  | 'npm'
  | 'pypi'
  | 'maven'
  | 'golang'
  | 'cargo'
  | 'gem'
  | 'composer';

const ECOSYSTEM_MANIFESTS: Array<{ eco: Ecosystem; files: string[] }> = [
  { eco: 'npm', files: ['package.json'] },
  { eco: 'maven', files: ['pom.xml'] },
  { eco: 'golang', files: ['go.mod'] },
  { eco: 'pypi', files: ['pyproject.toml', 'requirements.txt', 'setup.py', 'Pipfile'] },
  { eco: 'cargo', files: ['Cargo.toml'] },
  { eco: 'gem', files: ['Gemfile'] },
  { eco: 'composer', files: ['composer.json'] },
];

export function detectEcosystem(workspacePath: string): Ecosystem | null {
  for (const { eco, files } of ECOSYSTEM_MANIFESTS) {
    for (const f of files) {
      if (fs.existsSync(path.join(workspacePath, f))) {
        return eco;
      }
    }
  }
  return null;
}
