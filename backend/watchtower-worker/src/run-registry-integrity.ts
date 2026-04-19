/**
 * Run the real registry integrity check on a single package@version.
 * Uses the same logic as the worker (registry-integrity.ts).
 *
 * Usage:
 *   npx tsx src/run-registry-integrity.ts [package] [version]
 *   npx tsx src/run-registry-integrity.ts axios 1.13.5
 *   npx tsx src/run-registry-integrity.ts
 *     (defaults: axios@1.13.5)
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { checkRegistryIntegrity } from './registry-integrity';

const PACKAGE = process.argv[2] ?? 'axios';
const VERSION = process.argv[3] ?? '1.13.5';

function createTempDir(prefix: string): string {
  const dir = path.join(os.tmpdir(), `watchtower-${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

async function main() {
  console.log(`\n🔍 Registry integrity check: ${PACKAGE}@${VERSION}\n`);

  const tmpDir = createTempDir(`${PACKAGE}-${VERSION.replace(/\./g, '-')}`);

  try {
    const encodedName = encodeURIComponent(PACKAGE);
    const response = await fetch(`https://registry.npmjs.org/${encodedName}`);
    if (!response.ok) throw new Error(`npm registry returned ${response.status}`);
    const packageData = await response.json() as {
      repository?: string | { url?: string };
    };
    const rawRepository = typeof packageData.repository === 'string'
      ? packageData.repository
      : (packageData.repository as any)?.url || undefined;

    if (!rawRepository) {
      console.log('⚠️ No repository URL in package metadata. Running check anyway (will return warning).\n');
    } else {
      console.log(`📂 Repository: ${rawRepository}\n`);
    }

    const result = await checkRegistryIntegrity(PACKAGE, VERSION, rawRepository, tmpDir);

    console.log('\n' + '─'.repeat(60));
    console.log('RESULT');
    console.log('─'.repeat(60));
    console.log(`Status:        ${result.status.toUpperCase()}`);
    console.log(`Tag used:      ${result.tagUsed ?? '(none)'}`);
    console.log(`npm files:     ${result.npmFilesCount}`);
    console.log(`git files:     ${result.gitFilesCount}`);
    console.log(`Modified:      ${result.modifiedFiles.length} file(s)`);
    if (result.error) console.log(`Error:         ${result.error}`);

    if (result.modifiedFiles.length > 0) {
      const maxShow = 40;
      console.log(`\nFirst ${Math.min(maxShow, result.modifiedFiles.length)} differing file(s):`);
      result.modifiedFiles.slice(0, maxShow).forEach((f, i) => {
        console.log(`  ${(i + 1).toString().padStart(2)} ${f.path}`);
      });
      if (result.modifiedFiles.length > maxShow) {
        console.log(`  ... and ${result.modifiedFiles.length - maxShow} more`);
      }
    }
    console.log('');
  } finally {
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      console.log('🧹 Cleaned up temp directory.\n');
    }
  }
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
