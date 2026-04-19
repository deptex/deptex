/**
 * Resolves lib module path (legacy: EE modules are now merged into backend/src/lib).
 * Kept for any remaining dynamic imports; resolves to local lib.
 */
import path from 'path';

export function getEeModulePath(relativePath: string): string {
  return path.join(__dirname, relativePath);
}
