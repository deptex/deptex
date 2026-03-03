/**
 * Runtime path for EE modules. Uses a non-literal path so that when CE code does
 * await import(getEeModulePath('aegis/tasks')), TypeScript does not pull ee/ into
 * the backend build (rootDir stays backend/src only).
 */
const EE_LIB = process.env.DEPTEX_EE_LIB ?? '../../../ee/backend/lib';

export function getEeModulePath(relativePath: string): string {
  return `${EE_LIB}/${relativePath}`;
}
