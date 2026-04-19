/**
 * Cursor/IDE-style "JS" language badge — monospace bold, all yellow (not the JS logo).
 */
export function JsLangBadge({ className = '' }: { className?: string }) {
  return (
    <span
      className={`inline-flex items-center justify-center shrink-0 font-mono text-[11px] font-bold leading-none tracking-tight select-none text-yellow-400 ${className}`}
      aria-hidden
    >
      JS
    </span>
  );
}
