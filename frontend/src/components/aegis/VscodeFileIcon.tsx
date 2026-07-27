import { useEffect, useState } from 'react';
import { cn } from '../../lib/utils';

// A VSCode-style file icon (Material Icon Theme, via `material-file-icons`) — the
// colourful, purpose-drawn file icons you see in VSCode/Cursor, not brand logos.
// getIcon() handles special filenames (package.json, Dockerfile, tsconfig.json…)
// exactly like the editor. The icon set is ~475kB, so we lazy-`import()` it: the
// bundler code-splits it into its own chunk that's only fetched the first time a
// file icon actually renders (task chats), keeping it out of the initial load.
// The module caches after the first load, so subsequent icons resolve instantly.

export function VscodeFileIcon({
  file,
  size = 16,
  className,
}: {
  file: string;
  size?: number;
  className?: string;
}) {
  const [svg, setSvg] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    import('material-file-icons')
      .then((m) => {
        if (alive) setSvg(m.getIcon(file || 'file').svg);
      })
      .catch(() => {
        /* leave empty — the header still shows the filename */
      });
    return () => {
      alive = false;
    };
  }, [file]);

  return (
    <span
      aria-hidden
      className={cn('inline-flex shrink-0 items-center justify-center [&>svg]:h-full [&>svg]:w-full', className)}
      style={{ width: size, height: size }}
      {...(svg ? { dangerouslySetInnerHTML: { __html: svg } } : {})}
    />
  );
}
