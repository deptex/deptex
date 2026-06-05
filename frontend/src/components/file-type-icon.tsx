import {
  SiDocker, SiJavascript, SiTypescript, SiPython, SiGo, SiRust, SiRuby,
  SiPhp, SiOpenjdk, SiKotlin, SiDotnet, SiHtml5, SiCss, SiGnubash,
  SiYaml, SiJson, SiMarkdown, SiTerraform,
} from '@icons-pack/react-simple-icons';
import { FileCode } from 'lucide-react';
import { cn } from '../lib/utils';

// Brand-icon components accept extra SVG props; keep this loose to avoid
// fighting the library's forwardRef prop types.
type IconComp = React.ComponentType<any>;

// Map a file extension (or extensionless well-known basename) to its brand
// logo + a visible accent tint. We render the brand glyph in `currentColor`
// (not the icon's true brand hex) because several brand colours are black
// (Rust, JSON, Markdown) and would vanish on the near-black code header —
// the glyph is what makes each language recognisable, so we keep the shape
// and give it a readable, brand-evocative tint. Only icons confirmed present
// in @icons-pack/react-simple-icons are referenced.
const BY_EXT: Record<string, { Icon: IconComp; tint: string }> = {
  js: { Icon: SiJavascript, tint: 'text-yellow-400' },
  mjs: { Icon: SiJavascript, tint: 'text-yellow-400' },
  cjs: { Icon: SiJavascript, tint: 'text-yellow-400' },
  jsx: { Icon: SiJavascript, tint: 'text-yellow-400' },
  ts: { Icon: SiTypescript, tint: 'text-blue-400' },
  tsx: { Icon: SiTypescript, tint: 'text-blue-400' },
  py: { Icon: SiPython, tint: 'text-sky-400' },
  pyw: { Icon: SiPython, tint: 'text-sky-400' },
  go: { Icon: SiGo, tint: 'text-cyan-400' },
  rs: { Icon: SiRust, tint: 'text-orange-400' },
  rb: { Icon: SiRuby, tint: 'text-red-400' },
  php: { Icon: SiPhp, tint: 'text-indigo-400' },
  java: { Icon: SiOpenjdk, tint: 'text-orange-400' },
  kt: { Icon: SiKotlin, tint: 'text-purple-400' },
  kts: { Icon: SiKotlin, tint: 'text-purple-400' },
  cs: { Icon: SiDotnet, tint: 'text-purple-400' },
  html: { Icon: SiHtml5, tint: 'text-orange-400' },
  htm: { Icon: SiHtml5, tint: 'text-orange-400' },
  css: { Icon: SiCss, tint: 'text-blue-400' },
  sh: { Icon: SiGnubash, tint: 'text-green-400' },
  bash: { Icon: SiGnubash, tint: 'text-green-400' },
  yml: { Icon: SiYaml, tint: 'text-zinc-300' },
  yaml: { Icon: SiYaml, tint: 'text-zinc-300' },
  json: { Icon: SiJson, tint: 'text-amber-300' },
  md: { Icon: SiMarkdown, tint: 'text-zinc-300' },
  markdown: { Icon: SiMarkdown, tint: 'text-zinc-300' },
  tf: { Icon: SiTerraform, tint: 'text-purple-400' },
};

/** Real per-language brand logo for a file path, falling back to a generic
 *  code-file glyph for unmapped types. */
export function FileTypeIcon({ file, size = 14, className }: { file: string; size?: number; className?: string }) {
  const base = (file?.split(/[\\/]/).pop() ?? '').toLowerCase();
  let entry: { Icon: IconComp; tint: string } | undefined;
  if (base === 'dockerfile' || base.startsWith('dockerfile.') || base.endsWith('.dockerfile')) {
    entry = { Icon: SiDocker, tint: 'text-sky-400' };
  } else {
    const ext = base.includes('.') ? base.split('.').pop()! : '';
    entry = BY_EXT[ext];
  }
  if (!entry) {
    return <FileCode size={size} className={cn('text-zinc-400', className)} aria-hidden />;
  }
  const { Icon, tint } = entry;
  return <Icon size={size} className={cn(tint, className)} title="" />;
}
