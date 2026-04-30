import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

// Custom theme: near-white base text, oneDark token colors, transparent bg
const codeTheme: Record<string, React.CSSProperties> = {
  'pre[class*="language-"]': { color: '#e4e4e7', background: 'transparent' },
  'code[class*="language-"]': { color: '#e4e4e7' },
  comment: { color: '#636d83', fontStyle: 'italic' },
  prolog: { color: '#636d83' },
  doctype: { color: '#636d83' },
  cdata: { color: '#636d83' },
  punctuation: { color: '#9ca3af' },
  property: { color: '#e06c75' },
  tag: { color: '#e06c75' },
  boolean: { color: '#d19a66' },
  number: { color: '#d19a66' },
  constant: { color: '#d19a66' },
  symbol: { color: '#d19a66' },
  deleted: { color: '#e06c75' },
  selector: { color: '#98c379' },
  string: { color: '#98c379' },
  char: { color: '#98c379' },
  builtin: { color: '#98c379' },
  inserted: { color: '#98c379' },
  operator: { color: '#56b6c2' },
  url: { color: '#56b6c2' },
  'attr-name': { color: '#d19a66' },
  'attr-value': { color: '#98c379' },
  atrule: { color: '#c678dd' },
  keyword: { color: '#c678dd' },
  function: { color: '#61afef' },
  'class-name': { color: '#e5c07b' },
  regex: { color: '#56b6c2' },
  variable: { color: '#e06c75' },
  bold: { fontWeight: 'bold' },
  italic: { fontStyle: 'italic' },
};

interface MarkdownRendererProps {
  content: string;
}

// Models occasionally emit prose with leading whitespace (4+ spaces or a
// tab), which CommonMark turns into an "indented code block" — the wrapped
// gray block you see when the agent says "I found several critical
// vulnerabilities..." with stray leading indent. Strip leading whitespace
// from any line that isn't inside a fenced code block, isn't a list marker
// continuation, and isn't a blockquote. Preserves intentional structure,
// kills accidental indents that look like code.
function dedentProse(content: string): string {
  const lines = content.split('\n');
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*```/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    // Preserve list items and blockquotes — they need their leading marker
    // (and modest indent) to render correctly.
    if (/^(\s{0,3}[-*+]\s|\s{0,3}\d+\.\s|\s{0,3}>)/.test(line)) continue;
    lines[i] = line.replace(/^[ \t]+/, '');
  }
  return lines.join('\n');
}

function CodeBlock({ language, children }: { language?: string; children: string }) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(children).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="group my-3 relative rounded-xl border border-border overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-background-card-header border-b border-border">
        <span className="text-[11px] font-mono text-foreground/40 select-none">{language ?? 'code'}</span>
        <button
          type="button"
          onClick={copy}
          className="flex items-center gap-1 text-[11px] font-medium text-foreground/40 hover:text-foreground/70 transition-colors"
        >
          {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>

      <SyntaxHighlighter
        style={codeTheme}
        language={language ?? 'text'}
        PreTag="div"
        customStyle={{
          margin: 0,
          borderRadius: 0,
          fontSize: '13px',
          lineHeight: '1.7',
          background: '#050505',
          padding: '1rem 1.125rem',
        }}
      >
        {children}
      </SyntaxHighlighter>
    </div>
  );
}

export function MarkdownRenderer({ content }: MarkdownRendererProps) {
  const normalized = dedentProse(content);
  return (
    <div className="text-sm leading-relaxed text-foreground/90 space-y-3">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          p: ({ children }) => (
            <p className="text-sm leading-relaxed text-foreground/90">{children}</p>
          ),

          h1: ({ children }) => (
            <h1 className="text-base font-semibold text-foreground mt-4 mb-2 first:mt-0">{children}</h1>
          ),
          h2: ({ children }) => (
            <h2 className="text-[15px] font-semibold text-foreground mt-4 mb-2 first:mt-0">{children}</h2>
          ),
          h3: ({ children }) => (
            <h3 className="text-sm font-semibold text-foreground mt-3 mb-1.5 first:mt-0">{children}</h3>
          ),

          ul: ({ children }) => (
            <ul className="list-disc list-outside pl-5 space-y-1 text-foreground/90">{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className="list-decimal list-outside pl-5 space-y-1 text-foreground/90">{children}</ol>
          ),
          li: ({ children }) => (
            <li className="text-sm leading-relaxed">{children}</li>
          ),

          strong: ({ children }) => (
            <strong className="font-semibold text-foreground">{children}</strong>
          ),
          em: ({ children }) => (
            <em className="italic text-foreground/80">{children}</em>
          ),
          a: ({ href, children }) => (
            <a href={href} target="_blank" rel="noreferrer" className="text-blue-400 hover:text-blue-300 underline underline-offset-2">
              {children}
            </a>
          ),

          blockquote: ({ children }) => (
            <blockquote className="border-l-2 border-foreground/20 pl-4 py-0.5 text-foreground/60 italic my-2">
              {children}
            </blockquote>
          ),

          hr: () => <hr className="border-border my-4" />,

          table: ({ children }) => (
            <div className="markdown-table my-4 w-full overflow-x-auto">
              <table className="w-full text-sm border-collapse">{children}</table>
            </div>
          ),
          thead: ({ children }) => (
            <thead className="[&>tr]:border-b [&>tr]:border-foreground/20">{children}</thead>
          ),
          tbody: ({ children }) => (
            <tbody className="[&>tr]:border-b [&>tr]:border-border/50 [&>tr:last-child]:border-b-0">{children}</tbody>
          ),
          tr: ({ children }) => <tr>{children}</tr>,
          th: ({ children }) => (
            <th className="py-2.5 pr-8 text-left text-sm font-semibold text-foreground">
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="py-2.5 pr-8 text-sm text-foreground/80">{children}</td>
          ),

          // Block code: react-markdown always wraps fenced code in <pre><code>.
          // Handling it in `pre` is the reliable way to distinguish from inline.
          pre({ children }) {
            const child = Array.isArray(children) ? children[0] : children;
            if (child && typeof child === 'object' && 'props' in child) {
              const { className, children: code } = (child as any).props;
              const match = /language-(\w+)/.exec(className || '');
              return (
                <CodeBlock language={match?.[1]}>
                  {String(code).replace(/\n$/, '')}
                </CodeBlock>
              );
            }
            return <pre>{children}</pre>;
          },

          // Inline code only (block is handled by `pre` above)
          code({ children }) {
            return (
              <code className="text-[13px] bg-background-subtle text-foreground px-1.5 py-0.5 rounded font-mono">
                {children}
              </code>
            );
          },
        }}
      >
        {normalized}
      </ReactMarkdown>
    </div>
  );
}
