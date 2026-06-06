import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { CodeSnippetBlock } from './VulnerabilityOrgSidebarExpandedContent';

/**
 * Compact markdown renderer for vulnerability advisory text (GHSA / OSV
 * `details`). These blobs are real markdown — headings, lists, inline code,
 * links, GFM tables, and the occasional fenced PoC block — which we were
 * previously dumping as raw text (literal `###`, ``` fences, pipe tables).
 *
 * Deliberately lighter than the Aegis `MarkdownRenderer`: small type, no copy
 * buttons or syntax highlighter, scrollable code fences. Tuned to sit inside an
 * expanded finding row, so headings collapse to a single small-bold weight and
 * code blocks stay quiet.
 */
export function AdvisoryMarkdown({ content }: { content: string }) {
  return (
    <div className="text-xs leading-relaxed text-foreground-secondary space-y-2 [overflow-wrap:anywhere]">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          p: ({ children }) => <p className="text-xs leading-relaxed text-foreground-secondary">{children}</p>,
          // Advisory headings are noisy at full size — flatten them all to one
          // compact bold line so the text reads as prose, not a document.
          h1: ({ children }) => <p className="text-xs font-semibold text-foreground mt-2 first:mt-0">{children}</p>,
          h2: ({ children }) => <p className="text-xs font-semibold text-foreground mt-2 first:mt-0">{children}</p>,
          h3: ({ children }) => <p className="text-xs font-semibold text-foreground mt-2 first:mt-0">{children}</p>,
          h4: ({ children }) => <p className="text-xs font-semibold text-foreground mt-2 first:mt-0">{children}</p>,
          ul: ({ children }) => <ul className="list-disc list-outside pl-4 space-y-0.5">{children}</ul>,
          ol: ({ children }) => <ol className="list-decimal list-outside pl-4 space-y-0.5">{children}</ol>,
          li: ({ children }) => <li className="text-xs leading-relaxed">{children}</li>,
          strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
          em: ({ children }) => <em className="italic">{children}</em>,
          a: ({ href, children }) => (
            <a
              href={href}
              target="_blank"
              rel="noreferrer"
              className="text-blue-400 hover:text-blue-300 underline underline-offset-2 break-words"
              onClick={(e) => e.stopPropagation()}
            >
              {children}
            </a>
          ),
          blockquote: ({ children }) => (
            <blockquote className="border-l-2 border-border pl-3 text-foreground-muted italic">{children}</blockquote>
          ),
          hr: () => <hr className="border-border my-2" />,
          table: ({ children }) => (
            <div className="my-2 w-full overflow-x-auto custom-scrollbar">
              <table className="w-full text-[11px] border-collapse">{children}</table>
            </div>
          ),
          th: ({ children }) => (
            <th className="py-1 pr-4 text-left font-semibold text-foreground border-b border-border">{children}</th>
          ),
          td: ({ children }) => <td className="py-1 pr-4 align-top border-b border-border/50">{children}</td>,
          // Pull the raw code + language out of the child <code> and render the
          // muted reachability-style CodeSnippetBlock (line numbers, subdued
          // tokens) — deliberately quieter than the loud Aegis chat block. The
          // synthetic `snippet.<ext>` file just drives prism language detection.
          pre: ({ children }) => {
            const child = Array.isArray(children) ? children[0] : children;
            if (child && typeof child === 'object' && 'props' in child) {
              const { className, children: code } = (child as { props: { className?: string; children?: unknown } }).props;
              const match = /language-(\w+)/.exec(className ?? '');
              const text = String(code ?? '').replace(/\n$/, '');
              return (
                <div className="my-2 rounded-lg border border-border overflow-hidden">
                  <CodeSnippetBlock file={`snippet.${match?.[1] ?? 'txt'}`} code={text} />
                </div>
              );
            }
            return <pre className="whitespace-pre-wrap">{children}</pre>;
          },
          // Only reached for inline code (block code text is consumed by `pre`).
          code: ({ children }) => (
            <code className="rounded bg-background-subtle px-1 py-px font-mono text-[11px] text-foreground break-words">
              {children}
            </code>
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
