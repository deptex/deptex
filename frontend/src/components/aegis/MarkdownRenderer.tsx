import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface MarkdownRendererProps {
  content: string;
}

export function MarkdownRenderer({ content }: MarkdownRendererProps) {
  return (
    <div className="prose prose-sm prose-invert max-w-none text-sm leading-relaxed text-foreground/90
      prose-p:my-2 prose-p:text-foreground/90
      prose-headings:text-foreground prose-headings:font-semibold prose-headings:mt-4 prose-headings:mb-2
      prose-h1:text-base prose-h2:text-[15px] prose-h3:text-sm
      prose-strong:text-foreground prose-strong:font-semibold
      prose-ul:my-2 prose-ol:my-2 prose-li:my-0.5
      prose-code:text-foreground prose-code:bg-background-subtle prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-[13px] prose-code:before:content-none prose-code:after:content-none
      prose-pre:bg-transparent prose-pre:p-0 prose-pre:my-3
      prose-a:text-blue-400 hover:prose-a:text-blue-300 prose-a:no-underline hover:prose-a:underline
      prose-blockquote:border-l-border prose-blockquote:text-foreground/70
      prose-table:text-[13px] prose-th:text-foreground prose-td:border-border prose-th:border-border">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          code(props: any) {
            const { inline, className, children, ...rest } = props;
            const match = /language-(\w+)/.exec(className || '');
            if (!inline && match) {
              return (
                <SyntaxHighlighter
                  style={oneDark as any}
                  language={match[1]}
                  PreTag="div"
                  customStyle={{
                    margin: 0,
                    borderRadius: '0.5rem',
                    fontSize: '13px',
                    background: 'rgb(24 24 27)',
                  }}
                >
                  {String(children).replace(/\n$/, '')}
                </SyntaxHighlighter>
              );
            }
            return <code className={className} {...rest}>{children}</code>;
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
