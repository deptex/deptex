import type { CSSProperties } from 'react';

// Shared syntax-highlight theme for react-syntax-highlighter's Prism: near-white
// base text, oneDark token colours, transparent background (so it sits on the
// chat surface / diff-row tints). Used by MarkdownRenderer (fenced code blocks)
// and FileDiffCard (per-line diff highlighting) so code reads the same everywhere.
export const codeTheme: Record<string, CSSProperties> = {
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
