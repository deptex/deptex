/**
 * Slim Monaco beforeMount for policy language + deptex theme (no hover/completion).
 * Used by PolicyDiffCodeEditor. PolicyCodeEditor calls this then adds extraLib + providers.
 */
import type { languages } from 'monaco-editor';

export const CODE_BLOCK_BG = '#0a0a0a';

export const DEPTEX_THEME = {
  base: 'vs-dark' as const,
  inherit: true,
  rules: [] as [],
  colors: {
    'editor.background': CODE_BLOCK_BG,
    'editorGutter.background': CODE_BLOCK_BG,
    'editorLineNumber.foreground': '#525252',
    'editorLineNumber.activeForeground': '#a1a1a1',
    'diffEditor.insertedTextBackground': '#2ea04333',
    'diffEditor.removedTextBackground': '#f8514933',
    'diffEditor.insertedLineBackground': '#2ea04322',
    'diffEditor.removedLineBackground': '#f8514922',
  },
};

export const POLICY_LANGUAGE_ID = 'deptex-policy';

/** Minimal monarch matching PolicyCodeEditor (keywords + strings + comments). */
export const POLICY_MONARCH: languages.IMonarchLanguage = {
  defaultToken: 'source',
  tokenPostfix: '.js',
  brackets: [
    { open: '{', close: '}', token: 'delimiter.curly' },
    { open: '[', close: ']', token: 'delimiter.square' },
    { open: '(', close: ')', token: 'delimiter.parenthesis' },
  ],
  keywords: [
    'function', 'return', 'const', 'let', 'var', 'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
    'true', 'false', 'null', 'undefined', 'in', 'of', 'new', 'typeof', 'instanceof', 'delete', 'void',
    'try', 'catch', 'finally', 'throw', 'async', 'await',
  ],
  operators: ['=', '>', '<', '!', '~', '?', ':', '==', '<=', '>=', '!=', '&&', '||', '++', '--', '+', '-', '*', '/', '&', '|', '^', '%', '=>'],
  symbols: /[=><!~?:&|+\-*\/\^%]+/,
  escapes: /\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,
  tokenizer: {
    root: [
      [/[a-zA-Z_$][\w$]*/, { cases: { '@keywords': 'keyword', '@default': 'identifier' } }],
      [/[ \t\r\n]+/, ''],
      [/[{}()\[\]]/, '@brackets'],
      [/@symbols/, { cases: { '@operators': 'operator', '@default': '' } }],
      [/\d*\.\d+([eE][\-+]?\d+)?/, 'number.float'],
      [/0[xX][0-9a-fA-F]+/, 'number.hex'],
      [/\d+/, 'number'],
      [/[;,.]/, 'delimiter'],
      [/"([^"\\]|\\.)*$/, 'string.invalid'],
      [/"/, 'string', '@string_double'],
      [/'([^'\\]|\\.)*$/, 'string.invalid'],
      [/'/, 'string', '@string_single'],
      [/\/\*/, 'comment', '@comment_block'],
      [/\/\/.*$/, 'comment'],
    ],
    string_double: [
      [/[^\\"]+/, 'string'],
      [/@escapes/, 'string.escape'],
      [/\\./, 'string.escape.invalid'],
      [/"/, 'string', '@pop'],
    ],
    string_single: [
      [/[^\\']+/, 'string'],
      [/@escapes/, 'string.escape'],
      [/\\./, 'string.escape.invalid'],
      [/'/, 'string', '@pop'],
    ],
    comment_block: [
      [/[^\/*]+/, 'comment'],
      [/\/\*/, 'comment', '@push'],
      [/\*\//, 'comment', '@pop'],
      [/[\/*]/, 'comment'],
    ],
  },
};

// Monaco instance from @monaco-editor/react beforeMount; typescript defaults exist at runtime
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type MonacoBeforeMount = any;

export function beforeMountPolicyMonaco(monaco: MonacoBeforeMount): void {
  monaco.editor.defineTheme('deptex', DEPTEX_THEME as import('monaco-editor').editor.IStandaloneThemeData);

  if (!monaco.languages.getLanguages().some((l: { id: string }) => l.id === POLICY_LANGUAGE_ID)) {
    monaco.languages.register({ id: POLICY_LANGUAGE_ID });
    monaco.languages.setMonarchTokensProvider(POLICY_LANGUAGE_ID, POLICY_MONARCH);
  }

  monaco.languages.typescript.javascriptDefaults.setDiagnosticsOptions({
    noSemanticValidation: true,
    noSyntaxValidation: false,
  });

  monaco.languages.typescript.javascriptDefaults.setCompilerOptions({
    target: monaco.languages.typescript.ScriptTarget.ESNext,
    allowNonTsExtensions: true,
    allowJs: true,
    checkJs: false,
  });
}
