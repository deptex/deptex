import { useRef, useEffect } from 'react';
import MonacoEditor, { type OnMount, type BeforeMount } from '@monaco-editor/react';
import type { editor, languages, IDisposable, IRange } from 'monaco-editor';

/** Monaco theme extending vs-dark to match Deptex dark UI. */
const DEPTEX_THEME: editor.IStandaloneThemeData = {
  base: 'vs-dark',
  inherit: true,
  rules: [],
  colors: { 'editor.background': '#1A1C1E' },
};

const POLICY_TYPEDEFS = `
/** Asset criticality tier for the project. */
type AssetTier = 'CROWN_JEWELS' | 'EXTERNAL' | 'INTERNAL' | 'NON_PRODUCTION';

/** Supply chain analysis status. */
type AnalysisStatus = 'pass' | 'warning' | 'fail';

/** A known vulnerability affecting a dependency. */
interface Vulnerability {
  /** OSV identifier (e.g. "GHSA-xxxx-xxxx-xxxx"). */
  osv_id: string;
  /** Severity level. */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** CVSS base score (0.0 - 10.0). */
  cvss_score: number;
  /** EPSS exploit prediction score (0.0 - 1.0). Higher = more likely exploited. */
  epss_score: number;
  /** Depscore: composite risk score (0 - 100) combining CVSS, EPSS, KEV, reachability, and asset tier. */
  depscore: number;
  /** Whether the vulnerable code path is reachable from your project's code. */
  is_reachable: boolean;
  /** Whether this CVE is in CISA's Known Exploited Vulnerabilities catalog. */
  cisa_kev: boolean;
  /** Available fix versions, empty if no fix exists yet. */
  fixed_versions: string[];
  /** CVE and other advisory aliases. */
  aliases: string[];
  /** Human-readable vulnerability summary. */
  summary: string;
  /** When the vulnerability was published. */
  published_at: string;
}

/** A dependency in the project with full metadata. */
interface Dependency {
  /** Package name (e.g. "lodash"). */
  name: string;
  /** Installed version (e.g. "4.17.21"). */
  version: string;
  /** SPDX license identifier (e.g. "MIT"). */
  license: string;
  /** Whether this is a direct (true) or transitive (false) dependency. */
  is_direct: boolean;
  /** Environment: "production", "development", etc. */
  environment: string;
  /** Deptex reputation score (0 - 100). */
  score: number;
  /** OpenSSF Scorecard score (0.0 - 10.0). */
  openssf_score: number;
  /** npm weekly download count. */
  weekly_downloads: number;
  /** ISO date when the package was last published. */
  last_published_at: string;
  /** Number of releases in the last 12 months. */
  releases_last_12_months: number;
  /** Number of files in your project that import this package. */
  files_importing_count: number;
  /** Registry integrity check result. */
  registry_integrity_status: AnalysisStatus;
  /** Install scripts (preinstall/postinstall) check result. */
  install_scripts_status: AnalysisStatus;
  /** Entropy analysis (obfuscation detection) check result. */
  entropy_analysis_status: AnalysisStatus;
  /** Known vulnerabilities affecting this dependency version. */
  vulnerabilities: Vulnerability[];
}

/** An updated dependency with previous and new version info. */
interface UpdatedDependency extends Dependency {
  /** The version being replaced. */
  from_version: string;
  /** The new version. Alias for \`version\`. */
  to_version: string;
}

/** A removed dependency (minimal info). */
interface RemovedDependency {
  name: string;
  version: string;
}

/** Project metadata available in policy context. */
interface Project {
  /** Project name. */
  name: string;
  /** Asset criticality tier. */
  asset_tier: AssetTier;
}

/** Context passed to pullRequestCheck(). */
interface PullRequestCheckContext {
  /** The project being checked. */
  project: Project;
  /** Newly added dependencies in this PR. */
  added: Dependency[];
  /** Dependencies whose version changed in this PR. */
  updated: UpdatedDependency[];
  /** Dependencies removed in this PR. */
  removed: RemovedDependency[];
}

/** Context passed to projectCompliance(). */
interface ProjectComplianceContext {
  /** The project being evaluated. */
  project: Project;
  /** All dependencies currently in the project. */
  dependencies: Dependency[];
}

/** Return type for pullRequestCheck(). */
interface PullRequestCheckResult {
  /** Whether the PR passes the policy check. */
  passed: boolean;
  /** List of human-readable violation messages. */
  violations: string[];
}

/** Return type for projectCompliance(). */
interface ComplianceResult {
  /** Whether the project is compliant. */
  compliant: boolean;
  /** List of human-readable violation messages. */
  violations: string[];
}

/**
 * Evaluate dependency changes in a pull request.
 * Return { passed: true } if the PR is acceptable, or { passed: false, violations: [...] } to block.
 */
declare function pullRequestCheck(context: PullRequestCheckContext): PullRequestCheckResult;

/**
 * Evaluate all dependencies for ongoing project compliance.
 * Return { compliant: true } if the project meets policy, or { compliant: false, violations: [...] }.
 */
declare function projectCompliance(context: ProjectComplianceContext): ComplianceResult;
`;

const disposablesRef: IDisposable[] = [];

function cleanupDisposables() {
  while (disposablesRef.length) {
    disposablesRef.pop()?.dispose();
  }
}

const LINE_HEIGHT = 20;
const PADDING = 20;
const MIN_LINES = 1;
const MAX_LINES = 28;

function computeFitHeight(value: string): number {
  const lineCount = Math.max(1, (value.split('\n').length || 1));
  const lines = Math.max(MIN_LINES, lineCount);
  const cappedLines = Math.min(MAX_LINES, lines);
  return cappedLines * LINE_HEIGHT + PADDING;
}

interface PolicyCodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  className?: string;
  minHeight?: string;
  /** When true, height adapts to content instead of using minHeight. */
  fitContent?: boolean;
}

export function PolicyCodeEditor({
  value,
  onChange,
  readOnly = false,
  className = '',
  minHeight = '360px',
  fitContent = false,
}: PolicyCodeEditorProps) {
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);
  const height = fitContent ? `${computeFitHeight(value)}px` : minHeight;

  useEffect(() => {
    return () => cleanupDisposables();
  }, []);

  const handleBeforeMount: BeforeMount = (monaco) => {
    cleanupDisposables();

    monaco.editor.defineTheme('deptex', DEPTEX_THEME);

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

    disposablesRef.push(
      monaco.languages.typescript.javascriptDefaults.addExtraLib(POLICY_TYPEDEFS, 'policy-context.d.ts')
    );

    const completionProvider = monaco.languages.registerCompletionItemProvider('javascript', {
      triggerCharacters: ['.'],
      provideCompletionItems: (model: editor.ITextModel, position: { lineNumber: number; column: number }) => {
        const textUntilPosition = model.getValueInRange({
          startLineNumber: position.lineNumber,
          startColumn: 1,
          endLineNumber: position.lineNumber,
          endColumn: position.column,
        });

        const word = model.getWordUntilPosition(position);
        const range: IRange = {
          startLineNumber: position.lineNumber,
          endLineNumber: position.lineNumber,
          startColumn: word.startColumn,
          endColumn: word.endColumn,
        };

        const suggestions: languages.CompletionItem[] = [];

        if (/context\.\s*$/.test(textUntilPosition)) {
          const ctxFields = [
            { label: 'project', detail: 'Project', doc: 'Project metadata (name, asset_tier).' },
            { label: 'dependencies', detail: 'Dependency[]', doc: 'All project dependencies (projectCompliance).' },
            { label: 'added', detail: 'Dependency[]', doc: 'Newly added dependencies (pullRequestCheck).' },
            { label: 'updated', detail: 'UpdatedDependency[]', doc: 'Updated dependencies (pullRequestCheck).' },
            { label: 'removed', detail: 'RemovedDependency[]', doc: 'Removed dependencies (pullRequestCheck).' },
          ];
          for (const f of ctxFields) {
            suggestions.push({
              label: f.label,
              kind: monaco.languages.CompletionItemKind.Field,
              detail: f.detail,
              documentation: f.doc,
              insertText: f.label,
              range,
            });
          }
          return { suggestions };
        }

        if (/\.project\.\s*$/.test(textUntilPosition)) {
          for (const f of [
            { label: 'name', detail: 'string', doc: 'Project name.' },
            { label: 'asset_tier', detail: 'AssetTier', doc: '"CROWN_JEWELS" | "EXTERNAL" | "INTERNAL" | "NON_PRODUCTION"' },
          ]) {
            suggestions.push({
              label: f.label,
              kind: monaco.languages.CompletionItemKind.Field,
              detail: f.detail,
              documentation: f.doc,
              insertText: f.label,
              range,
            });
          }
          return { suggestions };
        }

        const depFieldPattern = /\.\b(name|version|license|is_direct|environment|score|openssf_score|weekly_downloads|last_published_at|releases_last_12_months|files_importing_count|registry_integrity_status|install_scripts_status|entropy_analysis_status|vulnerabilities)\b/;
        if (/\b(pkg|dep|dependency|d)\.\s*$/.test(textUntilPosition) || /\b(added|updated|removed|dependencies)\b.*\]\.\s*$/.test(textUntilPosition)) {
          const depFields = [
            { label: 'name', detail: 'string', doc: 'Package name.' },
            { label: 'version', detail: 'string', doc: 'Installed version.' },
            { label: 'license', detail: 'string', doc: 'SPDX license identifier.' },
            { label: 'is_direct', detail: 'boolean', doc: 'Direct (true) or transitive (false).' },
            { label: 'environment', detail: 'string', doc: '"production", "development", etc.' },
            { label: 'score', detail: 'number', doc: 'Deptex reputation score (0-100).' },
            { label: 'openssf_score', detail: 'number', doc: 'OpenSSF Scorecard score (0.0-10.0).' },
            { label: 'weekly_downloads', detail: 'number', doc: 'npm weekly download count.' },
            { label: 'last_published_at', detail: 'string', doc: 'ISO date of last publish.' },
            { label: 'releases_last_12_months', detail: 'number', doc: 'Release count in last 12 months.' },
            { label: 'files_importing_count', detail: 'number', doc: 'Files in your project importing this package.' },
            { label: 'registry_integrity_status', detail: 'AnalysisStatus', doc: '"pass" | "warning" | "fail"' },
            { label: 'install_scripts_status', detail: 'AnalysisStatus', doc: '"pass" | "warning" | "fail"' },
            { label: 'entropy_analysis_status', detail: 'AnalysisStatus', doc: '"pass" | "warning" | "fail"' },
            { label: 'vulnerabilities', detail: 'Vulnerability[]', doc: 'Known vulnerabilities for this dependency version.' },
            { label: 'from_version', detail: 'string', doc: 'Previous version (updated deps only).' },
            { label: 'to_version', detail: 'string', doc: 'New version (updated deps only).' },
          ];
          for (const f of depFields) {
            suggestions.push({
              label: f.label,
              kind: monaco.languages.CompletionItemKind.Field,
              detail: f.detail,
              documentation: f.doc,
              insertText: f.label,
              range,
            });
          }
          return { suggestions };
        }

        if (/\b(vuln|v|vulnerability)\.\s*$/.test(textUntilPosition) || depFieldPattern.test('vulnerabilities') && /vulnerabilities.*\]\.\s*$/.test(textUntilPosition)) {
          const vulnFields = [
            { label: 'osv_id', detail: 'string', doc: 'OSV identifier (e.g. "GHSA-xxxx").' },
            { label: 'severity', detail: 'string', doc: '"critical" | "high" | "medium" | "low"' },
            { label: 'cvss_score', detail: 'number', doc: 'CVSS base score (0.0-10.0).' },
            { label: 'epss_score', detail: 'number', doc: 'EPSS exploit prediction (0.0-1.0).' },
            { label: 'depscore', detail: 'number', doc: 'Composite risk score (0-100).' },
            { label: 'is_reachable', detail: 'boolean', doc: 'Whether the vuln code path is reachable.' },
            { label: 'cisa_kev', detail: 'boolean', doc: 'In CISA Known Exploited Vulnerabilities catalog.' },
            { label: 'fixed_versions', detail: 'string[]', doc: 'Available fix versions.' },
            { label: 'aliases', detail: 'string[]', doc: 'CVE and other advisory aliases.' },
            { label: 'summary', detail: 'string', doc: 'Human-readable vulnerability summary.' },
            { label: 'published_at', detail: 'string', doc: 'When the vulnerability was published.' },
          ];
          for (const f of vulnFields) {
            suggestions.push({
              label: f.label,
              kind: monaco.languages.CompletionItemKind.Field,
              detail: f.detail,
              documentation: f.doc,
              insertText: f.label,
              range,
            });
          }
          return { suggestions };
        }

        if (word.word.length > 0) {
          const topLevel = [
            { label: 'pullRequestCheck', detail: '(context) => PullRequestCheckResult', doc: 'Define the PR/merge gate policy function.', snippet: 'function pullRequestCheck(context) {\n\tconst violations = [];\n\t$0\n\treturn { passed: violations.length === 0, violations };\n}' },
            { label: 'projectCompliance', detail: '(context) => ComplianceResult', doc: 'Define the project compliance policy function.', snippet: 'function projectCompliance(context) {\n\tconst violations = [];\n\t$0\n\treturn { compliant: violations.length === 0, violations };\n}' },
          ];
          for (const f of topLevel) {
            suggestions.push({
              label: f.label,
              kind: monaco.languages.CompletionItemKind.Function,
              detail: f.detail,
              documentation: f.doc,
              insertText: f.snippet,
              insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
              range,
            });
          }
        }

        return { suggestions };
      },
    });
    disposablesRef.push(completionProvider);
  };

  const handleMount: OnMount = (editor) => {
    editorRef.current = editor;
  };

  return (
    <div
      className={`w-full overscroll-auto ${className}`}
      style={{
        backgroundColor: '#1A1C1E',
        ...(fitContent ? {} : { minHeight }),
        fontSize: 16,
      }}
    >
      <MonacoEditor
        width="100%"
        height={height}
        language="javascript"
        theme="deptex"
        loading={
          <div
            style={{
              minHeight: height,
              backgroundColor: '#1A1C1E',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#A0A6AD',
              fontSize: 13,
            }}
          >
            Loading...
          </div>
        }
        value={value}
        onChange={(v) => onChange(v ?? '')}
        beforeMount={handleBeforeMount}
        onMount={handleMount}
        options={{
          readOnly,
          theme: 'deptex',
          minimap: { enabled: false },
          fontSize: 13,
          fontFamily: "Consolas, 'Courier New', monospace",
          lineNumbers: 'on',
          lineNumbersMinChars: 2,
          scrollBeyondLastLine: false,
          automaticLayout: true,
          tabSize: 2,
          wordWrap: 'off',
          padding: { top: 10, bottom: 10 },
        }}
      />
    </div>
  );
}
