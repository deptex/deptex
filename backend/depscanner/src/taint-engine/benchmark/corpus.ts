/**
 * Benchmark corpus loader for the M8 atom A/B harness.
 *
 * The corpus is a JSON file that points at one or more JS/TS projects (local
 * paths or git repos with optional refs) and lists, per project, the CVE
 * findings the harness expects each engine to recover. We intentionally keep
 * the format separate from the Phase 5 corpus type so the harness works
 * before that code lands on main: loaders adapt one to the other.
 *
 * Shape:
 *   {
 *     "name": "phase5-88cve",            // human label for the report
 *     "ecosystems": ["npm"],             // (optional) ecosystem hint
 *     "projects": [
 *       {
 *         "id": "deptex-test-npm",
 *         "ecosystem": "npm",
 *         "path": "C:/Coding/Deptex/test-npm",
 *         "expectedFindings": [
 *           {
 *             "cve": "CVE-2021-23337",
 *             "vulnClass": "command_injection",
 *             "sinkFile": "src/index.js",
 *             "sinkPattern": "_.template"
 *           }
 *         ]
 *       }
 *     ]
 *   }
 *
 * The schema is deliberately tolerant — fields the harness doesn't recognize
 * are passed through to the report so callers can annotate corpus entries.
 */

import * as fs from 'fs';
import * as path from 'path';

export interface ExpectedFinding {
  /** Identifier for the expected vuln (CVE id, GHSA, or arbitrary tag). */
  cve: string;
  /** Vulnerability class — used to bucket recall on the report. */
  vulnClass?: string;
  /**
   * Optional sink file (relative to project root). When set, the comparator
   * also requires that the matched flow's sink_file ends with this path.
   * When unset, any flow on the project that touches the right vuln class
   * counts as a hit.
   */
  sinkFile?: string;
  /** Optional substring/exact match the sink_method or sink_pattern must contain. */
  sinkPattern?: string;
}

export interface BenchmarkProject {
  /** Stable id for the report. */
  id: string;
  /** npm | pypi | maven | gomod — used for engine routing + dep-scan -t flag. */
  ecosystem: string;
  /** Local filesystem path. Mutually exclusive with `git`. */
  path?: string;
  /** Git URL. Cloned to `<workspaceRoot>/<id>` if `path` is unset. */
  git?: string;
  /** Optional git ref (commit/tag/branch). Defaults to default branch. */
  ref?: string;
  /** Findings the corpus author expects each engine to recover. */
  expectedFindings: ExpectedFinding[];
  /** Free-form metadata; passed through to the report. */
  meta?: Record<string, unknown>;
}

export interface BenchmarkCorpus {
  name: string;
  ecosystems?: string[];
  projects: BenchmarkProject[];
}

export class CorpusLoadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CorpusLoadError';
  }
}

/** Read a JSON corpus file from disk, validate, return the typed shape. */
export function loadCorpus(corpusPath: string): BenchmarkCorpus {
  let raw: string;
  try {
    raw = fs.readFileSync(path.resolve(corpusPath), 'utf8');
  } catch (err) {
    throw new CorpusLoadError(`failed to read corpus at ${corpusPath}: ${(err as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new CorpusLoadError(`corpus at ${corpusPath} is not valid JSON: ${(err as Error).message}`);
  }
  return validateCorpus(parsed);
}

export function validateCorpus(input: unknown): BenchmarkCorpus {
  if (!isObject(input)) throw new CorpusLoadError('corpus root must be an object');
  const name = expectString(input, 'name', 'corpus');
  const projectsRaw = (input as Record<string, unknown>).projects;
  if (!Array.isArray(projectsRaw) || projectsRaw.length === 0) {
    throw new CorpusLoadError('corpus.projects must be a non-empty array');
  }
  const projects = projectsRaw.map((p, i) => validateProject(p, `projects[${i}]`));
  const ecosystems = Array.isArray((input as Record<string, unknown>).ecosystems)
    ? (input as Record<string, unknown>).ecosystems as string[]
    : undefined;
  return { name, ecosystems, projects };
}

function validateProject(input: unknown, fieldPath: string): BenchmarkProject {
  if (!isObject(input)) throw new CorpusLoadError(`${fieldPath} must be an object`);
  const id = expectString(input, 'id', fieldPath);
  const ecosystem = expectString(input, 'ecosystem', fieldPath);
  const projPath = (input as Record<string, unknown>).path;
  const git = (input as Record<string, unknown>).git;
  const ref = (input as Record<string, unknown>).ref;
  if (typeof projPath !== 'string' && typeof git !== 'string') {
    throw new CorpusLoadError(`${fieldPath}: must specify either "path" or "git"`);
  }
  if (typeof projPath === 'string' && typeof git === 'string') {
    throw new CorpusLoadError(`${fieldPath}: specify exactly one of "path" or "git", not both`);
  }
  const findingsRaw = (input as Record<string, unknown>).expectedFindings;
  if (!Array.isArray(findingsRaw)) {
    throw new CorpusLoadError(`${fieldPath}.expectedFindings must be an array (use [] for projects without expected hits)`);
  }
  const expectedFindings = findingsRaw.map((f, i) => validateExpectedFinding(f, `${fieldPath}.expectedFindings[${i}]`));
  const meta = isObject((input as Record<string, unknown>).meta)
    ? ((input as Record<string, unknown>).meta as Record<string, unknown>)
    : undefined;
  return {
    id,
    ecosystem,
    path: typeof projPath === 'string' ? projPath : undefined,
    git: typeof git === 'string' ? git : undefined,
    ref: typeof ref === 'string' ? ref : undefined,
    expectedFindings,
    meta,
  };
}

function validateExpectedFinding(input: unknown, fieldPath: string): ExpectedFinding {
  if (!isObject(input)) throw new CorpusLoadError(`${fieldPath} must be an object`);
  const cve = expectString(input, 'cve', fieldPath);
  const vc = (input as Record<string, unknown>).vulnClass;
  const sf = (input as Record<string, unknown>).sinkFile;
  const sp = (input as Record<string, unknown>).sinkPattern;
  return {
    cve,
    vulnClass: typeof vc === 'string' ? vc : undefined,
    sinkFile: typeof sf === 'string' ? sf : undefined,
    sinkPattern: typeof sp === 'string' ? sp : undefined,
  };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function expectString(obj: Record<string, unknown>, key: string, fieldPath: string): string {
  const v = obj[key];
  if (typeof v !== 'string' || v.length === 0) {
    throw new CorpusLoadError(`${fieldPath}.${key} must be a non-empty string`);
  }
  return v;
}
