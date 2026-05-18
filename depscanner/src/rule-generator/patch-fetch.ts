/**
 * Lightweight GitHub patch fetcher for prompt context.
 *
 * The validate.ts module clones the upstream repo at parent + fix SHAs to
 * actually run Semgrep. For the LLM prompt we only need the diff text and
 * the before/after of changed files — no clone needed. We use the
 * `application/vnd.github.diff` accept header to get a unified diff back from
 * `GET /repos/{owner}/{repo}/commits/{sha}`, plus a JSON fetch of the same
 * endpoint for the per-file before/after blob URLs.
 *
 * Auth is optional but recommended — without a token GitHub allows 60
 * unauthenticated requests/hour per IP, which throttles fast on a busy
 * extraction worker. With a token (any GitHub PAT or App installation token)
 * the limit is 5,000/hour.
 */

import type { FixCommit } from './osv-fetch';

const REQUEST_TIMEOUT_MS = 20_000;
const MAX_DIFF_BYTES = 1 * 1024 * 1024; // 1MB diffs are already too large for a useful prompt
const MAX_FILES_TO_RETURN = 8;
const MAX_FILE_BYTES = 64 * 1024;

export interface ChangedFileBlob {
  path: string;
  status: 'added' | 'removed' | 'modified' | 'renamed' | 'unknown';
  before: string | null;
  after: string | null;
  beforeTruncated: boolean;
  afterTruncated: boolean;
}

export interface PatchInfo {
  diff: string;
  diffTruncated: boolean;
  parentSha: string;
  fixSha: string;
  changedFiles: ChangedFileBlob[];
}

export class PatchFetchError extends Error {
  readonly code: 'not_found' | 'no_parent' | 'network' | 'parse' | 'too_large';

  constructor(code: PatchFetchError['code'], message: string) {
    super(message);
    this.name = 'PatchFetchError';
    this.code = code;
  }
}

interface FetchOptions {
  signal?: AbortSignal;
  githubToken?: string;
}

function buildHeaders(accept: string, token?: string): Record<string, string> {
  const h: Record<string, string> = {
    accept,
    'user-agent': 'deptex-extraction-worker',
    'x-github-api-version': '2022-11-28',
  };
  if (token) h.authorization = `Bearer ${token}`;
  return h;
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  outerSignal?: AbortSignal,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  if (outerSignal) {
    if (outerSignal.aborted) controller.abort();
    else outerSignal.addEventListener('abort', () => controller.abort(), { once: true });
  }
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetches both the unified diff and per-file before/after blobs for the
 * given fix commit. Returns a normalized PatchInfo or throws PatchFetchError.
 */
export async function fetchPatchInfo(commit: FixCommit, opts: FetchOptions = {}): Promise<PatchInfo> {
  const { signal, githubToken } = opts;
  const apiBase = `https://api.github.com/repos/${commit.owner}/${commit.repo}/commits/${commit.sha}`;

  // 1) Fetch JSON metadata (parent SHA + per-file blob URLs).
  let metaRes: Response;
  try {
    metaRes = await fetchWithTimeout(apiBase, {
      method: 'GET',
      headers: buildHeaders('application/vnd.github+json', githubToken),
    }, signal);
  } catch (err) {
    throw new PatchFetchError('network', `GitHub commit fetch failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (metaRes.status === 404) {
    throw new PatchFetchError('not_found', `GitHub commit ${commit.owner}/${commit.repo}@${commit.sha} not found`);
  }
  if (!metaRes.ok) {
    throw new PatchFetchError('network', `GitHub commit metadata returned ${metaRes.status}`);
  }
  let meta: unknown;
  try {
    meta = await metaRes.json();
  } catch (err) {
    throw new PatchFetchError('parse', `GitHub commit metadata not JSON: ${err instanceof Error ? err.message : String(err)}`);
  }

  const metaObj = meta as {
    sha?: string;
    parents?: Array<{ sha?: string }>;
    files?: Array<{
      filename?: string;
      status?: string;
      contents_url?: string;
      raw_url?: string;
    }>;
  };

  const parentSha = metaObj.parents?.[0]?.sha;
  if (!parentSha) {
    throw new PatchFetchError('no_parent', `Fix commit ${commit.sha} has no parent — cannot diff`);
  }

  // 2) Fetch unified diff for prompt body.
  let diffRes: Response;
  try {
    diffRes = await fetchWithTimeout(apiBase, {
      method: 'GET',
      headers: buildHeaders('application/vnd.github.diff', githubToken),
    }, signal);
  } catch (err) {
    throw new PatchFetchError('network', `GitHub diff fetch failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!diffRes.ok) {
    throw new PatchFetchError('network', `GitHub diff returned ${diffRes.status}`);
  }
  const fullDiff = await diffRes.text();
  let diff = fullDiff;
  let diffTruncated = false;
  if (diff.length > MAX_DIFF_BYTES) {
    diff = diff.slice(0, MAX_DIFF_BYTES);
    diffTruncated = true;
  }

  // 3) Pick the most informative N files (skip lockfiles + binaries) and
  //    fetch their before/after content. We're after source files the rule
  //    can pattern-match against, so package-lock.json / yarn.lock / .min.js
  //    add no signal.
  const candidateFiles = (metaObj.files ?? []).filter((f) => f.filename && isInterestingPath(f.filename!));
  const picked = candidateFiles.slice(0, MAX_FILES_TO_RETURN);
  const changedFiles: ChangedFileBlob[] = [];

  for (const file of picked) {
    const path = file.filename!;
    const status = mapStatus(file.status);
    const blobs = await fetchFileBlobs({
      owner: commit.owner,
      repo: commit.repo,
      filename: path,
      parentSha,
      fixSha: commit.sha,
      status,
      signal,
      githubToken,
    });
    changedFiles.push({
      path,
      status,
      ...blobs,
    });
  }

  return {
    diff,
    diffTruncated,
    parentSha,
    fixSha: commit.sha,
    changedFiles,
  };
}

function mapStatus(raw: string | undefined): ChangedFileBlob['status'] {
  switch (raw) {
    case 'added':
    case 'removed':
    case 'modified':
    case 'renamed':
      return raw;
    default:
      return 'unknown';
  }
}

const SKIP_PATH_RE = /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Gemfile\.lock|Cargo\.lock|go\.sum|poetry\.lock|requirements\.lock)$/i;
const BINARY_EXT_RE = /\.(?:png|jpg|jpeg|gif|webp|ico|woff2?|ttf|otf|eot|pdf|zip|tar|gz|tgz|class|jar|war|so|dll|exe|wasm|map|min\.js|min\.css)$/i;

function isInterestingPath(p: string): boolean {
  if (SKIP_PATH_RE.test(p)) return false;
  if (BINARY_EXT_RE.test(p)) return false;
  return true;
}

interface FetchBlobsArgs {
  owner: string;
  repo: string;
  filename: string;
  parentSha: string;
  fixSha: string;
  status: ChangedFileBlob['status'];
  signal?: AbortSignal;
  githubToken?: string;
}

async function fetchFileBlobs(args: FetchBlobsArgs): Promise<{
  before: string | null;
  after: string | null;
  beforeTruncated: boolean;
  afterTruncated: boolean;
}> {
  const before = args.status === 'added'
    ? null
    : await fetchRawAtRef(args.owner, args.repo, args.parentSha, args.filename, args.signal, args.githubToken);
  const after = args.status === 'removed'
    ? null
    : await fetchRawAtRef(args.owner, args.repo, args.fixSha, args.filename, args.signal, args.githubToken);

  const truncate = (raw: string | null): { v: string | null; t: boolean } => {
    if (raw === null) return { v: null, t: false };
    if (raw.length <= MAX_FILE_BYTES) return { v: raw, t: false };
    return { v: raw.slice(0, MAX_FILE_BYTES), t: true };
  };

  const b = truncate(before);
  const a = truncate(after);
  return { before: b.v, after: a.v, beforeTruncated: b.t, afterTruncated: a.t };
}

async function fetchRawAtRef(
  owner: string,
  repo: string,
  ref: string,
  filename: string,
  signal?: AbortSignal,
  token?: string,
): Promise<string | null> {
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURI(filename)}?ref=${ref}`;
  let res: Response;
  try {
    res = await fetchWithTimeout(url, {
      method: 'GET',
      headers: buildHeaders('application/vnd.github.raw', token),
    }, signal);
  } catch {
    // A single-file fetch failure is non-fatal — the diff text remains in
    // the prompt; we just lose the surrounding context for this file.
    return null;
  }
  if (res.status === 404) return null;
  if (!res.ok) return null;
  return await res.text();
}
