/**
 * Tests for osv-fetch.ts — the OSV.dev advisory fetcher.
 *
 * The pure helpers (parseGithubCommitUrl, extractFixCommits,
 * summarizeAffectedRange) are tested in rule-generator.test.ts. This file
 * pins the network paths: 200 success, 404 alias-hop, 5xx → typed error,
 * malformed body → parse error, alias-loop depth cap, timeout, and the
 * COMMIT_URL_RE / REPO_URL_RE bounds that are the only SSRF defense
 * against attacker-controlled OSV reference URLs.
 */
import {
  fetchOsvAdvisory,
  OsvFetchError,
  extractFixCommits,
  parseGithubCommitUrl,
  type OsvAdvisory,
} from '../rule-generator/osv-fetch';

const realFetch = global.fetch;

afterEach(() => {
  global.fetch = realFetch;
  jest.restoreAllMocks();
});

function makeJsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(headers),
    text: async () => JSON.stringify(body),
    json: async () => body,
  } as unknown as Response;
}

function makeStringResponse(text: string, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => text,
    json: async () => {
      try {
        return JSON.parse(text);
      } catch (err) {
        throw err;
      }
    },
  } as unknown as Response;
}

const minimalOsvBody = {
  id: 'CVE-2024-1234',
  aliases: ['GHSA-aaaa-bbbb-cccc'],
  summary: 'Test summary',
  details: 'Test details',
  affected: [],
  references: [],
};

describe('fetchOsvAdvisory', () => {
  it('returns the parsed advisory on a 200', async () => {
    const fetchMock = jest.fn().mockResolvedValue(makeJsonResponse(minimalOsvBody));
    global.fetch = fetchMock as any;

    const result = await fetchOsvAdvisory('CVE-2024-1234');

    expect(result).not.toBeNull();
    expect(result!.id).toBe('CVE-2024-1234');
    expect(result!.aliases).toEqual(['GHSA-aaaa-bbbb-cccc']);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toBe('https://api.osv.dev/v1/vulns/CVE-2024-1234');
  });

  it('URL-encodes the cveId', async () => {
    // No injection vector exists today (CVE ids don't contain `/` or
    // unusual chars), but pinning encodeURIComponent here closes the door
    // on a future caller passing a typo with `/` and ending up at a
    // different OSV path.
    const fetchMock = jest.fn().mockResolvedValue(makeJsonResponse(minimalOsvBody));
    global.fetch = fetchMock as any;

    await fetchOsvAdvisory('CVE-2024-1234/etc/passwd');

    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toContain('%2F');
    expect(calledUrl).not.toContain('/etc/passwd');
  });

  it('rejects empty cveId', async () => {
    await expect(fetchOsvAdvisory('')).rejects.toThrow(OsvFetchError);
    await expect(fetchOsvAdvisory('   ')).rejects.toThrow(/empty/);
  });

  it('alias-hops on 404 with a `Bug not found, but the following aliases were:` body', async () => {
    const fetchMock = jest.fn()
      // First call: 404 with alias hint
      .mockResolvedValueOnce(makeJsonResponse(
        { code: 5, message: 'Bug not found, but the following aliases were: GHSA-vvvv-wwww-xxxx' },
        404,
      ))
      // Second call: alias resolves
      .mockResolvedValueOnce(makeJsonResponse({ ...minimalOsvBody, id: 'GHSA-vvvv-wwww-xxxx' }));
    global.fetch = fetchMock as any;

    const result = await fetchOsvAdvisory('CVE-2099-9999');

    expect(result).not.toBeNull();
    expect(result!.id).toBe('GHSA-vvvv-wwww-xxxx');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect((fetchMock.mock.calls[1][0] as string)).toContain('GHSA-vvvv-wwww-xxxx');
  });

  it('caps alias-hop at depth=1 (no infinite loops)', async () => {
    // First 404 -> hop to GHSA-A. Second 404 -> hop to GHSA-B. Without the
    // depth cap, we'd recurse forever on a circular alias chain. The cap
    // returns null after the second 404.
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(makeJsonResponse(
        { message: 'Bug not found, but the following aliases were: GHSA-aaaa-bbbb-cccc' },
        404,
      ))
      .mockResolvedValueOnce(makeJsonResponse(
        { message: 'Bug not found, but the following aliases were: GHSA-dddd-eeee-ffff' },
        404,
      ))
      // Should never be called — the depth cap stops recursion before this.
      .mockResolvedValueOnce(makeJsonResponse(minimalOsvBody));
    global.fetch = fetchMock as any;

    const result = await fetchOsvAdvisory('CVE-9999-9999');

    expect(result).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('returns null on 404 without a parseable alias message', async () => {
    const fetchMock = jest.fn().mockResolvedValue(makeJsonResponse({ message: 'just a 404' }, 404));
    global.fetch = fetchMock as any;

    const result = await fetchOsvAdvisory('CVE-2099-9999');

    expect(result).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('returns null when the alias matches the original id (self-loop guard)', async () => {
    const fetchMock = jest.fn().mockResolvedValue(makeJsonResponse(
      { message: 'Bug not found, but the following aliases were: CVE-2024-1234' },
      404,
    ));
    global.fetch = fetchMock as any;

    const result = await fetchOsvAdvisory('CVE-2024-1234');

    expect(result).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('throws OsvFetchError(network) on 5xx', async () => {
    const fetchMock = jest.fn().mockResolvedValue(makeJsonResponse({ error: 'down' }, 503));
    global.fetch = fetchMock as any;

    await expect(fetchOsvAdvisory('CVE-2024-1234')).rejects.toMatchObject({
      name: 'OsvFetchError',
      code: 'network',
    });
  });

  it('throws OsvFetchError(network) when fetch itself rejects (DNS, connection refused, etc.)', async () => {
    const fetchMock = jest.fn().mockRejectedValue(new Error('ENOTFOUND api.osv.dev'));
    global.fetch = fetchMock as any;

    await expect(fetchOsvAdvisory('CVE-2024-1234')).rejects.toMatchObject({
      name: 'OsvFetchError',
      code: 'network',
    });
  });

  it('throws OsvFetchError(parse) on non-JSON body', async () => {
    const fetchMock = jest.fn().mockResolvedValue(makeStringResponse('<html>error</html>'));
    global.fetch = fetchMock as any;

    await expect(fetchOsvAdvisory('CVE-2024-1234')).rejects.toMatchObject({
      name: 'OsvFetchError',
      code: 'parse',
    });
  });

  it('throws OsvFetchError(parse) when body is JSON but missing id', async () => {
    const fetchMock = jest.fn().mockResolvedValue(makeJsonResponse({ aliases: [] }));
    global.fetch = fetchMock as any;

    await expect(fetchOsvAdvisory('CVE-2024-1234')).rejects.toMatchObject({
      name: 'OsvFetchError',
      code: 'parse',
    });
  });

  it('forwards an outer abort signal', async () => {
    const fetchMock = jest.fn().mockImplementation((_url: string, init: RequestInit) => {
      return new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => reject(new Error('aborted')));
      });
    });
    global.fetch = fetchMock as any;

    const controller = new AbortController();
    const promise = fetchOsvAdvisory('CVE-2024-1234', controller.signal);
    controller.abort();
    await expect(promise).rejects.toThrow();
  });
});

describe('parseGithubCommitUrl — SSRF guard', () => {
  // The COMMIT_URL_RE regex is the ONLY thing standing between an
  // attacker-published OSV `references[].url` and the worker's outbound
  // GitHub fetch. If this regex loosens, an attacker can point the worker at
  // the AWS metadata service or an internal IP. These tests pin the regex
  // boundary so any future loosening trips a test.

  it('accepts canonical github.com commit URLs', () => {
    expect(parseGithubCommitUrl('https://github.com/owner/repo/commit/abc1234567890def1234567890abcdef12345678')).toMatchObject({
      owner: 'owner',
      repo: 'repo',
      sha: 'abc1234567890def1234567890abcdef12345678',
    });
  });

  it('accepts www.github.com', () => {
    expect(parseGithubCommitUrl('https://www.github.com/owner/repo/commit/abc1234')).not.toBeNull();
  });

  it('accepts http (not just https) — GitHub redirects to https anyway, but the regex allows it', () => {
    expect(parseGithubCommitUrl('http://github.com/owner/repo/commit/abc1234')).not.toBeNull();
  });

  it('rejects non-github hosts (the SSRF prevention case)', () => {
    expect(parseGithubCommitUrl('http://169.254.169.254/owner/repo/commit/abc1234')).toBeNull();
    expect(parseGithubCommitUrl('http://localhost/owner/repo/commit/abc1234')).toBeNull();
    expect(parseGithubCommitUrl('http://attacker.com/owner/repo/commit/abc1234')).toBeNull();
    expect(parseGithubCommitUrl('https://gitlab.com/owner/repo/commit/abc1234')).toBeNull();
  });

  it('rejects fake github subdomain (typo squat)', () => {
    // The regex anchors on the literal `github.com` host (with optional `www.`),
    // so `github.com.attacker.com` does NOT match.
    expect(parseGithubCommitUrl('http://github.com.attacker.com/owner/repo/commit/abc1234')).toBeNull();
    expect(parseGithubCommitUrl('http://evilgithub.com/owner/repo/commit/abc1234')).toBeNull();
  });

  it('rejects file:// and javascript: schemes', () => {
    expect(parseGithubCommitUrl('file:///etc/passwd')).toBeNull();
    expect(parseGithubCommitUrl('javascript:fetch("/admin")')).toBeNull();
  });

  it('rejects when sha is too short (< 7 chars)', () => {
    expect(parseGithubCommitUrl('https://github.com/o/r/commit/abc12')).toBeNull();
  });

  it('rejects shas containing non-hex chars', () => {
    // The regex requires a `\b` word boundary after the hex run; non-hex
    // word chars (g-z, 0-9 already covered, _) prevent the match entirely
    // rather than truncating. Both forms reject.
    expect(parseGithubCommitUrl('https://github.com/o/r/commit/abc1234g')).toBeNull();
    expect(parseGithubCommitUrl('https://github.com/o/r/commit/zzzzzzz')).toBeNull();
  });

  it('accepts a sha followed by a non-word char (path slash, query string)', () => {
    // The `\b` allows non-word chars after the hex run — query-string and
    // path-suffix are both legal on GitHub commit URLs.
    expect(parseGithubCommitUrl('https://github.com/o/r/commit/abc1234?diff=split')).toMatchObject({ sha: 'abc1234' });
    expect(parseGithubCommitUrl('https://github.com/o/r/commit/abc1234/file/x.js')).toMatchObject({ sha: 'abc1234' });
  });

  it('rejects empty url', () => {
    expect(parseGithubCommitUrl('')).toBeNull();
  });

  it('lowercases the sha', () => {
    expect(parseGithubCommitUrl('https://github.com/o/r/commit/ABC1234')).toMatchObject({ sha: 'abc1234' });
  });

  it('strips trailing .git from repo name', () => {
    expect(parseGithubCommitUrl('https://github.com/o/r.git/commit/abc1234')).toMatchObject({ repo: 'r' });
  });
});

describe('extractFixCommits — filters non-github URLs from OSV references', () => {
  // Even if an attacker-published OSV record carries a malicious
  // `references[].url`, extractFixCommits silently drops it because
  // parseGithubCommitUrl returns null. This test reproduces the
  // attacker-input case and verifies the worker produces zero fix-commits
  // (so no fetch is ever issued against the attacker URL).
  it('drops references that do not match the github commit-URL regex', () => {
    const advisory: OsvAdvisory = {
      id: 'CVE-EVIL',
      aliases: [],
      summary: '',
      details: '',
      affected: [],
      references: [
        { type: 'FIX', url: 'http://169.254.169.254/aws/metadata' },
        { type: 'FIX', url: 'http://localhost:6379/' },
        { type: 'WEB', url: 'http://attacker.com/owner/repo/commit/abc1234' },
        // Legitimate one mixed in:
        { type: 'FIX', url: 'https://github.com/legit/repo/commit/abc1234567890def' },
      ],
    };

    const out = extractFixCommits(advisory);

    expect(out).toHaveLength(1);
    expect(out[0].owner).toBe('legit');
    expect(out[0].repo).toBe('repo');
    // The attacker URLs are silently filtered — never reach a fetch.
  });

  it('dedupes by owner/repo/sha across reference types', () => {
    const advisory: OsvAdvisory = {
      id: 'CVE-DUP',
      aliases: [],
      summary: '',
      details: '',
      affected: [],
      references: [
        { type: 'FIX', url: 'https://github.com/o/r/commit/abc1234' },
        { type: 'WEB', url: 'https://github.com/o/r/commit/abc1234' },
        { type: 'ADVISORY', url: 'https://github.com/o/r/commit/ABC1234' }, // case
      ],
    };

    expect(extractFixCommits(advisory)).toHaveLength(1);
  });
});
