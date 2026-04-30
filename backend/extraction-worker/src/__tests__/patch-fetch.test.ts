/**
 * Tests for patch-fetch.ts — the GitHub commit-diff fetcher used to populate
 * the LLM prompt with patch context.
 *
 * Pins: timeout, no_parent guard, 404 → typed error, MAX_DIFF_BYTES truncation
 * flag, MAX_FILE_BYTES truncation flag, lockfile/binary skip filter, and the
 * use of `application/vnd.github.diff` accept header.
 */
import { fetchPatchInfo, PatchFetchError } from '../rule-generator/patch-fetch';
import type { FixCommit } from '../rule-generator/osv-fetch';

const realFetch = global.fetch;

afterEach(() => {
  global.fetch = realFetch;
  jest.restoreAllMocks();
});

const baseCommit: FixCommit = {
  url: 'https://github.com/o/r/commit/abc1234',
  owner: 'o',
  repo: 'r',
  sha: 'abc1234',
};

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(),
    text: async () => JSON.stringify(body),
    json: async () => body,
  } as unknown as Response;
}

function textResponse(text: string, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(),
    text: async () => text,
    json: async () => {
      throw new Error('not JSON');
    },
  } as unknown as Response;
}

describe('fetchPatchInfo', () => {
  it('fetches metadata + diff and assembles before/after blobs', async () => {
    const meta = {
      sha: 'abc1234',
      parents: [{ sha: 'parent111' }],
      files: [
        { filename: 'src/app.js', status: 'modified' },
      ],
    };
    const diffText = `diff --git a/src/app.js b/src/app.js\n@@ -1 +1 @@\n-old\n+new\n`;
    const beforeBlob = 'old content';
    const afterBlob = 'new content';

    const fetchMock = jest.fn()
      .mockImplementationOnce(async (_url: string, init: RequestInit) => {
        // First call: metadata JSON
        const accept = (init.headers as Record<string, string>).accept;
        expect(accept).toBe('application/vnd.github+json');
        return jsonResponse(meta);
      })
      .mockImplementationOnce(async (_url: string, init: RequestInit) => {
        // Second call: diff
        const accept = (init.headers as Record<string, string>).accept;
        expect(accept).toBe('application/vnd.github.diff');
        return textResponse(diffText);
      })
      .mockImplementationOnce(async () => textResponse(beforeBlob))
      .mockImplementationOnce(async () => textResponse(afterBlob));
    global.fetch = fetchMock as any;

    const result = await fetchPatchInfo(baseCommit);

    expect(result.parentSha).toBe('parent111');
    expect(result.fixSha).toBe('abc1234');
    expect(result.diff).toBe(diffText);
    expect(result.diffTruncated).toBe(false);
    expect(result.changedFiles).toHaveLength(1);
    expect(result.changedFiles[0]).toMatchObject({
      path: 'src/app.js',
      status: 'modified',
      before: beforeBlob,
      after: afterBlob,
      beforeTruncated: false,
      afterTruncated: false,
    });
  });

  it('throws PatchFetchError(no_parent) when fix commit has no parent', async () => {
    const meta = { sha: 'abc1234', parents: [], files: [] };
    global.fetch = jest.fn().mockResolvedValue(jsonResponse(meta)) as any;

    await expect(fetchPatchInfo(baseCommit)).rejects.toMatchObject({
      name: 'PatchFetchError',
      code: 'no_parent',
    });
  });

  it('throws PatchFetchError(not_found) on 404', async () => {
    global.fetch = jest.fn().mockResolvedValue(jsonResponse({}, 404)) as any;

    await expect(fetchPatchInfo(baseCommit)).rejects.toMatchObject({
      name: 'PatchFetchError',
      code: 'not_found',
    });
  });

  it('throws PatchFetchError(network) on 5xx', async () => {
    global.fetch = jest.fn().mockResolvedValue(jsonResponse({}, 503)) as any;

    await expect(fetchPatchInfo(baseCommit)).rejects.toMatchObject({
      name: 'PatchFetchError',
      code: 'network',
    });
  });

  it('throws PatchFetchError(network) when fetch rejects (DNS, abort, etc.)', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('ENOTFOUND api.github.com')) as any;

    await expect(fetchPatchInfo(baseCommit)).rejects.toMatchObject({
      name: 'PatchFetchError',
      code: 'network',
    });
  });

  it('throws PatchFetchError(parse) when metadata is not JSON', async () => {
    global.fetch = jest.fn().mockResolvedValue(textResponse('<html>error</html>')) as any;

    await expect(fetchPatchInfo(baseCommit)).rejects.toMatchObject({
      name: 'PatchFetchError',
      code: 'parse',
    });
  });

  it('truncates diff to MAX_DIFF_BYTES (1MB) and sets diffTruncated', async () => {
    const meta = { sha: 'abc1234', parents: [{ sha: 'parent' }], files: [] };
    const huge = 'x'.repeat(1_500_000); // 1.5MB
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(jsonResponse(meta))
      .mockResolvedValueOnce(textResponse(huge));
    global.fetch = fetchMock as any;

    const result = await fetchPatchInfo(baseCommit);

    expect(result.diff.length).toBe(1_048_576); // exactly 1MB
    expect(result.diffTruncated).toBe(true);
  });

  it('truncates per-file blob to MAX_FILE_BYTES (64KB) and sets per-file truncated flag', async () => {
    const meta = { sha: 'abc1234', parents: [{ sha: 'parent' }], files: [{ filename: 'src/big.js', status: 'modified' }] };
    const bigFile = 'y'.repeat(70_000);
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(jsonResponse(meta))
      .mockResolvedValueOnce(textResponse('small diff'))
      .mockResolvedValueOnce(textResponse(bigFile)) // before
      .mockResolvedValueOnce(textResponse(bigFile)); // after
    global.fetch = fetchMock as any;

    const result = await fetchPatchInfo(baseCommit);

    expect(result.changedFiles[0].before!.length).toBe(65536); // 64KB
    expect(result.changedFiles[0].beforeTruncated).toBe(true);
    expect(result.changedFiles[0].after!.length).toBe(65536);
    expect(result.changedFiles[0].afterTruncated).toBe(true);
  });

  it('skips lockfiles and binary extensions (no fetch issued for them)', async () => {
    const meta = {
      sha: 'abc1234',
      parents: [{ sha: 'parent' }],
      files: [
        { filename: 'package-lock.json', status: 'modified' },
        { filename: 'yarn.lock', status: 'modified' },
        { filename: 'go.sum', status: 'modified' },
        { filename: 'logo.png', status: 'modified' },
        { filename: 'app.min.js', status: 'modified' },
        { filename: 'real.js', status: 'modified' },
      ],
    };
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(jsonResponse(meta))
      .mockResolvedValueOnce(textResponse('diff'))
      .mockResolvedValueOnce(textResponse('before'))
      .mockResolvedValueOnce(textResponse('after'));
    global.fetch = fetchMock as any;

    const result = await fetchPatchInfo(baseCommit);

    expect(result.changedFiles).toHaveLength(1);
    expect(result.changedFiles[0].path).toBe('real.js');
    // 4 fetches total: metadata + diff + before + after for the one
    // legitimate file. Lockfiles/binaries did NOT trigger blob fetches.
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it('handles added files (no before fetch issued)', async () => {
    const meta = {
      sha: 'abc1234',
      parents: [{ sha: 'parent' }],
      files: [{ filename: 'new.js', status: 'added' }],
    };
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(jsonResponse(meta))
      .mockResolvedValueOnce(textResponse('diff'))
      .mockResolvedValueOnce(textResponse('after'));
    global.fetch = fetchMock as any;

    const result = await fetchPatchInfo(baseCommit);

    expect(result.changedFiles[0].before).toBeNull();
    expect(result.changedFiles[0].after).toBe('after');
    // 3 fetches: metadata + diff + after only.
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('handles removed files (no after fetch issued)', async () => {
    const meta = {
      sha: 'abc1234',
      parents: [{ sha: 'parent' }],
      files: [{ filename: 'gone.js', status: 'removed' }],
    };
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(jsonResponse(meta))
      .mockResolvedValueOnce(textResponse('diff'))
      .mockResolvedValueOnce(textResponse('before'));
    global.fetch = fetchMock as any;

    const result = await fetchPatchInfo(baseCommit);

    expect(result.changedFiles[0].before).toBe('before');
    expect(result.changedFiles[0].after).toBeNull();
  });

  it('attaches Bearer token when githubToken provided', async () => {
    const meta = { sha: 'abc1234', parents: [{ sha: 'parent' }], files: [] };
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(jsonResponse(meta))
      .mockResolvedValueOnce(textResponse('diff'));
    global.fetch = fetchMock as any;

    await fetchPatchInfo(baseCommit, { githubToken: 'ghp_test123' });

    const headers = fetchMock.mock.calls[0][1].headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer ghp_test123');
  });

  it('omits Authorization header when no token', async () => {
    const meta = { sha: 'abc1234', parents: [{ sha: 'parent' }], files: [] };
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(jsonResponse(meta))
      .mockResolvedValueOnce(textResponse('diff'));
    global.fetch = fetchMock as any;

    await fetchPatchInfo(baseCommit);

    const headers = fetchMock.mock.calls[0][1].headers as Record<string, string>;
    expect(headers.authorization).toBeUndefined();
  });

  it('forwards an outer abort signal', async () => {
    const fetchMock = jest.fn().mockImplementation((_url: string, init: RequestInit) => {
      return new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => reject(new Error('aborted')));
      });
    });
    global.fetch = fetchMock as any;

    const controller = new AbortController();
    const promise = fetchPatchInfo(baseCommit, { signal: controller.signal });
    controller.abort();
    await expect(promise).rejects.toThrow();
  });

  it('returns null per-file blob on 404 without failing the whole patch', async () => {
    const meta = {
      sha: 'abc1234',
      parents: [{ sha: 'parent' }],
      files: [{ filename: 'maybe-deleted.js', status: 'modified' }],
    };
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(jsonResponse(meta))
      .mockResolvedValueOnce(textResponse('diff'))
      .mockResolvedValueOnce(textResponse('', 404)) // before missing
      .mockResolvedValueOnce(textResponse('after-content'));
    global.fetch = fetchMock as any;

    const result = await fetchPatchInfo(baseCommit);

    expect(result.changedFiles[0].before).toBeNull();
    expect(result.changedFiles[0].after).toBe('after-content');
  });
});
