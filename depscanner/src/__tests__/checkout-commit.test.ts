/**
 * Locks the shallow-clone commit-checkout fallback in checkoutCommit().
 *
 * The default clone is `--depth 1 --single-branch`, so only the branch tip is
 * local. checkoutCommit must:
 *   1) check out the SHA directly when it's the shallow tip (fast path),
 *   2) targeted-fetch the SHA shallowly when it's absent (branch advanced /
 *      older pinned commit), then check out,
 *   3) unshallow the branch as a last resort if the targeted fetch is rejected.
 */

const rawMock = jest.fn();
jest.mock('simple-git', () => ({
  __esModule: true,
  default: jest.fn(() => ({ raw: (...a: unknown[]) => rawMock(...a) })),
}));

import { checkoutCommit } from '../github';

describe('checkoutCommit', () => {
  beforeEach(() => {
    rawMock.mockReset();
  });

  it('fast path: checks out the SHA already present in the shallow clone', async () => {
    rawMock.mockResolvedValueOnce(undefined); // checkout succeeds
    await checkoutCommit('/repo', 'abc');
    expect(rawMock).toHaveBeenCalledTimes(1);
    expect(rawMock).toHaveBeenNthCalledWith(1, ['checkout', 'abc']);
  });

  it('targeted-fetches the SHA when absent from the shallow clone, then checks out', async () => {
    rawMock
      .mockRejectedValueOnce(new Error("pathspec 'abc' did not match")) // checkout fails
      .mockResolvedValueOnce(undefined) // fetch --depth 1 origin abc
      .mockResolvedValueOnce(undefined); // checkout abc
    await checkoutCommit('/repo', 'abc');
    expect(rawMock).toHaveBeenNthCalledWith(1, ['checkout', 'abc']);
    expect(rawMock).toHaveBeenNthCalledWith(2, ['fetch', '--depth', '1', 'origin', 'abc']);
    expect(rawMock).toHaveBeenNthCalledWith(3, ['checkout', 'abc']);
  });

  it('unshallows as a last resort when the targeted fetch is rejected', async () => {
    rawMock
      .mockRejectedValueOnce(new Error('checkout fail')) // checkout fails
      .mockRejectedValueOnce(new Error('want-sha rejected')) // targeted fetch fails
      .mockResolvedValueOnce(undefined) // fetch --unshallow origin
      .mockResolvedValueOnce(undefined); // checkout abc
    await checkoutCommit('/repo', 'abc');
    expect(rawMock).toHaveBeenNthCalledWith(3, ['fetch', '--unshallow', 'origin']);
    expect(rawMock).toHaveBeenNthCalledWith(4, ['checkout', 'abc']);
  });

  it('propagates the error when the commit cannot be obtained (e.g. force-pushed away)', async () => {
    rawMock
      .mockRejectedValueOnce(new Error('checkout fail'))
      .mockRejectedValueOnce(new Error('want-sha rejected'))
      .mockResolvedValueOnce(undefined) // unshallow succeeds
      .mockRejectedValueOnce(new Error('commit gone')); // final checkout fails
    await expect(checkoutCommit('/repo', 'abc')).rejects.toThrow('commit gone');
  });
});
