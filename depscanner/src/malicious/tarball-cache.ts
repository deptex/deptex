/**
 * Per-job ephemeral tarball cache for the malicious-scan step.
 *
 * Since Arc 2 the fetch/unpack core lives in `../lib/dep-sources.ts`
 * (`DepSourceCache`) so the dep-import-graph step can reuse the same name
 * gates + zip-slip/bomb guards under a different artifact policy. This class
 * keeps the malicious scanner's exact historical behavior: sdist-first
 * (GuardDog wants the source layout; the sdist build-backend tradeoff is
 * documented on the policy knob), wheel fallback, root at
 * `/tmp/malicious-scan-<jobId>/`.
 */
import { DepSourceCache } from '../lib/dep-sources';

export { parseTarListing, type TarballCacheEntry } from '../lib/dep-sources';

export class TarballCache extends DepSourceCache {
  constructor(jobId: string) {
    super({
      rootDirName: `malicious-scan-${jobId}`,
      artifactPolicy: 'sdist-first',
      label: 'malicious-scan',
    });
  }
}
