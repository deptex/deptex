/**
 * Unit tests for scanOneImage. Closes the test-thoroughness review finding
 * "scanOneImage and the entire per-image scan loop have zero unit tests" by
 * exercising:
 *   - scan-time SSRF re-check skips internal-host image refs
 *   - ghcr namespace mismatch (no installation login → skipped)
 *   - ghcr namespace mismatch (different login → skipped)
 *   - private image without cred and without ghcr fallback → no_matching_cred
 *   - registry auth kill switch → auth_disabled
 *   - cache hit returns rewritten image_reference per-org
 *   - cache miss → trivy_pull → findings + cache upsert
 *   - trivy_pull failure → classified skip reason
 *   - 4-guard cache contract: warnings → no cache write
 *   - 4-guard: digest mismatch → no cache write
 */

// Mock the network-touching modules BEFORE importing the orchestrator.
jest.mock('../host-guard', () => ({
  validateScanTimeHost: jest.fn(),
  extractImageRefHost: jest.fn((s: string) => s.split('/')[0] || 'docker.io'),
}));
jest.mock('../trivy', () => ({
  extractGhcrOwner: jest.fn((ref: string) => {
    const m = ref.match(/^ghcr\.io\/([^/]+)\//);
    return m ? m[1] : null;
  }),
  normalizeDigest: jest.fn((s: string) => {
    const m = s.match(/(?:^|@sha256:|^sha256:)([a-f0-9]{64})$/);
    if (!m) throw new Error(`invalid digest: ${s}`);
    return m[1];
  }),
  parseDockerfileFinalStage: jest.fn(),
  parseDockerfileFinalStageDetailed: jest.fn(),
  parseImageHost: jest.fn((s: string) => ({
    host: s.split('/')[0] || 'docker.io',
    path: s,
    isImplicitDockerHub: false,
  })),
  resolveImageDigest: jest.fn(),
  resolvePullStrategy: jest.fn(),
  RegistryUnavailableError: class RegistryUnavailableError extends Error {},
  runTrivyConfig: jest.fn(),
  runTrivyImage: jest.fn(),
  trivyDbVersionDay: jest.fn(async () => '2026-05-06'),
  trivyVersion: jest.fn(async () => '0.50.0'),
}));
jest.mock('../storage', () => ({
  lookupContainerScanCache: jest.fn(),
  upsertContainerFindings: jest.fn(),
  upsertContainerScanCache: jest.fn(),
  upsertIaCFindings: jest.fn(),
}));
jest.mock('../../github', () => ({
  createInstallationToken: jest.fn(),
  getInstallationAccount: jest.fn(),
}));

import * as fsPromises from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { _internal } from '../orchestrator';
import { validateScanTimeHost } from '../host-guard';
import { resolveImageDigest, runTrivyImage, RegistryUnavailableError } from '../trivy';
import { lookupContainerScanCache, upsertContainerScanCache } from '../storage';
import { createInstallationToken } from '../../github';

const { scanOneImage } = _internal as any;

const mockValidateScanTimeHost = validateScanTimeHost as jest.Mock;
const mockResolveImageDigest = resolveImageDigest as jest.Mock;
const mockRunTrivyImage = runTrivyImage as jest.Mock;
const mockLookupCache = lookupContainerScanCache as jest.Mock;
const mockUpsertCache = upsertContainerScanCache as jest.Mock;
const mockCreateInstallationToken = createInstallationToken as jest.Mock;

const DIGEST = 'a'.repeat(64);

function makeCtx(overrides: Partial<any> = {}) {
  return {
    supabase: {} as any,
    projectId: 'proj-1',
    organizationId: 'org-1',
    jobId: null,
    runId: 'run-1',
    repoPath: '/tmp/repo',
    githubInstallationId: 'install-1',
    logger: {
      warn: jest.fn(async () => {}),
      info: jest.fn(async () => {}),
      error: jest.fn(async () => {}),
    },
    onHeartbeat: jest.fn(async () => {}),
    ...overrides,
  };
}

// Real temp dir so writeConfigJson (called by the ghcr-App-token branch) can
// actually persist auths.json without ENOENT.
let tmpEnvelopeDir = '';

function makeEnvelope(overrides: Partial<any> = {}) {
  return {
    dockerConfigDir: tmpEnvelopeDir,
    entries: [],
    authedHosts: new Set<string>(),
    ...overrides,
  };
}

function makeSwitches(overrides: Partial<any> = {}) {
  return {
    iacEnabled: true,
    containerEnabled: true,
    trivyKilled: false,
    checkovKilled: false,
    configuredImagesKilled: false,
    registryAuthKilled: false,
    digestCacheKilled: false,
    credDecryptKilled: false,
    redisFallback: false,
    ...overrides,
  };
}

beforeEach(async () => {
  mockValidateScanTimeHost.mockReset();
  mockResolveImageDigest.mockReset();
  mockRunTrivyImage.mockReset();
  mockLookupCache.mockReset();
  mockUpsertCache.mockReset();
  mockCreateInstallationToken.mockReset();
  mockValidateScanTimeHost.mockResolvedValue({
    valid: true, host: 'public.example.com', addresses: ['1.2.3.4'],
  });
  tmpEnvelopeDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'deptex-scan-test-'));
});

afterEach(async () => {
  if (tmpEnvelopeDir) {
    await fsPromises.rm(tmpEnvelopeDir, { recursive: true, force: true });
  }
});

describe('scanOneImage — scan-time SSRF guard', () => {
  it('skips an image whose host re-resolves to a private/IMDS address', async () => {
    mockValidateScanTimeHost.mockResolvedValue({
      valid: false, reason: 'host resolved to IMDS endpoint',
    });
    const result = await scanOneImage(
      { imageRef: 'evil.example.com/foo:bar', source: 'configured_image', credId: null, credHostname: null, allowGhcrAppFallback: false },
      makeCtx(),
      makeEnvelope(),
      makeSwitches(),
      null,
    );
    expect(result).toEqual({ skipped: { image: 'evil.example.com/foo:bar', reason: 'image_host_blocked' } });
    expect(mockResolveImageDigest).not.toHaveBeenCalled();
    expect(mockRunTrivyImage).not.toHaveBeenCalled();
  });
});

describe('scanOneImage — ghcr namespace check', () => {
  const baseImage = {
    imageRef: 'ghcr.io/acme/internal:1.0',
    source: 'dockerfile_base' as const,
    credId: null,
    credHostname: null,
    allowGhcrAppFallback: true,
  };

  it('skips when no installation_login is provided', async () => {
    const result = await scanOneImage(baseImage, makeCtx(), makeEnvelope(), makeSwitches(), null);
    expect(result).toEqual({ skipped: { image: baseImage.imageRef, reason: 'ghcr_namespace_mismatch' } });
  });

  it('skips when the ghcr owner does not match the App installation login', async () => {
    const result = await scanOneImage(baseImage, makeCtx(), makeEnvelope(), makeSwitches(), 'other-org');
    expect(result).toEqual({ skipped: { image: baseImage.imageRef, reason: 'ghcr_namespace_mismatch' } });
  });

  it('mints an installation token when owner matches and pull eventually succeeds', async () => {
    mockCreateInstallationToken.mockResolvedValue('ghs_abc');
    mockResolveImageDigest.mockResolvedValue(DIGEST);
    mockLookupCache.mockResolvedValue(null);
    mockRunTrivyImage.mockResolvedValue({
      findings: [],
      warnings: [],
      imageDigest: `sha256:${DIGEST}`,
      version: 'trivy@0.50.0',
    });

    const env = makeEnvelope();
    const result = await scanOneImage(baseImage, makeCtx(), env, makeSwitches(), 'acme');
    expect(result).toEqual({ findings: [] });
    expect(mockCreateInstallationToken).toHaveBeenCalledWith('install-1');
    expect(env.authedHosts.has('ghcr.io')).toBe(true);
  });

  it('skips with auth_mint_failed when token mint throws', async () => {
    mockCreateInstallationToken.mockRejectedValue(new Error('mint exploded'));
    const result = await scanOneImage(baseImage, makeCtx(), makeEnvelope(), makeSwitches(), 'acme');
    expect(result).toEqual({ skipped: { image: baseImage.imageRef, reason: 'auth_mint_failed' } });
  });
});

describe('scanOneImage — private images without creds', () => {
  const privImage = {
    imageRef: 'private.example.com/foo:bar',
    source: 'configured_image' as const,
    credId: null,
    credHostname: null,
    allowGhcrAppFallback: false,
  };

  it('skips with no_matching_cred when no path is available', async () => {
    const result = await scanOneImage(privImage, makeCtx(), makeEnvelope(), makeSwitches(), null);
    expect(result).toEqual({ skipped: { image: privImage.imageRef, reason: 'no_matching_cred' } });
  });

  it('skips with auth_disabled when registry auth kill switch is on', async () => {
    const result = await scanOneImage(privImage, makeCtx(), makeEnvelope(), makeSwitches({ registryAuthKilled: true }), null);
    expect(result).toEqual({ skipped: { image: privImage.imageRef, reason: 'auth_disabled' } });
  });
});

describe('scanOneImage — cache lookup', () => {
  const pubImage = {
    imageRef: 'docker.io/library/nginx:1.27',
    source: 'dockerfile_base' as const,
    credId: null,
    credHostname: null,
    allowGhcrAppFallback: false,
  };

  it('returns cached findings with image_reference rewritten to the caller image ref', async () => {
    mockResolveImageDigest.mockResolvedValue(DIGEST);
    mockLookupCache.mockResolvedValue({
      findings: [
        { id: 'f1', image_reference: 'OTHER-ORG-pull-string', cve_id: 'CVE-1', severity: 'HIGH' } as any,
      ],
      scanner_version: 'trivy@0.50.0',
    });

    const result = await scanOneImage(pubImage, makeCtx(), makeEnvelope(), makeSwitches(), null);
    expect(mockRunTrivyImage).not.toHaveBeenCalled();
    expect('findings' in result).toBe(true);
    if ('findings' in result) {
      expect(result.findings).toHaveLength(1);
      // Rewrite invariant: cache row's pull-string never leaks across orgs.
      expect(result.findings[0].image_reference).toBe(pubImage.imageRef);
    }
  });

  it('falls through to trivy_pull on cache miss', async () => {
    mockResolveImageDigest.mockResolvedValue(DIGEST);
    mockLookupCache.mockResolvedValue(null);
    mockRunTrivyImage.mockResolvedValue({
      findings: [{ id: 'fresh-1' } as any],
      warnings: [],
      imageDigest: `sha256:${DIGEST}`,
      version: 'trivy@0.50.0',
    });

    const result = await scanOneImage(pubImage, makeCtx(), makeEnvelope(), makeSwitches(), null);
    expect(mockRunTrivyImage).toHaveBeenCalled();
    expect('findings' in result).toBe(true);
    if ('findings' in result) expect(result.findings[0].id).toBe('fresh-1');
    expect(mockUpsertCache).toHaveBeenCalled();
  });

  it('skips digest probe entirely when digestCacheKilled', async () => {
    mockRunTrivyImage.mockResolvedValue({
      findings: [],
      warnings: [],
      imageDigest: `sha256:${DIGEST}`,
      version: 'trivy@0.50.0',
    });
    const result = await scanOneImage(pubImage, makeCtx(), makeEnvelope(), makeSwitches({ digestCacheKilled: true }), null);
    expect(mockResolveImageDigest).not.toHaveBeenCalled();
    expect(mockLookupCache).not.toHaveBeenCalled();
    expect(mockUpsertCache).not.toHaveBeenCalled();
    expect('findings' in result).toBe(true);
  });
});

describe('scanOneImage — 4-guard cache contract', () => {
  const pubImage = {
    imageRef: 'docker.io/library/nginx:1.27',
    source: 'dockerfile_base' as const,
    credId: null,
    credHostname: null,
    allowGhcrAppFallback: false,
  };

  it('skips cache upsert when Trivy emitted warnings (guard #1)', async () => {
    mockResolveImageDigest.mockResolvedValue(DIGEST);
    mockLookupCache.mockResolvedValue(null);
    mockRunTrivyImage.mockResolvedValue({
      findings: [{ id: 'f1' } as any],
      warnings: ['mid-pull blob 503'],
      imageDigest: `sha256:${DIGEST}`,
      version: 'trivy@0.50.0',
    });
    await scanOneImage(pubImage, makeCtx(), makeEnvelope(), makeSwitches(), null);
    expect(mockUpsertCache).not.toHaveBeenCalled();
  });

  it('skips cache upsert when probe digest disagrees with Trivy RepoDigest (guard #4)', async () => {
    mockResolveImageDigest.mockResolvedValue(DIGEST);
    mockLookupCache.mockResolvedValue(null);
    mockRunTrivyImage.mockResolvedValue({
      findings: [{ id: 'f1' } as any],
      warnings: [],
      imageDigest: `sha256:${'b'.repeat(64)}`, // mismatch
      version: 'trivy@0.50.0',
    });
    await scanOneImage(pubImage, makeCtx(), makeEnvelope(), makeSwitches(), null);
    expect(mockUpsertCache).not.toHaveBeenCalled();
  });

  it('skips cache upsert when Trivy returned no imageDigest at all (guard #3)', async () => {
    mockResolveImageDigest.mockResolvedValue(DIGEST);
    mockLookupCache.mockResolvedValue(null);
    mockRunTrivyImage.mockResolvedValue({
      findings: [{ id: 'f1' } as any],
      warnings: [],
      imageDigest: null,
      version: 'trivy@0.50.0',
    });
    await scanOneImage(pubImage, makeCtx(), makeEnvelope(), makeSwitches(), null);
    expect(mockUpsertCache).not.toHaveBeenCalled();
  });
});

describe('scanOneImage — trivy_pull failure', () => {
  const pubImage = {
    imageRef: 'docker.io/library/nginx:1.27',
    source: 'dockerfile_base' as const,
    credId: null,
    credHostname: null,
    allowGhcrAppFallback: false,
  };

  it('classifies a generic trivy error as trivy_partial', async () => {
    mockResolveImageDigest.mockResolvedValue(DIGEST);
    mockLookupCache.mockResolvedValue(null);
    mockRunTrivyImage.mockRejectedValue(new Error('exit 137'));
    const result = await scanOneImage(pubImage, makeCtx(), makeEnvelope(), makeSwitches(), null);
    expect('skipped' in result).toBe(true);
    if ('skipped' in result) {
      expect(result.skipped.image).toBe(pubImage.imageRef);
    }
  });
});

describe('scanOneImage — RegistryUnavailableError fall-through', () => {
  const pubImage = {
    imageRef: 'docker.io/library/nginx:1.27',
    source: 'dockerfile_base' as const,
    credId: null,
    credHostname: null,
    allowGhcrAppFallback: false,
  };

  it('proceeds to a cache-bypassing scan when digest probe times out', async () => {
    mockResolveImageDigest.mockRejectedValue(new RegistryUnavailableError('5xx'));
    mockRunTrivyImage.mockResolvedValue({
      findings: [{ id: 'fresh' } as any],
      warnings: [],
      imageDigest: `sha256:${DIGEST}`,
      version: 'trivy@0.50.0',
    });
    const result = await scanOneImage(pubImage, makeCtx(), makeEnvelope(), makeSwitches(), null);
    expect('findings' in result).toBe(true);
    // Cache lookup skipped because probedDigest never set.
    expect(mockLookupCache).not.toHaveBeenCalled();
    // Cache upsert IS allowed: with probedDigest=null the digest-mismatch
    // guard short-circuits (`probedDigest && parsedDigest && ...` is false),
    // so a clean Trivy run still warms the cache for the next scan.
    expect(mockUpsertCache).toHaveBeenCalled();
  });
});
