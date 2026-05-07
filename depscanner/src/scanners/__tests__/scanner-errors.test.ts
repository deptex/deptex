import {
  AuthConfigInvalidError,
  AuthMintError,
  AuthThrottledError,
  CredDecryptError,
  ImageUnavailableError,
  PartialTrivyOutputError,
  classifyContainerScanError,
  type ContainerScanErrorClassification,
} from '../scanner-errors';
import { RegistryUnavailableError } from '../trivy';

describe('classifyContainerScanError — table from §M8 Step 7', () => {
  // (errInstance, expected code, retryable, cacheWriteAllowed, skipReason)
  const cases: Array<[
    Error,
    ContainerScanErrorClassification['code'],
    boolean,
    boolean,
    ContainerScanErrorClassification['skipReason']
  ]> = [
    [new CredDecryptError('boom'), 'cred_decrypt_panic', false, false, 'cred_decrypt_failed'],
    [new AuthMintError('boom'), 'cred_auth_mint_panic', false, false, 'auth_mint_failed'],
    [new AuthConfigInvalidError('boom'), 'auth_config_invalid', false, false, 'auth_invalid'],
    [new AuthThrottledError('boom'), 'auth_throttled', true, false, 'auth_throttled'],
    [new RegistryUnavailableError('repo:tag', 'crane probe timed out'), 'registry_unavailable', true, false, 'registry_5xx'],
    [new ImageUnavailableError('boom'), 'image_unavailable', false, false, 'manifest_not_found'],
    [new PartialTrivyOutputError('boom'), 'partial_trivy_output', false, false, 'trivy_partial'],
  ];

  it.each(cases)(
    '%s -> code=%s retryable=%s cacheWrite=%s skipReason=%s',
    (err, code, retryable, cacheWriteAllowed, skipReason) => {
      const got = classifyContainerScanError(err);
      expect(got.code).toBe(code);
      expect(got.retryable).toBe(retryable);
      expect(got.cacheWriteAllowed).toBe(cacheWriteAllowed);
      expect(got.skipReason).toBe(skipReason);
      expect(got.message).toBe(err.message);
    }
  );

  it('untagged Error falls into the catch-all with cache write blocked', () => {
    const got = classifyContainerScanError(new Error('something weird'));
    expect(got.code).toBe('unexpected');
    expect(got.retryable).toBe(false);
    expect(got.cacheWriteAllowed).toBe(false);
    // Catch-all skipReason is conservative — manifest_not_found is the most
    // benign value in the SkippedImage enum.
    expect(got.skipReason).toBe('manifest_not_found');
  });

  it('handles non-Error throws (string)', () => {
    const got = classifyContainerScanError('plain string');
    expect(got.code).toBe('unexpected');
    expect(got.message).toBe('plain string');
  });
});
