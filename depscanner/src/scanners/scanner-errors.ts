// Container-scan substep error taxonomy (M8).
//
// Each scanOneImage substep throws one of the tagged classes below on failure.
// classifyContainerScanError() folds the throw into a structured row for
// extraction_step_errors:
//
//   { code, retryable, cacheWriteAllowed, skipReason }
//
// The orchestrator surfaces `skipReason` on the SkippedImage entry; the worker
// pipeline writes `code` to extraction_step_errors so the failure cause is
// recoverable from the error table alone (no log-grep). `retryable` and
// `cacheWriteAllowed` are consulted by the cache_upsert sub-step's 4-guard
// contract — partial Trivy output, for instance, must NEVER write a cache row
// even when exit was 0.
//
// The class names match the columns of the table in iac-container-v2-phase1
// plan §M8 Step 7. When you add a new tag, add it here AND update SkippedImage
// in types.ts AND the parameterized table test in scanner-errors.test.ts.

import { RegistryUnavailableError } from './trivy';
import type { SkippedImage } from './types';

/** AES-256-GCM decrypt failed for a registry credential. The orchestrator
 *  treats this as a permanent terminal error for the failing image only —
 *  the rest of the project's images and the IaC step continue. */
export class CredDecryptError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredDecryptError';
  }
}

/** Auth-mint subprocess (ECR STS / Azure AAD-then-ACR / GH App token) failed
 *  in a way that doesn't smell like a transient registry 5xx. Permanent
 *  terminal for the image. */
export class AuthMintError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthMintError';
  }
}

/** Decrypted credential structure was malformed (missing required field,
 *  unknown shape, etc.). Not retryable — the row needs operator attention. */
export class AuthConfigInvalidError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthConfigInvalidError';
  }
}

/** Auth-mint endpoint signaled rate limiting (HTTP 429 / exponential backoff).
 *  Retryable up to 3 attempts; cache write blocked. */
export class AuthThrottledError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthThrottledError';
  }
}

/** Manifest probe / Trivy pull says the image doesn't exist (404). Not
 *  retryable; cache write blocked. */
export class ImageUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ImageUnavailableError';
  }
}

/** Trivy exited cleanly but the JSON output was structurally invalid OR the
 *  RepoDigest didn't match the crane-probed digest. NEVER cache a partial
 *  result — that would poison the cache for every other org pulling this
 *  digest. */
export class PartialTrivyOutputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PartialTrivyOutputError';
  }
}

export interface ContainerScanErrorClassification {
  /** Goes to extraction_step_errors.code. Stable identifier. */
  code: string;
  /** Goes to extraction_step_errors.message. */
  message: string;
  /** Stack trace for debugging (server-side only). */
  stack?: string;
  /** Whether the orchestrator is allowed to retry the substep. */
  retryable: boolean;
  /** Whether the cache_upsert sub-step is allowed to run. False means the
   *  Trivy output is suspect and must not contaminate the global cache. */
  cacheWriteAllowed: boolean;
  /** Surfaced to the user via SkippedImage.reason. */
  skipReason: SkippedImage['reason'];
}

export function classifyContainerScanError(err: unknown): ContainerScanErrorClassification {
  if (err instanceof CredDecryptError) {
    return {
      code: 'cred_decrypt_panic',
      message: err.message,
      stack: err.stack,
      retryable: false,
      cacheWriteAllowed: false,
      skipReason: 'cred_decrypt_failed',
    };
  }
  if (err instanceof AuthMintError) {
    return {
      code: 'cred_auth_mint_panic',
      message: err.message,
      stack: err.stack,
      retryable: false,
      cacheWriteAllowed: false,
      skipReason: 'auth_mint_failed',
    };
  }
  if (err instanceof AuthConfigInvalidError) {
    return {
      code: 'auth_config_invalid',
      message: err.message,
      stack: err.stack,
      retryable: false,
      cacheWriteAllowed: false,
      skipReason: 'auth_invalid',
    };
  }
  if (err instanceof AuthThrottledError) {
    return {
      code: 'auth_throttled',
      message: err.message,
      stack: err.stack,
      retryable: true,
      cacheWriteAllowed: false,
      skipReason: 'auth_throttled',
    };
  }
  if (err instanceof RegistryUnavailableError) {
    return {
      code: 'registry_unavailable',
      message: err.message,
      stack: err.stack,
      retryable: true,
      cacheWriteAllowed: false,
      skipReason: 'registry_5xx',
    };
  }
  if (err instanceof ImageUnavailableError) {
    return {
      code: 'image_unavailable',
      message: err.message,
      stack: err.stack,
      retryable: false,
      cacheWriteAllowed: false,
      skipReason: 'manifest_not_found',
    };
  }
  if (err instanceof PartialTrivyOutputError) {
    return {
      code: 'partial_trivy_output',
      message: err.message,
      stack: err.stack,
      retryable: false,
      cacheWriteAllowed: false,
      skipReason: 'trivy_partial',
    };
  }
  // Catch-all for anything not tagged. Treat as terminal for the image, with
  // the cache lock-out left in place — never trust untagged failures for the
  // global cache.
  const e = err as Error | undefined;
  return {
    code: 'unexpected',
    message: e?.message ?? String(err),
    stack: e?.stack,
    retryable: false,
    cacheWriteAllowed: false,
    skipReason: 'manifest_not_found',
  };
}
