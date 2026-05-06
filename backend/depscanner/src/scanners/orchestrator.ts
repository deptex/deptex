import * as fs from 'fs';
import * as fsPromises from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import type { SupabaseClient } from '@supabase/supabase-js';
import { withTimeout, logStepError, classifyError, type ScannerSubprocessLogger } from '../with-timeout';
import {
  createInstallationToken,
  getInstallationAccount,
} from '../github';
import { detectInfraTypes, findDockerfiles, type InfraType } from './detect-infra';
import { runCheckov } from './checkov';
import {
  extractGhcrOwner,
  normalizeDigest,
  parseDockerfileFinalStage,
  resolveImageDigest,
  resolvePullStrategy,
  RegistryUnavailableError,
  runTrivyConfig,
  runTrivyImage,
  trivyDbVersionDay,
  trivyVersion,
  type ConfiguredCredRef,
} from './trivy';
import {
  buildDockerAuthConfig,
  decryptCredential,
  mintAzureAuth,
  mintBasicAuth,
  mintEcrAuth,
  mintGcpAuth,
  mintTokenAuth,
  resolveRegistryHostname,
  type DockerAuthEntry,
} from './registry-auth';
import {
  lookupContainerScanCache,
  upsertContainerFindings,
  upsertContainerScanCache,
  upsertIaCFindings,
} from './storage';
import {
  AuthMintError,
  CredDecryptError,
  classifyContainerScanError,
} from './scanner-errors';
import { validateScanTimeHost } from './host-guard';
import type {
  ContainerFinding,
  CredentialPlaintext,
  IaCFinding,
  IaCFramework,
  RegistryType,
  SkippedImage,
} from './types';

const CHECKOV_TIMEOUT_MS = Number(
  process.env.DEPTEX_CHECKOV_TIMEOUT_MS ?? 5 * 60_000
);
const TRIVY_CONFIG_TIMEOUT_MS = Number(
  process.env.DEPTEX_TRIVY_CONFIG_TIMEOUT_MS ?? 3 * 60_000
);
const TRIVY_IMAGE_TIMEOUT_MS = Number(
  process.env.DEPTEX_TRIVY_IMAGE_TIMEOUT_MS ?? 8 * 60_000
);
/** Total wall-clock cap across the per-step container loop. Combined with the
 *  per-image cap of 20 (M11) leaves ~75s of headroom per image inside Fly's
 *  machine slot. (Plan §M8 Step 5.) */
const CONTAINER_SCAN_TOTAL_BUDGET_MS = Number(
  process.env.CONTAINER_SCAN_TOTAL_BUDGET_MS ?? 25 * 60_000
);
/** Cap on AES-256-GCM decrypts per orchestrator run. Protects neighbour
 *  tenants on the same Fly machine from a runaway loop. (Plan §M8 Step 6 /
 *  MTD-r2-6.) */
const DECRYPT_BUDGET = Number(process.env.DEPTEX_DECRYPT_BUDGET ?? 200);
const VERBOSE_TRIVY = process.env.DEPTEX_TRIVY_VERBOSE_LOG === '1';
const VERBOSE_CHECKOV = process.env.DEPTEX_CHECKOV_VERBOSE_LOG === '1';

export interface ScannerSummary {
  infraTypes: InfraType[];
  iacFindingsWritten: number;
  containerFindingsWritten: number;
  skippedImages: SkippedImage[];
  warnings: string[];
}

export interface ScannerStepContext {
  supabase: SupabaseClient;
  projectId: string;
  organizationId: string;
  jobId: string | null;
  runId: string;
  repoPath: string;
  /** Pulled from organizations.github_installation_id at pipeline start. */
  githubInstallationId: string | null;
  logger: ScannerSubprocessLogger;
  onHeartbeat: () => Promise<void>;
}

interface KillSwitchContext {
  iacEnabled: boolean;
  containerEnabled: boolean;
  trivyKilled: boolean;
  checkovKilled: boolean;
  configuredImagesKilled: boolean;
  registryAuthKilled: boolean;
  digestCacheKilled: boolean;
  credDecryptKilled: boolean;
  redisFallback: boolean;
}

/**
 * Read the IaC + container kill switches and feature flags. Redis lookups
 * carry a 1s timeout + try/catch — on Redis failure we fall back to env-flag
 * defaults rather than failing-closed (the env flag is the source of truth
 * for "is this scanner allowed to run at all"; Redis is the kill switch
 * layer on top of it).
 */
async function resolveKillSwitches(): Promise<KillSwitchContext> {
  const iacEnabled = process.env.SCANNERS_IAC_ENABLED !== 'false';
  const containerEnabled = process.env.SCANNERS_CONTAINER_ENABLED !== 'false';

  const redisUrl = process.env.UPSTASH_REDIS_URL ?? process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.UPSTASH_REDIS_TOKEN ?? process.env.UPSTASH_REDIS_REST_TOKEN;

  const defaults: KillSwitchContext = {
    iacEnabled,
    containerEnabled,
    trivyKilled: false,
    checkovKilled: false,
    configuredImagesKilled: false,
    registryAuthKilled: false,
    digestCacheKilled: false,
    credDecryptKilled: false,
    redisFallback: false,
  };

  if (!redisUrl || !redisToken) return defaults;

  const fetchOne = async (key: string): Promise<string | null> => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 1000);
    try {
      const res = await fetch(`${redisUrl}/get/${encodeURIComponent(key)}`, {
        headers: { Authorization: `Bearer ${redisToken}` },
        signal: ctrl.signal,
      });
      if (!res.ok) return null;
      const body = (await res.json()) as { result?: string | null };
      return body.result ?? null;
    } finally {
      clearTimeout(timer);
    }
  };

  try {
    const [trivy, checkov, configured, registryAuth, digestCache, credDecrypt] = await Promise.all([
      fetchOne('kill:scanner:trivy'),
      fetchOne('kill:scanner:checkov'),
      fetchOne('kill:scanner:configured_images'),
      fetchOne('kill:scanner:registry_auth'),
      fetchOne('kill:scanner:digest_cache'),
      fetchOne('kill:scanner:cred_decrypt'),
    ]);
    const isOn = (v: string | null) => v === '1' || v === 'true';
    return {
      iacEnabled,
      containerEnabled,
      trivyKilled: isOn(trivy),
      checkovKilled: isOn(checkov),
      configuredImagesKilled: isOn(configured),
      registryAuthKilled: isOn(registryAuth),
      digestCacheKilled: isOn(digestCache),
      credDecryptKilled: isOn(credDecrypt),
      redisFallback: false,
    };
  } catch {
    return { ...defaults, redisFallback: true };
  }
}

/**
 * Optional rollout allowlist for staged dogfood. Honors empty/unset = all
 * orgs.
 */
function isAllowedOrg(orgId: string): boolean {
  const raw = process.env.SCANNERS_ROLLOUT_ALLOWLIST;
  if (!raw) return true;
  const list = raw.split(',').map((s) => s.trim()).filter(Boolean);
  if (list.length === 0) return true;
  return list.includes(orgId);
}

// ---------------------------------------------------------------------------
// Tenancy-scoped reads. Both helpers chain the project_id / organization_id
// equality filter mandated by the plan's tenancy invariants — this is the
// load-bearing guard against the depscanner's service-role key returning
// cross-org rows. (Plan Patch 10 / WPA-r2-1.)
// ---------------------------------------------------------------------------

interface CredentialMetadataRow {
  id: string;
  registry_type: RegistryType;
  registry_url: string | null;
  credential_shape: string;
  encryption_key_version: number;
}

export async function listCredentialMetadata(
  supabase: SupabaseClient,
  organizationId: string
): Promise<CredentialMetadataRow[]> {
  const { data, error } = await supabase
    .from('organization_registry_credentials')
    .select('id, registry_type, registry_url, credential_shape, encryption_key_version')
    .eq('organization_id', organizationId);
  if (error) throw new Error(`listCredentialMetadata: ${error.message}`);
  return (data ?? []) as CredentialMetadataRow[];
}

interface ConfiguredImageRow {
  id: string;
  image_reference: string;
  credentials_id: string | null;
  enabled: boolean;
}

export async function listConfiguredImages(
  supabase: SupabaseClient,
  projectId: string
): Promise<ConfiguredImageRow[]> {
  const { data, error } = await supabase
    .from('project_configured_images')
    .select('id, image_reference, credentials_id, enabled')
    .eq('project_id', projectId)
    .eq('enabled', true);
  if (error) throw new Error(`listConfiguredImages: ${error.message}`);
  return (data ?? []) as ConfiguredImageRow[];
}

/**
 * Lazy-decrypt a single credential by id. Reads encrypted_credentials from
 * the row only at this moment (Patch 8 / FMH-P0-3) — never produced upstream
 * during cred-list metadata reads.
 *
 * Cross-checks the row's credential_shape column against the decrypted
 * plaintext.shape (the comment at registry-auth.ts promised this; previously
 * unimplemented). A swapped ciphertext — e.g. a token-shape row whose
 * encrypted_credentials was tampered to decrypt as aws_keys — is rejected
 * before mintAuthForCredential dispatches on the plaintext shape.
 */
export async function fetchAndDecryptCredential(
  supabase: SupabaseClient,
  credentialId: string,
  organizationId: string
): Promise<CredentialPlaintext> {
  const { data, error } = await supabase
    .from('organization_registry_credentials')
    .select('encrypted_credentials, encryption_key_version, credential_shape')
    .eq('id', credentialId)
    .eq('organization_id', organizationId)
    .single();
  if (error || !data) {
    throw new CredDecryptError(
      `cred lookup failed for id=${credentialId}: ${error?.message ?? 'no row'}`
    );
  }
  let plaintext: CredentialPlaintext;
  try {
    plaintext = decryptCredential(
      (data as any).encrypted_credentials,
      (data as any).encryption_key_version
    );
  } catch (e: any) {
    throw new CredDecryptError(`cred decrypt failed for id=${credentialId}: ${e?.message ?? e}`);
  }
  if (plaintext.shape !== (data as any).credential_shape) {
    throw new CredDecryptError(
      `cred shape mismatch for id=${credentialId}: row=${(data as any).credential_shape} plaintext=${plaintext.shape}`
    );
  }
  return plaintext;
}

/**
 * Resolve a single decrypted credential into a Docker auth entry (the
 * `{auth: base64('user:pass')}` shape ~/.docker/config.json expects).
 * Network-touching minters (ECR, ACR) wrap their failures in AuthMintError.
 */
export async function mintAuthForCredential(
  plaintext: CredentialPlaintext,
  registry_url: string | null
): Promise<DockerAuthEntry> {
  try {
    switch (plaintext.shape) {
      case 'username_password':
        return mintBasicAuth(plaintext);
      case 'token':
        return mintTokenAuth(plaintext);
      case 'gcp_service_account_key':
        return mintGcpAuth(plaintext);
      case 'aws_keys':
        return await mintEcrAuth(plaintext);
      case 'azure_service_principal':
        if (!registry_url) {
          throw new Error('ACR mint requires registry_url');
        }
        return await mintAzureAuth(plaintext, registry_url);
    }
  } catch (e: any) {
    throw new AuthMintError(`mint auth failed: ${e?.message ?? e}`);
  }
}

// ---------------------------------------------------------------------------
// Plan building
// ---------------------------------------------------------------------------

export type ImageSource = 'dockerfile_base' | 'configured_image';

export interface ImagePlanEntry {
  imageRef: string;
  source: ImageSource;
  /** Credential row matched to this image's host, or null when public/ghcr-App. */
  credId: string | null;
  /** Hostname used for DOCKER_CONFIG keying (only set when credId is set). */
  credHostname: string | null;
  /** True for Dockerfile-derived ghcr.io images that have no explicit cred —
   *  the orchestrator falls back to a GitHub App installation token + namespace
   *  check. v1 ghcr semantics preserved here. */
  allowGhcrAppFallback: boolean;
}

/**
 * Build the per-image plan from Dockerfile final stages + configured images.
 * Pure function — exported for unit testing; consumes only what the orchestrator
 * has already loaded.
 */
export function buildImagePlan(
  inputs: {
    dockerfileImageRefs: string[];
    configuredImages: ConfiguredImageRow[];
    creds: CredentialMetadataRow[];
  }
): ImagePlanEntry[] {
  const plan: ImagePlanEntry[] = [];
  const credRefs: ConfiguredCredRef[] = inputs.creds.map((c) => ({
    id: c.id,
    registry_type: c.registry_type,
    registry_url: c.registry_url,
  }));

  for (const imageRef of inputs.dockerfileImageRefs) {
    const strategy = resolvePullStrategy(imageRef, credRefs);
    if (strategy.kind === 'public') {
      plan.push({
        imageRef,
        source: 'dockerfile_base',
        credId: null,
        credHostname: null,
        allowGhcrAppFallback: false,
      });
    } else if (strategy.kind === 'authenticated') {
      plan.push({
        imageRef,
        source: 'dockerfile_base',
        credId: strategy.credId,
        credHostname: strategy.hostname,
        allowGhcrAppFallback: false,
      });
    } else {
      // No matching cred — for ghcr.io images, allow App-token fallback
      // (preserves v1 namespace-checked behaviour). Other private registries
      // skip outright.
      const ghcrOwner = extractGhcrOwner(imageRef);
      plan.push({
        imageRef,
        source: 'dockerfile_base',
        credId: null,
        credHostname: null,
        allowGhcrAppFallback: ghcrOwner !== null,
      });
    }
  }

  for (const ci of inputs.configuredImages) {
    if (ci.credentials_id) {
      const cred = inputs.creds.find((c) => c.id === ci.credentials_id);
      if (!cred) {
        // Cred row referenced but not present in the org's cred list —
        // attribute-mismatch (the credentials_same_org_fk should have
        // prevented this DB-side; treat as misconfigured).
        plan.push({
          imageRef: ci.image_reference,
          source: 'configured_image',
          credId: null,
          credHostname: null,
          allowGhcrAppFallback: false,
        });
        continue;
      }
      let hostname: string | null = null;
      try {
        hostname = resolveRegistryHostname(cred.registry_type, cred.registry_url);
      } catch {
        hostname = null;
      }
      plan.push({
        imageRef: ci.image_reference,
        source: 'configured_image',
        credId: ci.credentials_id,
        credHostname: hostname,
        allowGhcrAppFallback: false,
      });
    } else {
      // No cred attached → public pull only (resolvePullStrategy still applies).
      const strategy = resolvePullStrategy(ci.image_reference, credRefs);
      if (strategy.kind === 'public') {
        plan.push({
          imageRef: ci.image_reference,
          source: 'configured_image',
          credId: null,
          credHostname: null,
          allowGhcrAppFallback: false,
        });
      } else if (strategy.kind === 'authenticated') {
        plan.push({
          imageRef: ci.image_reference,
          source: 'configured_image',
          credId: strategy.credId,
          credHostname: strategy.hostname,
          allowGhcrAppFallback: false,
        });
      } else {
        plan.push({
          imageRef: ci.image_reference,
          source: 'configured_image',
          credId: null,
          credHostname: null,
          allowGhcrAppFallback: false,
        });
      }
    }
  }

  return plan;
}

// ---------------------------------------------------------------------------
// DOCKER_CONFIG dir lifecycle
// ---------------------------------------------------------------------------

interface AuthEnvelopeContext {
  dockerConfigDir: string;
  /** Live entries — kept so the ghcr App-token fallback can append without
   *  losing existing host entries. */
  entries: Array<readonly [string, DockerAuthEntry]>;
  /** Hosts we successfully wrote credentials for. */
  authedHosts: Set<string>;
  /** Decrypts already performed, capped by DECRYPT_BUDGET. */
  decryptCount: number;
}

async function buildDockerConfigDir(
  ctx: ScannerStepContext,
  plan: ImagePlanEntry[],
  switches: KillSwitchContext
): Promise<AuthEnvelopeContext> {
  const dir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'deptex-scan-'));
  await fsPromises.chmod(dir, 0o700);
  const authedHosts = new Set<string>();
  const entries: Array<readonly [string, DockerAuthEntry]> = [];
  let decryptCount = 0;

  if (switches.registryAuthKilled || switches.credDecryptKilled) {
    // Skip the per-cred decrypt + mint loop entirely; the resulting empty
    // config.json forces every private image into the no-auth path (which
    // skipReason='auth_disabled' if it can't pull).
    await writeConfigJson(dir, entries);
    return { dockerConfigDir: dir, entries, authedHosts, decryptCount };
  }

  // Walk distinct cred ids in the plan once; each cred maps to one host entry.
  const distinctCredIds = new Set<string>();
  for (const p of plan) if (p.credId) distinctCredIds.add(p.credId);

  for (const credId of distinctCredIds) {
    if (decryptCount >= DECRYPT_BUDGET) {
      ctx.logger.warn('container_scan.decrypt_creds', `decrypt budget exhausted (${DECRYPT_BUDGET})`).catch(() => {});
      break;
    }
    try {
      const plaintext = await fetchAndDecryptCredential(
        ctx.supabase,
        credId,
        ctx.organizationId
      );
      decryptCount++;
      // Find the matching plan entry to recover the hostname (each cred
      // resolves to one host).
      const planEntry = plan.find((p) => p.credId === credId);
      if (!planEntry || !planEntry.credHostname) continue;
      const auth = await mintAuthForCredential(plaintext, planEntry.credHostname);
      entries.push([planEntry.credHostname, auth]);
      authedHosts.add(planEntry.credHostname);
    } catch (e: any) {
      // Per Patch 8 — per-cred failure doesn't abort envelope build; the
      // affected images later skip with cred_decrypt_failed / auth_mint_failed.
      ctx.logger
        .warn(
          'container_scan.build_auth_envelope',
          `cred ${credId} skipped: ${e?.message ?? e}`
        )
        .catch(() => {});
    }
  }

  await writeConfigJson(dir, entries);
  return { dockerConfigDir: dir, entries, authedHosts, decryptCount };
}

async function writeConfigJson(
  dir: string,
  entries: ReadonlyArray<readonly [string, DockerAuthEntry]>
): Promise<void> {
  const json = buildDockerAuthConfig(entries);
  await fsPromises.writeFile(path.join(dir, 'config.json'), json, { mode: 0o600 });
}

async function shredAndRemoveDir(dir: string): Promise<void> {
  // Best-effort overwrite of any auth blob before unlink, then rm -rf.
  try {
    const cfg = path.join(dir, 'config.json');
    if (fs.existsSync(cfg)) {
      const sz = fs.statSync(cfg).size;
      await fsPromises.writeFile(cfg, '0'.repeat(Math.min(sz, 4096)));
    }
  } catch {
    /* shred is best-effort; the rm below is the actual cleanup */
  }
  await fsPromises.rm(dir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Per-image scan — owns its substep taxonomy + try/catch. NEVER rethrows.
// ---------------------------------------------------------------------------

async function scanOneImage(
  image: ImagePlanEntry,
  ctx: ScannerStepContext,
  envelope: AuthEnvelopeContext,
  switches: KillSwitchContext,
  installationLogin: string | null
): Promise<{ findings: ContainerFinding[] } | { skipped: SkippedImage }> {
  // ---- scan-time SSRF re-check (defeats DNS rebinding between create-time
  // host validation in the route layer and now). If the registry host
  // re-resolves to a private/loopback/IMDS/Fly-6PN range, skip the image
  // before any crane / Trivy invocation.
  const hostGuard = await validateScanTimeHost(image.imageRef, 'imageRef');
  if (!hostGuard.valid) {
    ctx.logger
      .warn('container_scan.host_blocked', `${image.imageRef}: ${hostGuard.reason}`)
      .catch(() => {});
    return { skipped: { image: image.imageRef, reason: 'image_host_blocked' } };
  }

  // ---- ghcr App-token fallback path: write the App token into envelope on
  // demand. The namespace check is enforced HERE (only on this fallback);
  // explicit ghcr creds bypass it.
  const ghcrOwner = extractGhcrOwner(image.imageRef);
  if (
    image.allowGhcrAppFallback &&
    ghcrOwner &&
    !switches.registryAuthKilled &&
    !switches.credDecryptKilled
  ) {
    if (!ctx.githubInstallationId || !installationLogin) {
      return { skipped: { image: image.imageRef, reason: 'ghcr_namespace_mismatch' } };
    }
    if (ghcrOwner.toLowerCase() !== installationLogin.toLowerCase()) {
      return { skipped: { image: image.imageRef, reason: 'ghcr_namespace_mismatch' } };
    }
    if (!envelope.authedHosts.has('ghcr.io')) {
      try {
        const token = await createInstallationToken(ctx.githubInstallationId);
        // ghcr.io with a GitHub App token uses x-access-token as the username.
        const auth = {
          auth: Buffer.from(`x-access-token:${token}`, 'utf8').toString('base64'),
        };
        envelope.entries.push(['ghcr.io', auth]);
        await writeConfigJson(envelope.dockerConfigDir, envelope.entries);
        envelope.authedHosts.add('ghcr.io');
      } catch (e: any) {
        ctx.logger
          .warn('container_scan.mint_auth', `ghcr App token mint failed: ${e?.message ?? e}`)
          .catch(() => {});
        return { skipped: { image: image.imageRef, reason: 'auth_mint_failed' } };
      }
    }
  } else if (
    image.credId === null &&
    !image.allowGhcrAppFallback &&
    !isPublicImage(image.imageRef)
  ) {
    // No public path, no cred, no App fallback → can't pull.
    if (switches.registryAuthKilled) {
      return { skipped: { image: image.imageRef, reason: 'auth_disabled' } };
    }
    return { skipped: { image: image.imageRef, reason: 'no_matching_cred' } };
  }

  // ---- digest_probe + cache_lookup ------------------------------------
  let probedDigest: string | null = null;
  if (!switches.digestCacheKilled) {
    try {
      probedDigest = await resolveImageDigest(image.imageRef, {
        dockerConfigDir: envelope.dockerConfigDir,
      });
    } catch (err) {
      const cls = classifyContainerScanError(err);
      ctx.logger
        .warn('container_scan.digest_probe', `${image.imageRef}: ${cls.message}`)
        .catch(() => {});
      // RegistryUnavailableError → fall through to a cache-bypassing scan
      // (degraded but correct). Other errors short-circuit with the
      // classified skip reason.
      if (!(err instanceof RegistryUnavailableError)) {
        return { skipped: { image: image.imageRef, reason: cls.skipReason } };
      }
    }
  }

  if (probedDigest) {
    try {
      const hit = await lookupContainerScanCache(ctx.supabase, {
        image_digest: probedDigest,
        scanner: 'trivy',
        scanner_version: `trivy@${await trivyVersion()}`,
        trivy_db_version_day: await trivyDbVersionDay(),
      });
      if (hit) {
        // Rewrite image_reference on every cached row so cross-org cache
        // hits don't leak the original org's pull string.
        const rewritten = hit.findings.map((f) => ({
          ...f,
          image_reference: image.imageRef,
        }));
        return { findings: rewritten };
      }
    } catch (e: any) {
      ctx.logger
        .warn('container_scan.cache_lookup', `${image.imageRef}: ${e?.message ?? e}`)
        .catch(() => {});
      // Cache lookup failure is non-fatal — fall through to a Trivy run.
    }
  }

  // ---- trivy_pull -----------------------------------------------------
  let trivyResult: Awaited<ReturnType<typeof runTrivyImage>>;
  try {
    trivyResult = await withTimeout(
      async (signal) =>
        runTrivyImage({
          imageRef: image.imageRef,
          dockerConfigDir: envelope.dockerConfigDir,
          signal,
          onHeartbeat: ctx.onHeartbeat,
          logger: ctx.logger,
          verboseLog: VERBOSE_TRIVY,
        }),
      TRIVY_IMAGE_TIMEOUT_MS,
      'container_scan.trivy_pull'
    );
  } catch (err) {
    const cls = classifyContainerScanError(err);
    ctx.logger
      .warn('container_scan.trivy_pull', `${image.imageRef}: ${cls.message}`)
      .catch(() => {});
    return { skipped: { image: image.imageRef, reason: cls.skipReason } };
  }

  // 4-guard cache contract (Patch 3): exit clean, no warnings, structurally
  // valid parse, probe digest matches RepoDigest. If the run produced
  // findings but failed any guard, we return findings WITHOUT writing the
  // cache — better to scan again next time than to poison the global cache.
  let cacheWriteAllowed = true;
  if (trivyResult.warnings.length > 0) cacheWriteAllowed = false;
  let parsedDigest: string | null = null;
  if (trivyResult.imageDigest) {
    try {
      parsedDigest = normalizeDigest(trivyResult.imageDigest);
    } catch {
      cacheWriteAllowed = false;
    }
  } else {
    cacheWriteAllowed = false;
  }
  if (probedDigest && parsedDigest && probedDigest !== parsedDigest) {
    ctx.logger
      .warn(
        'container_scan.trivy_pull',
        `digest mismatch for ${image.imageRef}: probe=${probedDigest} trivy=${parsedDigest}`
      )
      .catch(() => {});
    cacheWriteAllowed = false;
  }

  // ---- cache_upsert ---------------------------------------------------
  if (cacheWriteAllowed && !switches.digestCacheKilled && parsedDigest) {
    try {
      await upsertContainerScanCache(
        ctx.supabase,
        {
          image_digest: parsedDigest,
          scanner: 'trivy',
          scanner_version: trivyResult.version,
          trivy_db_version_day: await trivyDbVersionDay(),
        },
        trivyResult.findings,
        ctx.organizationId,
        ctx.runId
      );
    } catch (e: any) {
      ctx.logger
        .warn('container_scan.cache_upsert', `${image.imageRef}: ${e?.message ?? e}`)
        .catch(() => {});
    }
  }

  return { findings: trivyResult.findings };
}

const PUBLIC_HOSTS = new Set([
  'docker.io',
  'index.docker.io',
  'registry-1.docker.io',
  'public.ecr.aws',
  'mcr.microsoft.com',
]);

function isPublicImage(imageRef: string): boolean {
  const noDigest = imageRef.split('@')[0];
  const firstSlash = noDigest.indexOf('/');
  if (firstSlash === -1) return true;
  const firstSegment = noDigest.slice(0, firstSlash);
  const looksLikeHost =
    firstSegment === 'localhost' ||
    /\./.test(firstSegment) ||
    /:\d+$/.test(firstSegment);
  if (!looksLikeHost) return true; // bare-name → docker.io
  return PUBLIC_HOSTS.has(firstSegment);
}

// ---------------------------------------------------------------------------
// Container scan loop
// ---------------------------------------------------------------------------

async function scanContainerImages(
  ctx: ScannerStepContext,
  switches: KillSwitchContext
): Promise<{
  findings: { dockerfile: ContainerFinding[]; configured: ContainerFinding[] };
  skipped: SkippedImage[];
  warnings: string[];
}> {
  const skipped: SkippedImage[] = [];
  const warnings: string[] = [];
  const dockerfileFindings: ContainerFinding[] = [];
  const configuredFindings: ContainerFinding[] = [];

  // Step 1 — metadata reads (no decryption yet; tenancy guards inside).
  const dockerfilePaths = findDockerfiles(ctx.repoPath);
  const dockerfileImageRefs: string[] = [];
  for (const dp of dockerfilePaths) {
    const stage = parseDockerfileFinalStage(dp);
    if (!stage) {
      skipped.push({ image: dp, reason: 'parse_failed' });
      continue;
    }
    dockerfileImageRefs.push(stage.imageRef);
  }

  let creds: CredentialMetadataRow[] = [];
  if (!switches.credDecryptKilled) {
    try {
      creds = await listCredentialMetadata(ctx.supabase, ctx.organizationId);
    } catch (e: any) {
      warnings.push(`cred_list_failed:${e?.message ?? 'unknown'}`);
    }
  }

  let configuredImages: ConfiguredImageRow[] = [];
  if (!switches.configuredImagesKilled) {
    try {
      configuredImages = await listConfiguredImages(ctx.supabase, ctx.projectId);
    } catch (e: any) {
      warnings.push(`configured_image_list_failed:${e?.message ?? 'unknown'}`);
    }
  }

  // Step 2 — plan
  const plan = buildImagePlan({ dockerfileImageRefs, configuredImages, creds });
  if (plan.length === 0) {
    return {
      findings: { dockerfile: [], configured: [] },
      skipped,
      warnings,
    };
  }

  // GitHub installation account resolved once for the App-token fallback.
  let installationLogin: string | null = null;
  if (ctx.githubInstallationId && plan.some((p) => p.allowGhcrAppFallback)) {
    try {
      const acct = await getInstallationAccount(ctx.githubInstallationId);
      installationLogin = acct?.login.toLowerCase() ?? null;
    } catch {
      installationLogin = null;
    }
  }

  // Step 3 — DOCKER_CONFIG dir lifecycle
  const envelope = await buildDockerConfigDir(ctx, plan, switches);
  const stepStart = Date.now();
  try {
    for (const image of plan) {
      if (Date.now() - stepStart > CONTAINER_SCAN_TOTAL_BUDGET_MS) {
        skipped.push({ image: image.imageRef, reason: 'budget_exhausted' });
        continue;
      }
      const result = await scanOneImage(image, ctx, envelope, switches, installationLogin);
      if ('findings' in result) {
        if (image.source === 'dockerfile_base') {
          dockerfileFindings.push(...result.findings);
        } else {
          configuredFindings.push(...result.findings);
        }
      } else {
        skipped.push(result.skipped);
      }
    }
  } finally {
    await shredAndRemoveDir(envelope.dockerConfigDir);
  }

  return {
    findings: { dockerfile: dockerfileFindings, configured: configuredFindings },
    skipped,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Entry point — IaC + container in one step
// ---------------------------------------------------------------------------

export async function runIaCAndContainerScans(
  ctx: ScannerStepContext
): Promise<ScannerSummary> {
  const summary: ScannerSummary = {
    infraTypes: [],
    iacFindingsWritten: 0,
    containerFindingsWritten: 0,
    skippedImages: [],
    warnings: [],
  };

  if (!isAllowedOrg(ctx.organizationId)) {
    summary.warnings.push('rollout_allowlist_excluded');
    await ctx.logger.warn('detect_infra', 'Org not in SCANNERS_ROLLOUT_ALLOWLIST — skipping');
    return summary;
  }

  const switches = await resolveKillSwitches();
  if (switches.redisFallback) {
    summary.warnings.push('redis_kill_switch_unreachable');
    await ctx.logger.warn(
      'detect_infra',
      'Redis kill-switch lookup failed; falling back to env flags'
    );
  }

  await ctx.logger.info('detect_infra', 'Scanning workspace for infra files...');
  const infraTypes = detectInfraTypes(ctx.repoPath);
  summary.infraTypes = infraTypes;
  if (infraTypes.length === 0 && !switches.containerEnabled) {
    await ctx.logger.info('detect_infra', 'No infra files detected — skipping IaC + container scans');
    return summary;
  }
  if (infraTypes.length > 0) {
    await ctx.logger.info('detect_infra', `Detected: ${infraTypes.join(', ')}`);
  }

  // ---- IaC scan (Checkov + Trivy config in parallel) ----
  if (!switches.iacEnabled) {
    summary.warnings.push('iac_disabled_by_env');
    await ctx.logger.warn('iac_scan', 'SCANNERS_IAC_ENABLED=false — skipping IaC scan');
  } else if (infraTypes.length === 0) {
    // No IaC files; skip without warning — container path may still run.
  } else {
    const iacFindings: IaCFinding[] = [];
    const iacFrameworks: IaCFramework[] = infraTypes.filter(
      (t): t is Exclude<IaCFramework, 'dockerfile'> => t !== 'dockerfile'
    );

    const tasks: Array<Promise<void>> = [];

    if (!switches.checkovKilled && iacFrameworks.length > 0) {
      tasks.push(
        (async () => {
          try {
            const result = await withTimeout(
              async (signal) =>
                runCheckov({
                  repoPath: ctx.repoPath,
                  frameworks: iacFrameworks,
                  signal,
                  onHeartbeat: ctx.onHeartbeat,
                  logger: ctx.logger,
                  verboseLog: VERBOSE_CHECKOV,
                }),
              CHECKOV_TIMEOUT_MS,
              'iac_scan_checkov'
            );
            iacFindings.push(...result.findings);
            summary.warnings.push(...result.warnings);
          } catch (err: any) {
            summary.warnings.push(`checkov_failed:${err?.message ?? 'unknown'}`);
            await logStepError(ctx.supabase as any, {
              jobId: ctx.jobId ?? 'unknown',
              projectId: ctx.projectId,
              step: 'iac_scan_checkov',
              ...classifyError(err),
              severity: 'warn',
            });
          }
        })()
      );
    } else if (switches.checkovKilled) {
      summary.warnings.push('checkov_killswitch');
      await ctx.logger.warn('iac_scan', 'kill:scanner:checkov is set — skipping');
    }

    const hasDockerfile = infraTypes.includes('dockerfile');
    if (!switches.trivyKilled && hasDockerfile) {
      tasks.push(
        (async () => {
          try {
            const result = await withTimeout(
              async (signal) =>
                runTrivyConfig({
                  repoPath: ctx.repoPath,
                  signal,
                  onHeartbeat: ctx.onHeartbeat,
                  logger: ctx.logger,
                  verboseLog: VERBOSE_TRIVY,
                }),
              TRIVY_CONFIG_TIMEOUT_MS,
              'iac_scan_trivy'
            );
            iacFindings.push(...result.findings);
            summary.warnings.push(...result.warnings);
          } catch (err: any) {
            summary.warnings.push(`trivy_config_failed:${err?.message ?? 'unknown'}`);
            await logStepError(ctx.supabase as any, {
              jobId: ctx.jobId ?? 'unknown',
              projectId: ctx.projectId,
              step: 'iac_scan_trivy',
              ...classifyError(err),
              severity: 'warn',
            });
          }
        })()
      );
    } else if (switches.trivyKilled) {
      summary.warnings.push('trivy_killswitch');
      await ctx.logger.warn('iac_scan', 'kill:scanner:trivy is set — skipping');
    }

    await Promise.all(tasks);

    try {
      const upsert = await upsertIaCFindings(
        ctx.supabase,
        ctx.projectId,
        ctx.runId,
        iacFindings
      );
      summary.iacFindingsWritten = upsert.inserted;
      await ctx.logger.info(
        'iac_scan',
        `IaC scan complete — ${upsert.inserted} findings written`
      );
    } catch (err: any) {
      summary.warnings.push(`iac_storage_failed:${err?.message ?? 'unknown'}`);
      await logStepError(ctx.supabase as any, {
        jobId: ctx.jobId ?? 'unknown',
        projectId: ctx.projectId,
        step: 'iac_scan_storage',
        ...classifyError(err),
        severity: 'warn',
      });
    }
  }

  // ---- Container scan (Dockerfile final-stage + configured images) ----
  if (!switches.containerEnabled) {
    summary.warnings.push('container_disabled_by_env');
    await ctx.logger.warn(
      'container_scan',
      'SCANNERS_CONTAINER_ENABLED=false — skipping container scan'
    );
  } else if (switches.trivyKilled) {
    summary.warnings.push('container_skipped_trivy_killswitch');
    await ctx.logger.warn(
      'container_scan',
      'kill:scanner:trivy is set — skipping container scan'
    );
  } else {
    try {
      const containerResult = await scanContainerImages(ctx, switches);
      summary.skippedImages.push(...containerResult.skipped);
      summary.warnings.push(...containerResult.warnings);

      // Two batches because image_source differs per row. Could collapse via
      // per-finding stamping but keeping the calls separate keeps the upsert
      // payloads small + makes the source attribution explicit at the
      // database boundary.
      const dfUpsert = await upsertContainerFindings(
        ctx.supabase,
        ctx.projectId,
        ctx.runId,
        containerResult.findings.dockerfile,
        'dockerfile_base'
      );
      const ciUpsert = await upsertContainerFindings(
        ctx.supabase,
        ctx.projectId,
        ctx.runId,
        containerResult.findings.configured,
        'configured_image'
      );
      summary.containerFindingsWritten = dfUpsert.inserted + ciUpsert.inserted;
      await ctx.logger.info(
        'container_scan',
        `Container scan complete — ${summary.containerFindingsWritten} findings written, ${containerResult.skipped.length} images skipped`
      );
    } catch (err: any) {
      summary.warnings.push(`container_failed:${err?.message ?? 'unknown'}`);
      await logStepError(ctx.supabase as any, {
        jobId: ctx.jobId ?? 'unknown',
        projectId: ctx.projectId,
        step: 'container_scan',
        ...classifyError(err),
        severity: 'warn',
      });
    }
  }

  return summary;
}

export const SCANNER_TIMEOUTS = {
  CHECKOV_TIMEOUT_MS,
  TRIVY_CONFIG_TIMEOUT_MS,
  TRIVY_IMAGE_TIMEOUT_MS,
  CONTAINER_SCAN_TOTAL_BUDGET_MS,
};

/** Used by the rescan endpoint — exposed for parity with depscan setup. */
export function ensureWorkspaceTmp(): string {
  const tmp = path.join(os.tmpdir(), 'deptex-iac-cache');
  try {
    fs.mkdirSync(tmp, { recursive: true });
  } catch {
    /* non-fatal */
  }
  return tmp;
}

// Internal exports for test harnesses.
export const _internal = {
  isPublicImage,
  scanOneImage,
};
