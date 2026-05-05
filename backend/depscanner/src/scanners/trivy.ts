import * as fs from 'fs';
import { execFile } from 'child_process';
import { runScannerSubprocess, type ScannerSubprocessLogger } from '../with-timeout';
import { resolveRegistryHostname } from './registry-auth';
import type {
  ContainerFinding,
  IaCFinding,
  IaCFramework,
  RegistryType,
  SkippedImage,
} from './types';

// ============================================================
// Multi-stage Dockerfile parsing — Patch E
// ============================================================

const FROM_LINE_RE =
  /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+([A-Za-z0-9_-]+))?\s*$/i;

export interface DockerfileStage {
  imageRef: string;
  alias: string | null;
  /** 0-indexed position of this FROM in the file. */
  index: number;
}

export interface DockerfileFinalStage {
  imageRef: string;
  stageIndex: number;
  totalStages: number;
}

/**
 * Parse all FROM directives from a Dockerfile and return the FINAL stage —
 * the image that ships to production. v1 returns the last FROM regardless of
 * inter-stage references; intermediate `AS builder` stages are intentionally
 * not scanned at v1 (their findings would be noise — they don't ship).
 *
 * Returns null when no FROM lines parse cleanly, or when the final stage is
 * `scratch` (which has no userland packages to scan).
 */
export function parseDockerfileFinalStage(
  dockerfilePath: string
): DockerfileFinalStage | null {
  let text: string;
  try {
    text = fs.readFileSync(dockerfilePath, 'utf8');
  } catch {
    return null;
  }
  const stages: DockerfileStage[] = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const m = FROM_LINE_RE.exec(line);
    if (!m) continue;
    stages.push({ imageRef: m[1], alias: m[2] ?? null, index: stages.length });
  }
  if (stages.length === 0) return null;
  const final = stages[stages.length - 1];
  if (/^scratch(:|@|$)/i.test(final.imageRef)) return null;
  return {
    imageRef: final.imageRef,
    stageIndex: final.index,
    totalStages: stages.length,
  };
}

// ============================================================
// Container pull eligibility — Patch C
// ============================================================

export type PullEligibility =
  | { kind: 'public_dockerhub' }
  | { kind: 'ghcr'; owner: string }
  | { kind: 'unsupported_registry' };

const KNOWN_REGISTRY_HOSTS = new Set([
  'docker.io',
  'index.docker.io',
  'registry-1.docker.io',
  'ghcr.io',
  'public.ecr.aws',
  'quay.io',
  'gcr.io',
  'mcr.microsoft.com',
]);

/**
 * Classify a Docker image reference for v1 pull policy.
 *
 *   docker.io/library/node:20  → public_dockerhub
 *   node:20                    → public_dockerhub (bare-name resolves to docker.io/library)
 *   ghcr.io/<owner>/foo:tag    → ghcr (owner returned for namespace check)
 *   anything else with a host  → unsupported_registry
 */
export function classifyImageRef(imageRef: string): PullEligibility {
  // Strip digest pin if present.
  const noDigest = imageRef.split('@')[0];
  const firstSlash = noDigest.indexOf('/');

  // Docker CLI rule: a host must precede the first "/", AND the segment
  // before that "/" must look like a host (contains ".", contains ":<port>",
  // or is the literal "localhost"). When there's no "/", it's always a bare
  // name in the docker.io/library namespace — `:` there is the tag separator,
  // not a port.
  if (firstSlash === -1) {
    return { kind: 'public_dockerhub' };
  }
  const firstSegment = noDigest.slice(0, firstSlash);
  const looksLikeHost =
    firstSegment === 'localhost' ||
    /\./.test(firstSegment) ||
    /:\d+$/.test(firstSegment);

  if (!looksLikeHost) {
    // e.g. "library/node:20" — bare-name with explicit library prefix.
    return { kind: 'public_dockerhub' };
  }

  if (
    firstSegment === 'docker.io' ||
    firstSegment === 'index.docker.io' ||
    firstSegment === 'registry-1.docker.io'
  ) {
    return { kind: 'public_dockerhub' };
  }

  if (firstSegment === 'ghcr.io') {
    const rest = noDigest.slice(firstSlash + 1);
    const owner = rest.split('/')[0]?.split(':')[0] ?? '';
    if (!owner) return { kind: 'unsupported_registry' };
    return { kind: 'ghcr', owner };
  }

  // Any other host (ECR, GCR, ACR, Quay, Harbor, JFrog, private docker.io) → skip.
  return { kind: 'unsupported_registry' };
}

// ============================================================
// Trivy IaC (config) — Dockerfile misconfig
// ============================================================

const TRIVY_RULE_RE = /^trivy:[A-Z0-9-]+:[\w./@\-+:#=,]+$/;

interface TrivyConfigMisconfig {
  ID?: string;
  AVDID?: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  PrimaryURL?: string;
  CauseMetadata?: {
    Resource?: string;
    StartLine?: number;
    EndLine?: number;
    Code?: { Lines?: Array<{ Number: number; Content: string }> };
  };
}

interface TrivyConfigResult {
  Target?: string;
  Class?: string;
  Type?: string;
  Misconfigurations?: TrivyConfigMisconfig[];
}

interface TrivyConfigReport {
  Results?: TrivyConfigResult[];
  ArtifactName?: string;
}

function trivyFingerprint(rule: TrivyConfigMisconfig, target: string): string | null {
  const ruleId = rule.AVDID ?? rule.ID;
  const cause = rule.CauseMetadata?.Resource || target;
  if (!ruleId || !cause) return null;
  const fp = `trivy:${ruleId}:${cause}`;
  if (!TRIVY_RULE_RE.test(fp)) return null;
  return fp;
}

function trivySnippet(misconfig: TrivyConfigMisconfig): string | null {
  const lines = misconfig.CauseMetadata?.Code?.Lines;
  if (!lines || lines.length === 0) return null;
  return lines.map((l) => l.Content).join('\n').trimEnd() || null;
}

/**
 * Parse `trivy config --format json --scanners=misconfig` output and emit
 * Dockerfile findings only — Checkov already covers TF/K8s, so trivy config's
 * overlapping coverage is intentionally dropped to avoid duplicate rows.
 */
export function parseTrivyConfigOutput(stdout: string, version: string): IaCFinding[] {
  let parsed: TrivyConfigReport | null = null;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  if (!parsed || !Array.isArray(parsed.Results)) return [];

  const out: IaCFinding[] = [];
  for (const result of parsed.Results) {
    const isDockerfile =
      result.Type === 'dockerfile' ||
      /Dockerfile(\..+)?$/i.test(result.Target ?? '');
    if (!isDockerfile) continue;
    const target = (result.Target ?? '').replace(/^\//, '');
    if (!target) continue;
    const misconfigs = result.Misconfigurations ?? [];
    for (const m of misconfigs) {
      const ruleId = m.AVDID ?? m.ID;
      if (!ruleId) continue;
      const sev = (m.Severity ?? '').toUpperCase();
      out.push({
        scanner: 'trivy',
        scanner_version: version,
        rule_id: ruleId,
        framework: 'dockerfile',
        file_path: target,
        start_line: m.CauseMetadata?.StartLine ?? null,
        end_line: m.CauseMetadata?.EndLine ?? null,
        severity:
          ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(sev) ? sev : null,
        message: m.Title ?? null,
        description: m.Description ?? null,
        cwe_ids: [],
        code_snippet: trivySnippet(m),
        rule_doc_url: m.PrimaryURL ?? null,
        iac_fingerprint: trivyFingerprint(m, target),
        compliance_refs: null,
        metadata: null,
      });
    }
  }
  return out;
}

export interface RunTrivyConfigOptions {
  repoPath: string;
  signal?: AbortSignal;
  onHeartbeat?: () => Promise<void> | void;
  logger?: ScannerSubprocessLogger;
  verboseLog?: boolean;
}

export async function runTrivyConfig(
  opts: RunTrivyConfigOptions
): Promise<{ findings: IaCFinding[]; version: string; warnings: string[] }> {
  const warnings: string[] = [];
  const version = await trivyVersion();
  const result = await runScannerSubprocess({
    exe: 'trivy',
    args: [
      'config',
      '--format', 'json',
      '--skip-db-update',
      '--scanners=misconfig',
      opts.repoPath,
    ],
    cwd: opts.repoPath,
    signal: opts.signal,
    onHeartbeat: opts.onHeartbeat,
    logger: opts.logger,
    verboseLog: opts.verboseLog,
    verboseLogStep: 'iac_scan',
  });
  if (result.exitCode !== 0 && result.exitCode !== 1) {
    warnings.push(`trivy_config_exit_${result.exitCode}`);
    return { findings: [], version: `trivy@${version}`, warnings };
  }
  const findings = parseTrivyConfigOutput(result.stdout, `trivy@${version}`);
  return { findings, version: `trivy@${version}`, warnings };
}

// ============================================================
// Trivy image — container CVE scan
// ============================================================

interface TrivyImageVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  CVSS?: Record<string, { V3Score?: number; V2Score?: number }>;
  PrimaryURL?: string;
  Description?: string;
  Title?: string;
  Layer?: { Digest?: string };
  PublishedDate?: string;
  CweIDs?: string[];
  References?: string[];
}

interface TrivyImageResult {
  Target?: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyImageVuln[];
}

interface TrivyImageReport {
  ArtifactName?: string;
  Metadata?: {
    ImageID?: string;
    RepoDigests?: string[];
    DiffIDs?: string[];
  };
  Results?: TrivyImageResult[];
}

function bestCvss(v: TrivyImageVuln): number | null {
  if (!v.CVSS) return null;
  let best: number | null = null;
  for (const k of Object.keys(v.CVSS)) {
    const score = v.CVSS[k]?.V3Score ?? v.CVSS[k]?.V2Score;
    if (typeof score === 'number' && (best === null || score > best)) best = score;
  }
  return best;
}

export function parseTrivyImageOutput(
  stdout: string,
  imageReference: string,
  version: string
): { findings: ContainerFinding[]; imageDigest: string } {
  let parsed: TrivyImageReport | null = null;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return { findings: [], imageDigest: '' };
  }
  if (!parsed) return { findings: [], imageDigest: '' };

  const imageDigest =
    parsed.Metadata?.RepoDigests?.[0] ?? parsed.Metadata?.ImageID ?? imageReference;

  const out: ContainerFinding[] = [];
  for (const result of parsed.Results ?? []) {
    if (result.Class !== 'os-pkgs' && result.Class !== 'lang-pkgs') continue;
    const ecosystem = result.Type ?? null;
    for (const v of result.Vulnerabilities ?? []) {
      if (!v.PkgName || !v.InstalledVersion) continue;
      const sev = (v.Severity ?? '').toUpperCase();
      const cveId = v.VulnerabilityID?.startsWith('CVE-') ? v.VulnerabilityID : null;
      const osvId = v.VulnerabilityID && !cveId ? v.VulnerabilityID : null;
      const fingerprintKey = cveId ?? osvId;
      const containerFingerprint = fingerprintKey
        ? `${v.PkgName}@${fingerprintKey}`
        : null;

      out.push({
        scanner_version: version,
        image_reference: imageReference,
        image_digest: imageDigest,
        os_package_name: v.PkgName,
        os_package_version: v.InstalledVersion,
        os_package_ecosystem: ecosystem,
        osv_id: osvId,
        cve_id: cveId,
        severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(sev) ? sev : null,
        cvss_score: bestCvss(v),
        epss_score: null,
        is_kev: false,
        fix_versions: v.FixedVersion ? v.FixedVersion.split(',').map((s) => s.trim()) : [],
        layer_digest: v.Layer?.Digest ?? null,
        description: v.Description ?? v.Title ?? null,
        rule_doc_url: v.PrimaryURL ?? null,
        container_fingerprint: containerFingerprint,
      });
    }
  }
  return { findings: out, imageDigest };
}

export interface RunTrivyImageOptions {
  imageRef: string;
  /** Per-scan ephemeral DOCKER_CONFIG dir (Patch 15). Trivy + crane both honor
   *  $DOCKER_CONFIG and read its config.json for registry auth. Preferred over
   *  the v1 dockerAuthConfig env var, which Trivy/crane do not consume. */
  dockerConfigDir?: string;
  /** Legacy: JSON string set as $DOCKER_AUTH_CONFIG. Kept until the M8 rewrite
   *  retires the v1 ghcr-only auth path. New callers should use dockerConfigDir. */
  dockerAuthConfig?: string;
  signal?: AbortSignal;
  onHeartbeat?: () => Promise<void> | void;
  logger?: ScannerSubprocessLogger;
  verboseLog?: boolean;
}

export async function runTrivyImage(
  opts: RunTrivyImageOptions
): Promise<{ findings: ContainerFinding[]; imageDigest: string; version: string; warnings: string[] }> {
  const warnings: string[] = [];
  const version = await trivyVersion();
  const env: Record<string, string | undefined> = {};
  if (opts.dockerConfigDir) {
    env.DOCKER_CONFIG = opts.dockerConfigDir;
  }
  if (opts.dockerAuthConfig) {
    env.DOCKER_AUTH_CONFIG = opts.dockerAuthConfig;
  }
  const result = await runScannerSubprocess({
    exe: 'trivy',
    args: [
      'image',
      '--format', 'json',
      '--scanners=vuln',
      // Pin platform so the manifest-list resolution is deterministic between
      // the crane digest probe and the Trivy pull. Without this, the cache key
      // (Trivy's RepoDigest) can diverge from the probe digest on multi-arch
      // images and we'd spuriously skip cache writes (Patch 3).
      '--platform', 'linux/amd64',
      opts.imageRef,
    ],
    signal: opts.signal,
    onHeartbeat: opts.onHeartbeat,
    logger: opts.logger,
    verboseLog: opts.verboseLog,
    verboseLogStep: 'container_scan',
    env,
  });
  if (result.exitCode !== 0 && result.exitCode !== 1) {
    warnings.push(`trivy_image_exit_${result.exitCode}`);
    return { findings: [], imageDigest: '', version: `trivy@${version}`, warnings };
  }
  const parsed = parseTrivyImageOutput(result.stdout, opts.imageRef, `trivy@${version}`);
  return {
    findings: parsed.findings,
    imageDigest: parsed.imageDigest,
    version: `trivy@${version}`,
    warnings,
  };
}

// ============================================================
// Helpers
// ============================================================

let cachedVersion: string | null = null;
async function trivyVersion(): Promise<string> {
  if (cachedVersion) return cachedVersion;
  try {
    const v = await runScannerSubprocess({
      exe: 'trivy',
      args: ['--version'],
      timeoutMs: 10_000,
    });
    const match = /Version:\s*(\S+)/i.exec(v.stdout);
    cachedVersion = match?.[1] ?? 'unknown';
  } catch {
    cachedVersion = 'unknown';
  }
  return cachedVersion;
}

export type { SkippedImage };

// ============================================================
// v2 — Digest normalization, pull strategy, and crane probe (M6)
// ============================================================

/**
 * Canonicalize a docker image digest to its bare 64-hex form. Accepts:
 *
 *   abcdef…64-hex                          → abcdef…
 *   sha256:abcdef…64-hex                   → abcdef…
 *   repo/path@sha256:abcdef…               → abcdef…
 *   registry.example/repo/path@sha256:…    → abcdef…
 *
 * The container_image_scan_cache primary key uses this canonical form. crane's
 * digest output is `sha256:<hex>` and Trivy's RepoDigests are `<repo>@sha256:<hex>` —
 * without normalization, lookups would miss every time. (Patch 3.)
 */
export function normalizeDigest(s: string): string {
  const m = s.match(/(?:^|@sha256:|^sha256:)([a-f0-9]{64})$/);
  if (!m) throw new Error(`invalid digest: ${s}`);
  return m[1];
}

export type PullStrategy =
  | { kind: 'public' }
  | { kind: 'authenticated'; credId: string; hostname: string }
  | { kind: 'skip'; reason: 'no_matching_cred' };

export interface ConfiguredCredRef {
  id: string;
  registry_type: RegistryType;
  registry_url: string | null;
}

const PUBLIC_PULL_HOSTS = new Set([
  'docker.io',
  'index.docker.io',
  'registry-1.docker.io',
  'public.ecr.aws',
  'mcr.microsoft.com',
]);

function extractImageHost(imageRef: string): { host: string; isImplicitDockerHub: boolean } {
  const noDigest = imageRef.split('@')[0];
  const firstSlash = noDigest.indexOf('/');
  if (firstSlash === -1) return { host: 'docker.io', isImplicitDockerHub: true };
  const firstSegment = noDigest.slice(0, firstSlash);
  const looksLikeHost =
    firstSegment === 'localhost' ||
    /\./.test(firstSegment) ||
    /:\d+$/.test(firstSegment);
  if (!looksLikeHost) return { host: 'docker.io', isImplicitDockerHub: true };
  return { host: firstSegment, isImplicitDockerHub: false };
}

/**
 * Resolve how the worker should pull a given image given the org's set of
 * configured registry credentials. Replaces v1's ghcr-only special case;
 * ghcr/quay/gcr now flow through the same cred-matching mechanism as ECR/ACR.
 *
 *   public          — anonymous pull (docker.io, public.ecr.aws, mcr.…)
 *   authenticated   — a cred whose hostname matches the image's host exists;
 *                     the cred id is returned for downstream decryption
 *   skip            — neither public nor cred-backed; orchestrator records
 *                     SkippedImage{ reason: 'private_registry_unsupported_at_v1' }
 *                     (or its v2 equivalent) and moves on
 */
export function resolvePullStrategy(
  imageRef: string,
  configuredCreds: ReadonlyArray<ConfiguredCredRef>
): PullStrategy {
  const { host } = extractImageHost(imageRef);

  if (PUBLIC_PULL_HOSTS.has(host)) {
    return { kind: 'public' };
  }

  for (const cred of configuredCreds) {
    let credHost: string;
    try {
      credHost = resolveRegistryHostname(cred.registry_type, cred.registry_url);
    } catch {
      // Misconfigured cred row (e.g. harbor/jfrog/custom with NULL registry_url).
      // Skip it for matching; the orchestrator surfaces the row's bad-data
      // separately via cred-validation.
      continue;
    }
    if (credHost === host) {
      return { kind: 'authenticated', credId: cred.id, hostname: host };
    }
  }

  return { kind: 'skip', reason: 'no_matching_cred' };
}

export class RegistryUnavailableError extends Error {
  readonly imageRef: string;
  readonly cause?: string;
  constructor(imageRef: string, cause?: string) {
    super(`Registry unavailable for ${imageRef}${cause ? `: ${cause}` : ''}`);
    this.name = 'RegistryUnavailableError';
    this.imageRef = imageRef;
    this.cause = cause;
  }
}

export interface CraneRunResult {
  stdout: string;
  exitCode: number;
}

export type CraneRunner = (
  imageRef: string,
  options: { dockerConfigDir?: string; timeoutMs: number }
) => Promise<CraneRunResult>;

const CRANE_TIMEOUT_MS = 5000;
const CRANE_MAX_BUFFER = 65536;

/**
 * Default crane runner. execFile with explicit timeout, SIGKILL on timeout,
 * and a tight maxBuffer (FMH-r2-4): zombie risk eliminated, output capped so
 * a malicious registry can't OOM the worker by streaming garbage.
 */
function defaultCraneRunner(
  imageRef: string,
  options: { dockerConfigDir?: string; timeoutMs: number }
): Promise<CraneRunResult> {
  return new Promise((resolve, reject) => {
    const env = { ...process.env };
    if (options.dockerConfigDir) env.DOCKER_CONFIG = options.dockerConfigDir;
    execFile(
      'crane',
      ['digest', imageRef],
      {
        timeout: options.timeoutMs,
        killSignal: 'SIGKILL',
        maxBuffer: CRANE_MAX_BUFFER,
        env,
      },
      (err, stdout) => {
        if (err) {
          const e = err as NodeJS.ErrnoException & { killed?: boolean; signal?: string };
          if (e.killed || e.signal === 'SIGKILL' || e.code === 'ETIMEDOUT') {
            reject(new RegistryUnavailableError(imageRef, 'crane probe timed out'));
            return;
          }
          reject(err);
          return;
        }
        resolve({ stdout, exitCode: 0 });
      }
    );
  });
}

/**
 * Resolve an image's content digest via `crane digest <imageRef>`. Used by
 * the orchestrator before paying the Trivy pull, so a cache hit short-circuits
 * the download. The returned digest is the canonical 64-hex form.
 *
 * Throws RegistryUnavailableError on timeout or crane failure; the orchestrator
 * classifies these as registry_unavailable and falls through to a
 * cache-bypassing Trivy run (or a skip, depending on kill switches).
 */
export async function resolveImageDigest(
  imageRef: string,
  options: { dockerConfigDir?: string; runner?: CraneRunner } = {}
): Promise<string> {
  const runner = options.runner ?? defaultCraneRunner;
  let result: CraneRunResult;
  try {
    result = await runner(imageRef, {
      dockerConfigDir: options.dockerConfigDir,
      timeoutMs: CRANE_TIMEOUT_MS,
    });
  } catch (err) {
    if (err instanceof RegistryUnavailableError) throw err;
    throw new RegistryUnavailableError(imageRef, (err as Error).message);
  }
  if (result.exitCode !== 0) {
    throw new RegistryUnavailableError(imageRef, `crane exit ${result.exitCode}`);
  }
  return normalizeDigest(result.stdout.trim());
}
