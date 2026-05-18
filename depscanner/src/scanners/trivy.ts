import * as fs from 'fs';
import { createHash } from 'crypto';
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

// Matches `ARG NAME` or `ARG NAME=default` (optionally quoted default). Only
// ARGs with a default are usable for FROM substitution — a bare `ARG NAME`
// has no value until `docker build --build-arg`, which we can't observe.
const ARG_LINE_RE = /^\s*ARG\s+([A-Za-z0-9_]+)(?:=(.*))?\s*$/i;

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
 * Substitute `${VAR}` / `$VAR` against collected ARG defaults. Returns the
 * resolved string, or null if any referenced variable has no known default
 * (the caller treats this as an `unresolved_arg` skip rather than passing the
 * literal `${VAR}` downstream to crane/trivy).
 */
function substituteArgs(
  ref: string,
  args: Map<string, string>
): string | null {
  let unresolved = false;
  const resolved = ref.replace(
    /\$\{([A-Za-z0-9_]+)\}|\$([A-Za-z0-9_]+)/g,
    (_m, braced, bare) => {
      const name = braced ?? bare;
      const val = args.get(name);
      if (val === undefined) {
        unresolved = true;
        return '';
      }
      return val;
    }
  );
  return unresolved ? null : resolved;
}

export type ParseDockerfileResult =
  | { kind: 'stage'; stage: DockerfileFinalStage }
  | { kind: 'skip'; reason: 'parse_failed' | 'unresolved_arg' };

/**
 * Parse all FROM directives from a Dockerfile and return the FINAL stage —
 * the image that ships to production. v1 returns the last FROM regardless of
 * inter-stage references; intermediate `AS builder` stages are intentionally
 * not scanned at v1 (their findings would be noise — they don't ship).
 *
 * Returns null when no FROM lines parse cleanly, or when the final stage is
 * `scratch` (which has no userland packages to scan). Thin wrapper over
 * parseDockerfileFinalStageDetailed for callers that don't need the skip
 * reason.
 */
export function parseDockerfileFinalStage(
  dockerfilePath: string
): DockerfileFinalStage | null {
  const r = parseDockerfileFinalStageDetailed(dockerfilePath);
  return r.kind === 'stage' ? r.stage : null;
}

/**
 * Same as parseDockerfileFinalStage but distinguishes a clean parse miss from
 * an `unresolved_arg` skip — a `FROM ${VAR}` where VAR has no ARG default we
 * could observe. Passing the literal `${VAR}` to crane/trivy silently skips
 * the image; this lets the orchestrator record a distinct skip reason.
 */
export function parseDockerfileFinalStageDetailed(
  dockerfilePath: string
): ParseDockerfileResult {
  let text: string;
  try {
    text = fs.readFileSync(dockerfilePath, 'utf8');
  } catch {
    return { kind: 'skip', reason: 'parse_failed' };
  }
  const stages: DockerfileStage[] = [];
  const rawLines = text.split(/\r?\n/);
  // Coalesce backslash line continuations so a multi-line `FROM \\\n nginx`
  // still parses. Without this, the trailing `\` makes the first physical
  // line not match FROM_LINE_RE, and the second line ("  nginx:alpine") doesn't
  // start with FROM, so the directive is dropped silently.
  const logicalLines: string[] = [];
  let buf = '';
  for (const raw of rawLines) {
    if (raw.endsWith('\\')) {
      buf += raw.slice(0, -1) + ' ';
      continue;
    }
    logicalLines.push(buf + raw);
    buf = '';
  }
  if (buf) logicalLines.push(buf);
  // Collect ARG defaults as we scan so a `FROM ${BASE}` line can resolve
  // against an `ARG BASE=node:20` declared above it. Docker only honors ARGs
  // declared before the FROM that uses them, so a single forward pass with a
  // running map is the correct scope.
  const args = new Map<string, string>();
  let sawUnresolvedArg = false;
  for (const line of logicalLines) {
    const argMatch = ARG_LINE_RE.exec(line);
    if (argMatch) {
      if (argMatch[2] !== undefined) {
        // Strip surrounding quotes from the default value.
        const raw = argMatch[2].trim();
        const val = raw.replace(/^(['"])(.*)\1$/, '$2');
        args.set(argMatch[1], val);
      }
      continue;
    }
    const m = FROM_LINE_RE.exec(line);
    if (!m) continue;
    let imageRef = m[1];
    if (imageRef.includes('$')) {
      const resolved = substituteArgs(imageRef, args);
      if (resolved === null) {
        sawUnresolvedArg = true;
        continue;
      }
      imageRef = resolved;
    }
    stages.push({ imageRef, alias: m[2] ?? null, index: stages.length });
  }
  if (stages.length === 0) {
    return { kind: 'skip', reason: sawUnresolvedArg ? 'unresolved_arg' : 'parse_failed' };
  }
  const final = stages[stages.length - 1];
  if (/^scratch(:|@|$)/i.test(final.imageRef)) {
    return { kind: 'skip', reason: 'parse_failed' };
  }
  // Skip when the final stage's "imageRef" is actually an earlier stage's
  // alias (case-insensitive per Docker's stage-name matching). E.g.
  // `FROM builder AS production` flattens — `production` is built from the
  // `builder` layer locally, not pulled from a registry. Probing it would
  // 404 and waste budget.
  for (let i = 0; i < stages.length - 1; i++) {
    if (
      stages[i].alias &&
      stages[i].alias!.toLowerCase() === final.imageRef.toLowerCase()
    ) {
      return { kind: 'skip', reason: 'parse_failed' };
    }
  }
  return {
    kind: 'stage',
    stage: {
      imageRef: final.imageRef,
      stageIndex: final.index,
      totalStages: stages.length,
    },
  };
}

// ============================================================
// ghcr owner extraction — used by the App-token fallback path in the
// orchestrator's container-scan loop. M8 retired the v1 classifyImageRef
// special-case; the only surviving ghcr-specific logic is the namespace
// check, which still needs the image's owner segment.
// ============================================================

/**
 * Single source of truth for splitting an image reference into its registry
 * host + remaining path. The host segment is lowercased exactly once here so
 * `GHCR.IO/owner/img` and `ghcr.io/owner/img` are treated identically by every
 * call site. A bare name (`nginx`, `library/nginx`) implies Docker Hub.
 *
 *   host                — lowercased registry host (port stripped)
 *   path                — everything after the host (no leading slash); for an
 *                          implicit-hub ref this is the whole ref minus digest
 *   isImplicitDockerHub — true when no explicit host was present
 */
export function parseImageHost(imageRef: string): {
  host: string;
  path: string;
  isImplicitDockerHub: boolean;
} {
  const noDigest = imageRef.split('@')[0].trim();
  const firstSlash = noDigest.indexOf('/');
  if (firstSlash === -1) {
    return { host: 'docker.io', path: noDigest, isImplicitDockerHub: true };
  }
  const firstSegment = noDigest.slice(0, firstSlash);
  const looksLikeHost =
    firstSegment === 'localhost' ||
    /\./.test(firstSegment) ||
    /:\d+$/.test(firstSegment);
  if (!looksLikeHost) {
    return { host: 'docker.io', path: noDigest, isImplicitDockerHub: true };
  }
  // Strip an explicit port so `registry.example:5000` keys as the bare host.
  const colon = firstSegment.lastIndexOf(':');
  const hostNoPort =
    colon !== -1 && /^\d+$/.test(firstSegment.slice(colon + 1))
      ? firstSegment.slice(0, colon)
      : firstSegment;
  return {
    host: hostNoPort.toLowerCase(),
    path: noDigest.slice(firstSlash + 1),
    isImplicitDockerHub: false,
  };
}

export function extractGhcrOwner(imageRef: string): string | null {
  const { host, path } = parseImageHost(imageRef);
  if (host !== 'ghcr.io') return null;
  const owner = path.split('/')[0]?.split(':')[0] ?? '';
  return owner.length > 0 ? owner : null;
}

// ============================================================
// Trivy IaC (config) — Dockerfile misconfig
// ============================================================

// Trivy emits Resource strings like `Dockerfile:RUN apt-get install foo`,
// where the cause segment is the raw instruction — it contains `;`, backticks,
// backslashes and non-ASCII constantly. We only structurally validate the
// `trivy:` prefix + rule-id segment (Trivy's IDs are stable uppercase
// alphanum + dashes); the free-text cause is treated as opaque and hashed
// into the fingerprint so it can never fail validation and silently drop a
// finding's status carry-forward.
const TRIVY_RULE_ID_RE = /^[A-Z0-9-]+$/;

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
  // Only the rule-id is structurally validated; the cause segment is opaque
  // free text (raw RUN instructions) so we hash it instead of embedding it
  // raw. A short hash keeps the fingerprint stable for status carry-forward
  // without risking a regex rejection on shell metacharacters.
  if (!TRIVY_RULE_ID_RE.test(ruleId)) return null;
  const causeHash = createHash('sha256').update(cause, 'utf8').digest('hex').slice(0, 16);
  return `trivy:${ruleId}:${causeHash}`;
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
    // Trivy config scans on a typical repo are well under 16MB; cap to defend
    // against a malicious target with thousands of generated YAMLs.
    stdoutMaxBytes: 16 * 1024 * 1024,
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

  // Prefer RepoDigests (immutable `<repo>@sha256:<hex>`) and fall back to
  // ImageID (also content-addressed, `sha256:<hex>`). Do NOT fall back to
  // imageReference — that's a tag like `nginx:1.25` whose target can change
  // over time, producing fragile fingerprints that conflate distinct images.
  // Callers receive '' (empty string) when no immutable identifier is
  // available; the runner pushes a `trivy_image_no_digest` warning so the
  // signal isn't silently lost.
  const imageDigest = parsed.Metadata?.RepoDigests?.[0] ?? parsed.Metadata?.ImageID ?? '';

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
    // Real Trivy image scans of legitimate base images stay <2MB; 64MB is
    // a generous ceiling that defends the worker from a malicious registry
    // serving a manifest whose layers expand to a hundred-MB CVE report.
    stdoutMaxBytes: 64 * 1024 * 1024,
  });
  if (result.exitCode !== 0 && result.exitCode !== 1) {
    warnings.push(`trivy_image_exit_${result.exitCode}`);
    return { findings: [], imageDigest: '', version: `trivy@${version}`, warnings };
  }
  const parsed = parseTrivyImageOutput(result.stdout, opts.imageRef, `trivy@${version}`);
  if (!parsed.imageDigest) {
    // Trivy returned neither RepoDigests nor ImageID — the image is
    // identifiable only by its mutable tag, which we refuse to use as a
    // fingerprint. Surface a warning so callers can flag the affected scan.
    warnings.push('trivy_image_no_digest');
  }
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
// undefined = not yet probed; null = probed but DB block absent (caching
// disabled for this scan); string = the DB UpdatedAt day.
let cachedDbVersionDay: string | null | undefined = undefined;

async function readTrivyVersionOutput(): Promise<string | null> {
  try {
    const v = await runScannerSubprocess({
      exe: 'trivy',
      args: ['--version'],
      timeoutMs: 10_000,
    });
    return v.stdout;
  } catch {
    return null;
  }
}

export async function trivyVersion(): Promise<string> {
  if (cachedVersion) return cachedVersion;
  const stdout = await readTrivyVersionOutput();
  const match = stdout ? /Version:\s*(\S+)/i.exec(stdout) : null;
  cachedVersion = match?.[1] ?? 'unknown';
  return cachedVersion;
}

/**
 * Surfaces Trivy's vulnerability-DB UpdatedAt date as YYYY-MM-DD UTC. This is
 * the actual CVE DB version, not the calendar day of the scan — so two scans
 * straddling a Trivy DB refresh produce different cache keys, and a stale row
 * cannot serve fresh CVEs after the DB rolls.
 *
 * Trivy --version output looks like:
 *   Version: 0.50.0
 *   Vulnerability DB:
 *     Version: 2
 *     UpdatedAt: 2026-05-06 06:24:30.123456 +0000 UTC
 *     ...
 *
 * Returns null when the DB block is absent (older Trivy or malformed output).
 * Callers MUST treat null as "disable caching for this scan" — substituting
 * the wall-clock date would let two scans on the same calendar day but with
 * different actual CVE DBs collide on the cache key and serve stale results.
 */
export async function trivyDbVersionDay(): Promise<string | null> {
  if (cachedDbVersionDay !== undefined) return cachedDbVersionDay;
  const stdout = await readTrivyVersionOutput();
  if (stdout) {
    // Match `UpdatedAt: YYYY-MM-DD ...` inside the Vulnerability DB block.
    const m = /Vulnerability DB:[\s\S]*?UpdatedAt:\s*(\d{4}-\d{2}-\d{2})/i.exec(stdout);
    if (m) {
      cachedDbVersionDay = m[1];
      return cachedDbVersionDay;
    }
  }
  cachedDbVersionDay = null;
  return null;
}

/** Test-only: clears the version + DB-version cache between cases. */
export function _resetTrivyVersionCacheForTests(): void {
  cachedVersion = null;
  cachedDbVersionDay = undefined;
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
  const { host, isImplicitDockerHub } = parseImageHost(imageRef);
  return { host, isImplicitDockerHub };
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
// 1 MiB. A `crane digest` response is a single sha256 line, but registries
// and auth layers interleave warnings/redirect noise on stdout; a 64 KiB cap
// could truncate a legitimate response and surface as a misleading
// maxBuffer ENOBUFS error. 1 MiB still bounds a malicious registry's output.
const CRANE_MAX_BUFFER = 1024 * 1024;

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
      // Pin the platform to match runTrivyImage's --platform linux/amd64 flag.
      // Without this, on a non-amd64 host (Apple Silicon dev, future ARM Fly
      // machines) crane returns the host-platform manifest digest while Trivy
      // returns the amd64 child digest, the 4-guard mismatch trips, and the
      // cache never warms for any multi-arch image.
      ['digest', '--platform', 'linux/amd64', imageRef],
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
          // execFile raises ERR_CHILD_PROCESS_STDIO_MAXBUFFER when stdout
          // exceeds maxBuffer. With the 1 MiB cap this only fires on a
          // genuinely abusive registry — classify it distinctly rather than
          // letting it fall through as a generic registry error.
          if (
            e.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' ||
            /maxBuffer/i.test(e.message ?? '')
          ) {
            reject(
              new RegistryUnavailableError(imageRef, 'crane output exceeded maxBuffer')
            );
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
