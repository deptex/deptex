import * as fs from 'fs';
import { runScannerSubprocess, type ScannerSubprocessLogger } from '../with-timeout';
import type {
  ContainerFinding,
  IaCFinding,
  IaCFramework,
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
  // Detect explicit registry by presence of "/" in the first segment AND a
  // dot or colon (e.g. host:port) — same heuristic used by Docker CLI.
  const firstSlash = noDigest.indexOf('/');
  const firstSegment = firstSlash === -1 ? noDigest : noDigest.slice(0, firstSlash);
  const hasHost = /[.:]/.test(firstSegment);

  if (!hasHost) {
    // Bare name like "node:20" or "library/node:20" — resolves to docker.io/library/*
    return { kind: 'public_dockerhub' };
  }

  if (firstSegment === 'docker.io' || firstSegment === 'index.docker.io' || firstSegment === 'registry-1.docker.io') {
    return { kind: 'public_dockerhub' };
  }

  if (firstSegment === 'ghcr.io') {
    const rest = noDigest.slice(firstSlash + 1);
    const owner = rest.split('/')[0]?.split(':')[0] ?? '';
    if (!owner) return { kind: 'unsupported_registry' };
    return { kind: 'ghcr', owner };
  }

  // Any other host (ECR, GCR, ACR, Quay, Harbor, JFrog, private docker.io) → skip.
  if (KNOWN_REGISTRY_HOSTS.has(firstSegment) || hasHost) {
    return { kind: 'unsupported_registry' };
  }

  return { kind: 'public_dockerhub' };
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
  /** JSON string suitable for ~/.docker/config.json — written into a temp dir
   *  via DOCKER_AUTH_CONFIG so the GitHub App token never ends up in argv. */
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
  if (opts.dockerAuthConfig) {
    env.DOCKER_AUTH_CONFIG = opts.dockerAuthConfig;
  }
  const result = await runScannerSubprocess({
    exe: 'trivy',
    args: [
      'image',
      '--format', 'json',
      '--scanners=vuln',
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
