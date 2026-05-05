/**
 * Maintainer-signal detection for the malicious-packages-v2 M1c path.
 *
 * One sync iteration per (package, version, ecosystem):
 *   1. Pull current registry metadata for the package (npm registry / PyPI
 *      JSON API / RubyGems v1 API).
 *   2. Snapshot the current state into `package_maintainer_snapshots` so
 *      future runs can diff against it.
 *   3. Look up the most recent prior snapshot ≥30 days old (cold-start
 *      callers get `null` here and yield zero change signals — first sync
 *      for any package never fires false-positive change alerts).
 *   4. Compute the per-package signal set by combining stateless current
 *      metadata (account_age_days, install_script_present) with diff-based
 *      change signals against the baseline (email/maintainer/signing/
 *      postinstall change flags).
 *
 * v2 ships full clients for npm + PyPI + RubyGems and stubs (warn-once,
 * return null) for the remaining 7 canonical ecosystems. Stubbed ecosystems
 * never fire signals — their `installScriptPresent` flag is false; the
 * snapshot writer is skipped; `computeMaintainerSignalsForPackage` returns
 * null so the cron route iterates past them. Adding a new ecosystem client
 * is purely additive — no schema change, no code-touching outside this file
 * + a new fetcher branch.
 *
 * Multi-tenant invariant: snapshots are global cache. Registry data is pure
 * public metadata. Org / project / user identifiers never enter this module.
 */
import * as crypto from 'crypto';
import { type SupabaseClient } from '@supabase/supabase-js';
import { canonicalizeEcosystem, type CanonicalEcosystem } from './ecosystem';
import {
  writeMaintainerSnapshot,
  getLatestSnapshotBefore,
  type MaintainerSnapshotRow,
} from './maintainer-snapshots';

// ───────────────────────────── types ──────────────────────────────────────

export interface RegistryMetadata {
  packageName: string;
  version: string;
  ecosystem: CanonicalEcosystem;
  /** Earliest known publish time on the registry (any version). */
  packageCreatedAt: string | null;
  maintainerHandles: string[];
  primaryMaintainerEmail: string | null;
  /** sha256 of (provenance + signing-keys-fingerprints) JSON, or null. */
  signingConfigHash: string | null;
  /** sha256 of normalized install-script body (preinstall+install+postinstall+prepare), or null. */
  postinstallHash: string | null;
  /** Raw registry response (truncated to what we need). For diagnostics + AI Explain. */
  raw: Record<string, unknown>;
}

export interface MaintainerSignals {
  /** Days since earliest registry publish. Null when registry didn't expose. */
  account_age_days: number | null;
  /** True when current metadata has any normalized install script body. */
  install_script_present: boolean;

  /** Diff signals — all false on cold start (no baseline ≥30d old). */
  email_changed_in_last_30d: boolean;
  maintainer_changed_in_last_30d: boolean;
  signing_setup_changed: boolean;
  new_postinstall_added: boolean;
}

export interface ComputeOptions {
  /** Override the clock for tests. Defaults to `new Date()`. */
  now?: Date;
  /** Inject a fetch implementation for tests. Defaults to global `fetch`. */
  fetcher?: typeof fetch;
  /** Skip the snapshot upsert (useful when running offline / dry-run). */
  skipWriteSnapshot?: boolean;
}

export interface ComputeResult {
  signals: MaintainerSignals;
  metadata: RegistryMetadata;
}

// ───────────────────────────── public API ─────────────────────────────────

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Public entry point used by the M1c daily cron route.
 *
 * Returns `null` when the ecosystem is unsupported (or canonicalization
 * fails) so the cron can iterate past unrecognised package rows without
 * throwing. Registry-fetch failures inside a supported ecosystem ALSO
 * return null — they're logged but don't propagate, because one bad
 * package shouldn't kill the cron run for thousands of others.
 */
export async function computeMaintainerSignalsForPackage(
  supabase: SupabaseClient,
  packageName: string,
  version: string,
  ecosystem: string,
  options: ComputeOptions = {},
): Promise<ComputeResult | null> {
  const eco = canonicalizeEcosystem(ecosystem);
  if (!eco) return null;

  const now = options.now ?? new Date();
  const fetcher = options.fetcher ?? fetch;

  let metadata: RegistryMetadata | null = null;
  try {
    metadata = await pullRegistryMetadata(packageName, version, eco, fetcher);
  } catch (err: any) {
    console.warn(`[maintainer-signals] ${eco}/${packageName}@${version} fetch failed: ${err?.message ?? err}`);
    return null;
  }
  if (!metadata) return null;

  // Persist current snapshot before computing diff signals so the next run
  // has a baseline to diff against. `null`-id return means the upsert
  // failed (logged inside `writeMaintainerSnapshot`); we still return the
  // signal result because the diff against the in-memory baseline below
  // doesn't depend on the snapshot row landing.
  if (!options.skipWriteSnapshot) {
    await writeMaintainerSnapshot(supabase, {
      packageName: metadata.packageName,
      version: metadata.version,
      ecosystem: metadata.ecosystem,
      maintainerHandles: metadata.maintainerHandles,
      primaryMaintainerEmail: metadata.primaryMaintainerEmail,
      signingConfigHash: metadata.signingConfigHash,
      postinstallHash: metadata.postinstallHash,
      registryMetadataRaw: metadata.raw,
      observedAt: now.toISOString(),
    });
  }

  const baselineCutoff = new Date(now.getTime() - THIRTY_DAYS_MS).toISOString();
  const baseline = await getLatestSnapshotBefore(
    supabase,
    metadata.packageName,
    metadata.version,
    metadata.ecosystem,
    baselineCutoff,
  );

  const signals = diffSignals(metadata, baseline, now);
  return { signals, metadata };
}

/**
 * Pure signal-diff function. Exported for unit tests + reuse by the cron
 * route's batched-fetch path (where it pulls metadata once and re-uses).
 */
export function diffSignals(
  current: RegistryMetadata,
  baseline: MaintainerSnapshotRow | null,
  now: Date,
): MaintainerSignals {
  const accountAgeDays = current.packageCreatedAt
    ? Math.max(0, Math.floor((now.getTime() - new Date(current.packageCreatedAt).getTime()) / (24 * 60 * 60 * 1000)))
    : null;

  const installScriptPresent = current.postinstallHash !== null;

  // Cold start: no baseline ≥30d old. All change signals stay false so a
  // first sync run for a brand-new (or never-snapshot'd) package can't
  // fire false-positive change alerts. The stateless signals
  // (`account_age_days`, `install_script_present`) still surface.
  if (!baseline) {
    return {
      account_age_days: accountAgeDays,
      install_script_present: installScriptPresent,
      email_changed_in_last_30d: false,
      maintainer_changed_in_last_30d: false,
      signing_setup_changed: false,
      new_postinstall_added: false,
    };
  }

  const emailChanged =
    Boolean(baseline.primary_maintainer_email) &&
    Boolean(current.primaryMaintainerEmail) &&
    baseline.primary_maintainer_email !== current.primaryMaintainerEmail;

  const maintainerSetChanged = !setsEqual(
    new Set(baseline.maintainer_handles ?? []),
    new Set(current.maintainerHandles),
  );

  const signingChanged =
    baseline.signing_config_hash !== null &&
    current.signingConfigHash !== null &&
    baseline.signing_config_hash !== current.signingConfigHash;

  const newPostinstallAdded =
    !baseline.postinstall_hash && Boolean(current.postinstallHash);

  return {
    account_age_days: accountAgeDays,
    install_script_present: installScriptPresent,
    email_changed_in_last_30d: emailChanged,
    maintainer_changed_in_last_30d: maintainerSetChanged,
    signing_setup_changed: signingChanged,
    new_postinstall_added: newPostinstallAdded,
  };
}

function setsEqual<T>(a: Set<T>, b: Set<T>): boolean {
  if (a.size !== b.size) return false;
  for (const v of a) if (!b.has(v)) return false;
  return true;
}

// ───────────────────────────── registry pulls ─────────────────────────────

const stubbedEcosystemsLogged = new Set<string>();
function logStubbedOnce(eco: string): void {
  if (stubbedEcosystemsLogged.has(eco)) return;
  stubbedEcosystemsLogged.add(eco);
  console.warn(
    `[maintainer-signals] ${eco}: registry client not implemented in v2 — package skipped`,
  );
}

async function pullRegistryMetadata(
  packageName: string,
  version: string,
  ecosystem: CanonicalEcosystem,
  fetcher: typeof fetch,
): Promise<RegistryMetadata | null> {
  switch (ecosystem) {
    case 'npm':
      return pullNpm(packageName, version, fetcher);
    case 'pypi':
      return pullPypi(packageName, version, fetcher);
    case 'rubygems':
      return pullRubygems(packageName, version, fetcher);
    default:
      logStubbedOnce(ecosystem);
      return null;
  }
}

// ─── npm ──────────────────────────────────────────────────────────────────

async function pullNpm(
  packageName: string,
  version: string,
  fetcher: typeof fetch,
): Promise<RegistryMetadata | null> {
  // Scoped packages (`@scope/name`) need URL-encoded slash.
  const url = `https://registry.npmjs.org/${packageName.replace('/', '%2F')}`;
  const res = await fetcher(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) {
    if (res.status === 404) return null;
    throw new Error(`npm registry ${res.status}: ${res.statusText}`);
  }
  const json = (await res.json()) as any;

  const versionMeta = json?.versions?.[version];
  if (!versionMeta) return null;

  const time = json?.time ?? {};
  const packageCreatedAt: string | null =
    typeof time.created === 'string' ? time.created : null;

  const handles: string[] = Array.isArray(versionMeta.maintainers)
    ? versionMeta.maintainers
        .map((m: any) => (typeof m?.name === 'string' ? m.name : null))
        .filter((s: string | null): s is string => !!s)
    : [];

  const primaryEmail: string | null =
    Array.isArray(versionMeta.maintainers) && versionMeta.maintainers[0]?.email
      ? String(versionMeta.maintainers[0].email)
      : null;

  // Signing config = provenance + signature-key fingerprints. npm publishes
  // these inside `dist`. Hash the JSON-serialized stable view so unrelated
  // metadata changes don't trip `signing_setup_changed`.
  const signingPayload = {
    signatures: Array.isArray(versionMeta?.dist?.signatures)
      ? versionMeta.dist.signatures.map((s: any) => ({ keyid: s?.keyid, sig_present: !!s?.sig }))
      : null,
    npm_signature: versionMeta?.dist?.['npm-signature'] ?? null,
    has_provenance: !!versionMeta?.dist?.attestations,
  };
  const signingConfigHash = stableHash(signingPayload);

  // Install scripts. Concatenate the four hooks that npm executes so
  // adding ANY of them flips the postinstall hash.
  const scripts = (versionMeta.scripts ?? {}) as Record<string, string>;
  const installBody = ['preinstall', 'install', 'postinstall', 'prepare']
    .map((k) => `${k}=${scripts[k] ?? ''}`)
    .join('\n');
  const postinstallHash = installBody.match(/=\S/)
    ? crypto.createHash('sha256').update(installBody).digest('hex')
    : null;

  return {
    packageName,
    version,
    ecosystem: 'npm',
    packageCreatedAt,
    maintainerHandles: handles,
    primaryMaintainerEmail: primaryEmail,
    signingConfigHash,
    postinstallHash,
    raw: {
      time_created: packageCreatedAt,
      dist_tags: json['dist-tags'] ?? null,
      version_meta: {
        scripts: scripts,
        maintainers: versionMeta.maintainers,
      },
    },
  };
}

// ─── PyPI ─────────────────────────────────────────────────────────────────

async function pullPypi(
  packageName: string,
  version: string,
  fetcher: typeof fetch,
): Promise<RegistryMetadata | null> {
  const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}/json`;
  const res = await fetcher(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) {
    if (res.status === 404) return null;
    throw new Error(`PyPI ${res.status}: ${res.statusText}`);
  }
  const json = (await res.json()) as any;
  const info = json?.info ?? {};

  // Earliest release timestamp across ALL versions of the package.
  let packageCreatedAt: string | null = null;
  const releases = json?.releases ?? {};
  for (const versionRecords of Object.values(releases) as any[]) {
    if (!Array.isArray(versionRecords)) continue;
    for (const file of versionRecords) {
      const ts = typeof file?.upload_time_iso_8601 === 'string'
        ? file.upload_time_iso_8601
        : (typeof file?.upload_time === 'string' ? file.upload_time : null);
      if (!ts) continue;
      if (!packageCreatedAt || ts < packageCreatedAt) packageCreatedAt = ts;
    }
  }

  // PyPI exposes a single author email + maintainer email; treat the
  // author-email + maintainer-email pair as the maintainer handle set.
  const handles: string[] = [];
  if (typeof info.author === 'string' && info.author.trim()) handles.push(info.author.trim());
  if (typeof info.maintainer === 'string' && info.maintainer.trim() && info.maintainer !== info.author) {
    handles.push(info.maintainer.trim());
  }

  const primaryEmail: string | null =
    (typeof info.maintainer_email === 'string' && info.maintainer_email.trim()) ? info.maintainer_email.trim()
    : (typeof info.author_email === 'string' && info.author_email.trim()) ? info.author_email.trim()
    : null;

  // PyPI doesn't expose install scripts via JSON. setup.py would have
  // to be fetched + parsed — deferred to v3.
  const postinstallHash: string | null = null;

  // No formal signing metadata in the PyPI JSON API yet (PEP 740 is
  // experimental). Hash a stable empty payload so equal pulls produce
  // equal hashes.
  const signingConfigHash = stableHash({ pypi: 'no-signing-metadata-v2' });

  return {
    packageName,
    version,
    ecosystem: 'pypi',
    packageCreatedAt,
    maintainerHandles: handles,
    primaryMaintainerEmail: primaryEmail,
    signingConfigHash,
    postinstallHash,
    raw: {
      info_author: info.author ?? null,
      info_maintainer: info.maintainer ?? null,
      info_author_email: info.author_email ?? null,
      info_maintainer_email: info.maintainer_email ?? null,
    },
  };
}

// ─── RubyGems ─────────────────────────────────────────────────────────────

async function pullRubygems(
  packageName: string,
  version: string,
  fetcher: typeof fetch,
): Promise<RegistryMetadata | null> {
  const gemUrl = `https://rubygems.org/api/v1/gems/${encodeURIComponent(packageName)}.json`;
  const versionsUrl = `https://rubygems.org/api/v1/versions/${encodeURIComponent(packageName)}.json`;

  const [gemRes, versionsRes] = await Promise.all([
    fetcher(gemUrl, { headers: { Accept: 'application/json' } }),
    fetcher(versionsUrl, { headers: { Accept: 'application/json' } }),
  ]);

  if (!gemRes.ok) {
    if (gemRes.status === 404) return null;
    throw new Error(`RubyGems ${gemRes.status}: ${gemRes.statusText}`);
  }
  const gemJson = (await gemRes.json()) as any;

  let packageCreatedAt: string | null = null;
  if (versionsRes.ok) {
    const versions = (await versionsRes.json()) as any[];
    if (Array.isArray(versions) && versions.length > 0) {
      // versions are returned newest-first; iterate to find min created_at
      for (const v of versions) {
        const ts = typeof v?.created_at === 'string' ? v.created_at : null;
        if (!ts) continue;
        if (!packageCreatedAt || ts < packageCreatedAt) packageCreatedAt = ts;
      }
    }
  }

  // RubyGems exposes `authors` (free-text), no per-version maintainer set
  // in the gem-level endpoint. We treat the comma-joined `authors` as a
  // single handle until a per-version owner endpoint is wired.
  const handles: string[] = typeof gemJson.authors === 'string'
    ? gemJson.authors.split(',').map((s: string) => s.trim()).filter(Boolean)
    : [];

  // Email isn't surfaced on the public gem endpoint — gone since RubyGems'
  // 2018 privacy update. Leave null; the email-changed signal becomes
  // unfireable for RubyGems but the maintainer-set-changed signal still works.
  const primaryEmail: string | null = null;

  const signingConfigHash = stableHash({
    metadata: gemJson?.metadata ?? null,
  });

  // No install scripts in the gem-level JSON. The .gemspec extensions
  // field is a partial proxy and lives in the tarball.
  const postinstallHash: string | null = null;

  return {
    packageName,
    version,
    ecosystem: 'rubygems',
    packageCreatedAt,
    maintainerHandles: handles,
    primaryMaintainerEmail: primaryEmail,
    signingConfigHash,
    postinstallHash,
    raw: {
      authors: gemJson.authors ?? null,
      info: typeof gemJson.info === 'string' ? gemJson.info.slice(0, 200) : null,
    },
  };
}

// ───────────────────────────── helpers ────────────────────────────────────

function stableHash(payload: unknown): string {
  // JSON.stringify is deterministic for plain objects up to key order. We
  // sort top-level keys so two objects with the same key/value pairs in
  // different order produce the same hash.
  const json = JSON.stringify(payload, Object.keys(flatten(payload)).sort());
  return crypto.createHash('sha256').update(json).digest('hex');
}

function flatten(v: unknown): Record<string, unknown> {
  if (v && typeof v === 'object' && !Array.isArray(v)) return v as Record<string, unknown>;
  return { _value: v };
}
