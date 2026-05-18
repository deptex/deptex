/**
 * Base-image catalog loader (Phase 2, Item J).
 *
 * Loads and validates the hand-curated `base-image-catalog.yaml`, and answers
 * "what are the more secure alternatives to this base image?" for the
 * base-image advisor. The YAML is the single source of truth; a weekly
 * registry-catalog scrape replaces hand-curation in Phase 2.5.
 */

import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

export type CatalogProvider =
  | 'chainguard'
  | 'distroless'
  | 'dhi'
  | 'official_slim'
  | 'wolfi';

export type LibcFamily = 'glibc' | 'musl' | 'none';

const PROVIDERS: ReadonlySet<string> = new Set([
  'chainguard',
  'distroless',
  'dhi',
  'official_slim',
  'wolfi',
]);
const LIBC_FAMILIES: ReadonlySet<string> = new Set(['glibc', 'musl', 'none']);

export interface CatalogAlternative {
  image: string;
  provider: CatalogProvider;
  /** False = no shell; breaks a Dockerfile whose CMD/ENTRYPOINT needs one. */
  has_shell: boolean;
  libc_family: LibcFamily;
  /** Curated 0-100 confidence the swap is drop-in. */
  drop_in_score: number;
  /** Curated, hand-refreshed CVE-count snapshot for this alternative. */
  cve_count: number;
  notes: string;
}

export interface CatalogSource {
  source_image: string;
  alternatives: CatalogAlternative[];
}

export interface CatalogFamily {
  family: string;
  sources: CatalogSource[];
}

export interface BaseImageCatalog {
  families: CatalogFamily[];
}

export class CatalogValidationError extends Error {
  constructor(message: string) {
    super(`base-image-catalog.yaml invalid: ${message}`);
    this.name = 'CatalogValidationError';
  }
}

/** The catalog ships beside the compiled code; the build copies the YAML into
 *  dist/scanners so __dirname resolves in both tsx-dev and built-worker modes. */
const CATALOG_PATH = path.join(__dirname, 'base-image-catalog.yaml');

// ============================================================
// Validation
// ============================================================

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function validateAlternative(raw: unknown, where: string): CatalogAlternative {
  if (!isObject(raw)) throw new CatalogValidationError(`${where} is not a mapping`);
  const { image, provider, has_shell, libc_family, drop_in_score, cve_count, notes } = raw;
  if (typeof image !== 'string' || image.length === 0) {
    throw new CatalogValidationError(`${where}.image must be a non-empty string`);
  }
  if (typeof provider !== 'string' || !PROVIDERS.has(provider)) {
    throw new CatalogValidationError(`${where}.provider "${String(provider)}" is not a known provider`);
  }
  if (typeof has_shell !== 'boolean') {
    throw new CatalogValidationError(`${where}.has_shell must be a boolean`);
  }
  if (typeof libc_family !== 'string' || !LIBC_FAMILIES.has(libc_family)) {
    throw new CatalogValidationError(`${where}.libc_family "${String(libc_family)}" is invalid`);
  }
  if (typeof drop_in_score !== 'number' || drop_in_score < 0 || drop_in_score > 100) {
    throw new CatalogValidationError(`${where}.drop_in_score must be a number in 0..100`);
  }
  if (typeof cve_count !== 'number' || cve_count < 0 || !Number.isFinite(cve_count)) {
    throw new CatalogValidationError(`${where}.cve_count must be a non-negative number`);
  }
  if (notes !== undefined && typeof notes !== 'string') {
    throw new CatalogValidationError(`${where}.notes must be a string`);
  }
  return {
    image,
    provider: provider as CatalogProvider,
    has_shell,
    libc_family: libc_family as LibcFamily,
    drop_in_score,
    cve_count,
    notes: typeof notes === 'string' ? notes : '',
  };
}

function validateCatalog(raw: unknown): BaseImageCatalog {
  if (!isObject(raw)) throw new CatalogValidationError('root is not a mapping');
  const families = raw.families;
  if (!Array.isArray(families)) throw new CatalogValidationError('families must be a list');
  const out: CatalogFamily[] = [];
  const seenSources = new Set<string>();
  for (let fi = 0; fi < families.length; fi++) {
    const fam = families[fi];
    if (!isObject(fam)) throw new CatalogValidationError(`families[${fi}] is not a mapping`);
    if (typeof fam.family !== 'string' || fam.family.length === 0) {
      throw new CatalogValidationError(`families[${fi}].family must be a non-empty string`);
    }
    if (!Array.isArray(fam.sources)) {
      throw new CatalogValidationError(`families[${fi}].sources must be a list`);
    }
    const sources: CatalogSource[] = [];
    for (let si = 0; si < fam.sources.length; si++) {
      const src = fam.sources[si];
      const where = `families[${fi}].sources[${si}]`;
      if (!isObject(src)) throw new CatalogValidationError(`${where} is not a mapping`);
      if (typeof src.source_image !== 'string' || src.source_image.length === 0) {
        throw new CatalogValidationError(`${where}.source_image must be a non-empty string`);
      }
      const key = normalizeImageRef(src.source_image);
      if (seenSources.has(key)) {
        throw new CatalogValidationError(`duplicate source_image "${src.source_image}"`);
      }
      seenSources.add(key);
      if (!Array.isArray(src.alternatives) || src.alternatives.length === 0) {
        throw new CatalogValidationError(`${where}.alternatives must be a non-empty list`);
      }
      sources.push({
        source_image: src.source_image,
        alternatives: src.alternatives.map((a, ai) =>
          validateAlternative(a, `${where}.alternatives[${ai}]`)
        ),
      });
    }
    out.push({ family: fam.family, sources });
  }
  return { families: out };
}

// ============================================================
// Loading + lookup
// ============================================================

/** Normalize an image reference for catalog lookup: lowercase, drop any digest. */
export function normalizeImageRef(imageRef: string): string {
  return imageRef.trim().toLowerCase().split('@')[0];
}

let cached: BaseImageCatalog | null = null;

/**
 * Load and validate the catalog. Result is memoized for the worker process —
 * the YAML never changes at runtime. Pass an explicit path to bypass the cache
 * (used by tests).
 */
export function loadCatalog(explicitPath?: string): BaseImageCatalog {
  if (!explicitPath && cached) return cached;
  const file = explicitPath ?? CATALOG_PATH;
  let text: string;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    throw new CatalogValidationError(`cannot read ${file}: ${(err as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = yaml.load(text);
  } catch (err) {
    throw new CatalogValidationError(`YAML parse failed: ${(err as Error).message}`);
  }
  const catalog = validateCatalog(parsed);
  if (!explicitPath) cached = catalog;
  return catalog;
}

/** Test-only: drop the memoized catalog. */
export function _resetCatalogCacheForTests(): void {
  cached = null;
}

export interface CatalogLookupResult {
  family: string;
  source_image: string;
  alternatives: CatalogAlternative[];
}

/**
 * Look up the curated alternatives for a base image. Matching is normalized
 * (case-insensitive, digest-stripped) and exact on the tag — `node:20` and
 * `node:20-slim` are distinct catalog entries. Returns null when the image is
 * not in the catalog.
 */
export function lookupAlternatives(
  sourceImage: string,
  catalog: BaseImageCatalog = loadCatalog()
): CatalogLookupResult | null {
  const target = normalizeImageRef(sourceImage);
  for (const fam of catalog.families) {
    for (const src of fam.sources) {
      if (normalizeImageRef(src.source_image) === target) {
        return {
          family: fam.family,
          source_image: src.source_image,
          alternatives: src.alternatives,
        };
      }
    }
  }
  return null;
}

/**
 * Stable content hash of the catalog — surfaced in logs so a structural change
 * to the curated data is observable across worker deploys.
 */
export function catalogHash(catalog: BaseImageCatalog = loadCatalog()): string {
  return createHash('sha256')
    .update(JSON.stringify(catalog))
    .digest('hex')
    .slice(0, 16);
}
