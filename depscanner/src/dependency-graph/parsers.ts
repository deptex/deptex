/**
 * Per-ecosystem direct-dependency-set parsers.
 *
 * These run only as a fallback: when cdxgen's CycloneDX `dependencies` graph
 * comes back unwired (`parseSbom().directSetTrusted === false`) the SBOM gives
 * us components but no direct/transitive split. Each parser reads the
 * ecosystem's manifest (or, for Maven/PyPI, the resolved tree) to recover the
 * set of dependencies the project itself declares — i.e. the direct set.
 *
 * Every parser returns a `Set` of *match keys* in the same shape `depMatchKey`
 * produces (lowercased name; Maven keys are `groupId:artifactId`). A `null`
 * return means the manifest/tree was absent or unreadable — the caller treats
 * that as "recovery unavailable" and floors reachability at `module`.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

/** package.json — dependencies + devDependencies + optional/peer. */
export function parseNpmDirectSet(workspaceRoot: string): Set<string> | null {
  const pkgPath = path.join(workspaceRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) return null;
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as Record<
      string,
      Record<string, string> | undefined
    >;
    const set = new Set<string>();
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const block = pkg[field];
      if (block && typeof block === 'object') {
        for (const name of Object.keys(block)) set.add(name.trim().toLowerCase());
      }
    }
    return set;
  } catch {
    return null;
  }
}

/** composer.json — require + require-dev, minus php and the `ext-` / `lib-` platform entries. */
export function parseComposerDirectSet(workspaceRoot: string): Set<string> | null {
  const jsonPath = path.join(workspaceRoot, 'composer.json');
  if (!fs.existsSync(jsonPath)) return null;
  try {
    const json = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as Record<
      string,
      Record<string, string> | undefined
    >;
    const set = new Set<string>();
    for (const field of ['require', 'require-dev']) {
      const block = json[field];
      if (!block || typeof block !== 'object') continue;
      for (const name of Object.keys(block)) {
        const lower = name.trim().toLowerCase();
        // Platform packages aren't real dependency components in the SBOM.
        if (lower === 'php' || /^(ext|lib|composer|hhvm)-/.test(lower)) continue;
        set.add(lower);
      }
    }
    return set;
  } catch {
    return null;
  }
}

/** go.mod — `require` directives that are NOT marked `// indirect`. */
export function parseGolangDirectSet(workspaceRoot: string): Set<string> | null {
  const modPath = path.join(workspaceRoot, 'go.mod');
  if (!fs.existsSync(modPath)) return null;
  try {
    const content = fs.readFileSync(modPath, 'utf8');
    const set = new Set<string>();
    let inBlock = false;
    for (const raw of content.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('//')) continue;
      if (line.startsWith('require (')) { inBlock = true; continue; }
      if (inBlock && line === ')') { inBlock = false; continue; }

      let body: string | null = null;
      if (inBlock) {
        body = line;
      } else if (line.startsWith('require ')) {
        body = line.slice('require '.length).trim();
      }
      if (!body) continue;
      if (/\/\/\s*indirect/.test(body)) continue; // transitive

      // `module/path v1.2.3` — take the module path.
      const modName = body.split(/\s+/)[0];
      if (modName) set.add(modName.trim().toLowerCase());
    }
    return set;
  } catch {
    return null;
  }
}

/** Cargo.toml — [dependencies], [dev-dependencies], [build-dependencies]. */
export function parseCargoDirectSet(workspaceRoot: string): Set<string> | null {
  const tomlPath = path.join(workspaceRoot, 'Cargo.toml');
  if (!fs.existsSync(tomlPath)) return null;
  try {
    const content = fs.readFileSync(tomlPath, 'utf8');
    const set = new Set<string>();
    const depSections = new Set(['dependencies', 'dev-dependencies', 'build-dependencies']);
    // `inDepSection` — inside a plain `[dependencies]` table, where each
    // `key = value` line names a crate. `inSubTable` — inside a
    // `[dependencies.serde]` table, where `key = value` lines are that one
    // crate's properties (version, features, …), NOT new crates.
    let inDepSection = false;
    let inSubTable = false;
    for (const raw of content.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;

      // `[dependencies.serde]` sub-table form: the crate name is the suffix.
      const subTable = line.match(/^\[([a-z-]+)\.([^\].]+)\]$/i);
      if (subTable) {
        inDepSection = false;
        inSubTable = true;
        if (depSections.has(subTable[1].toLowerCase())) set.add(subTable[2].trim().toLowerCase());
        continue;
      }
      const section = line.match(/^\[([^\]]+)\]$/);
      if (section) {
        inDepSection = depSections.has(section[1].trim().toLowerCase());
        inSubTable = false;
        continue;
      }
      if (inDepSection && !inSubTable) {
        // `serde = "1.0"` or `tokio = { version = "1" }`
        const key = line.match(/^([A-Za-z0-9_-]+)\s*=/);
        if (key) set.add(key[1].trim().toLowerCase());
      }
    }
    return set;
  } catch {
    return null;
  }
}

/** Gemfile.lock DEPENDENCIES section, falling back to `gem` lines in the Gemfile. */
export function parseGemDirectSet(workspaceRoot: string): Set<string> | null {
  const lockPath = path.join(workspaceRoot, 'Gemfile.lock');
  if (fs.existsSync(lockPath)) {
    try {
      const content = fs.readFileSync(lockPath, 'utf8');
      const set = new Set<string>();
      let inDeps = false;
      for (const raw of content.split(/\r?\n/)) {
        if (raw === 'DEPENDENCIES') { inDeps = true; continue; }
        if (inDeps) {
          // Section ends at a blank line or the next non-indented header.
          if (!raw.startsWith('  ')) break;
          const name = raw.trim().split(/[\s(!]/)[0];
          if (name) set.add(name.trim().toLowerCase());
        }
      }
      if (set.size > 0) return set;
    } catch {
      /* fall through to Gemfile */
    }
  }

  const gemfilePath = path.join(workspaceRoot, 'Gemfile');
  if (!fs.existsSync(gemfilePath)) return null;
  try {
    const content = fs.readFileSync(gemfilePath, 'utf8');
    const set = new Set<string>();
    for (const raw of content.split(/\r?\n/)) {
      const m = raw.trim().match(/^gem\s+['"]([^'"]+)['"]/);
      if (m) set.add(m[1].trim().toLowerCase());
    }
    return set;
  } catch {
    return null;
  }
}

/**
 * Maven — run `mvn dependency:tree` and take the depth-1 nodes as the direct
 * set. `resolveDependencies()` already warmed the `.m2` cache with
 * `mvn dependency:resolve`, so this is mostly offline. Keys are
 * `groupId:artifactId` to match `depMatchKey('maven', ...)`.
 */
export function parseMavenDirectSet(workspaceRoot: string): Set<string> | null {
  const pomPath = path.join(workspaceRoot, 'pom.xml');
  if (!fs.existsSync(pomPath)) return null;
  let output: string;
  try {
    output = execSync('mvn dependency:tree -DoutputType=text -B', {
      cwd: workspaceRoot,
      encoding: 'utf8',
      timeout: 180_000,
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch (err) {
    // `mvn` may still print a usable tree to stdout before a non-zero exit.
    const stdout = (err as { stdout?: string }).stdout;
    if (typeof stdout !== 'string' || stdout.length === 0) return null;
    output = stdout;
  }

  const set = new Set<string>();
  for (const raw of output.split(/\r?\n/)) {
    const line = raw.replace(/^\[INFO\]\s?/, '');
    // Depth-1 nodes are prefixed exactly `+- ` or `\- `; deeper nodes carry a
    // leading `|  ` / spaces before the connector.
    const m = line.match(/^[+\\]- ([^:\s]+:[^:\s]+):/);
    if (m) set.add(m[1].trim().toLowerCase());
  }
  return set.size > 0 ? set : null;
}

interface PipdeptreeNode {
  package?: { key?: string; package_name?: string };
  dependencies?: PipdeptreeNode[];
}

/**
 * PyPI — `pipdeptree --json-tree` top-level nodes are packages nothing else
 * depends on, i.e. the project's direct set. Falls back to parsing
 * requirements.txt declarations when pipdeptree is unavailable.
 */
export function parsePypiDirectSet(workspaceRoot: string): Set<string> | null {
  try {
    const output = execSync('pipdeptree --json-tree', {
      cwd: workspaceRoot,
      encoding: 'utf8',
      timeout: 60_000,
      maxBuffer: 32 * 1024 * 1024,
    });
    const tree = JSON.parse(output) as PipdeptreeNode[];
    if (Array.isArray(tree) && tree.length > 0) {
      const set = new Set<string>();
      for (const node of tree) {
        const name = node.package?.key ?? node.package?.package_name;
        if (name) set.add(normalizePypiName(name));
      }
      if (set.size > 0) return set;
    }
  } catch {
    /* pipdeptree missing or failed — fall back to the manifest */
  }
  return parsePypiRequirements(workspaceRoot);
}

function parsePypiRequirements(workspaceRoot: string): Set<string> | null {
  const reqPath = path.join(workspaceRoot, 'requirements.txt');
  if (!fs.existsSync(reqPath)) return null;
  try {
    const content = fs.readFileSync(reqPath, 'utf8');
    const set = new Set<string>();
    for (const raw of content.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#') || line.startsWith('-')) continue;
      const name = line.split(/[=<>!~;[\s]/)[0];
      if (name) set.add(normalizePypiName(name));
    }
    return set.size > 0 ? set : null;
  } catch {
    return null;
  }
}

/** PyPI names are case-insensitive and treat `_`/`.`/`-` as equivalent. */
export function normalizePypiName(name: string): string {
  return name.trim().toLowerCase().replace(/[._]+/g, '-');
}
