/**
 * Manifest-driven `install_script` detection.
 *
 * Rather than scanning source for "looks like an install hook", we read the
 * canonical metadata file the package manager respects: install hooks
 * declared in those files run on `npm install` / `pip install` / etc.
 * without the user opting in. That's the supply-chain risk we want to flag.
 */
import * as fs from 'fs';
import * as path from 'path';
import type { CanonicalEcosystem } from '../ecosystem';

const NPM_HOOKS = new Set([
  'preinstall',
  'install',
  'postinstall',
  'preuninstall',
  'uninstall',
  'postuninstall',
  'preversion',
  'prepublish',
  'prepublishOnly',
  'prepare',
  'prepack',
  'postpack',
]);

/**
 * Returns true when the unpacked package declares an install-time script
 * hook in its manifest. Best-effort: errors swallowed (returns false).
 */
export function detectInstallScript(unpackedDir: string, ecosystem: CanonicalEcosystem): boolean {
  try {
    switch (ecosystem) {
      case 'npm':
        return detectNpmInstallScript(unpackedDir);
      case 'pypi':
        return detectPypiInstallScript(unpackedDir);
      case 'composer':
        return detectComposerInstallScript(unpackedDir);
      case 'rubygems':
        return detectRubygemsInstallScript(unpackedDir);
      case 'cargo':
        return detectCargoInstallScript(unpackedDir);
      case 'nuget':
        return detectNugetInstallScript(unpackedDir);
      default:
        return false;
    }
  } catch {
    return false;
  }
}

function detectNpmInstallScript(dir: string): boolean {
  const pkg = readJson(path.join(dir, 'package.json'));
  if (!pkg) return false;
  const scripts = (pkg as { scripts?: Record<string, unknown> }).scripts;
  if (!scripts || typeof scripts !== 'object') return false;
  for (const k of Object.keys(scripts)) {
    if (NPM_HOOKS.has(k)) return true;
  }
  return false;
}

function detectPypiInstallScript(dir: string): boolean {
  // setup.py with a custom cmdclass install hook, or pyproject.toml with
  // build-system hooks beyond the default setuptools/poetry-core. We use a
  // light heuristic: presence of `cmdclass=` in setup.py, or `[tool.poetry.scripts]`
  // / `[project.scripts]` declaring a non-empty entry point list.
  const setupPy = readText(path.join(dir, 'setup.py'));
  if (setupPy) {
    if (/\bcmdclass\s*=/.test(setupPy)) return true;
    if (/class\s+\w*Install\w*\s*\(\s*(?:install|develop|build_py)\s*\)/.test(setupPy)) return true;
  }
  const setupCfg = readText(path.join(dir, 'setup.cfg'));
  if (setupCfg && /\bcmdclass\b/.test(setupCfg)) return true;
  const pyproject = readText(path.join(dir, 'pyproject.toml'));
  if (pyproject) {
    if (/\[tool\.poetry\.scripts\]/.test(pyproject)) return true;
    if (/\[project\.scripts\]/.test(pyproject)) return true;
    // Custom build backends are themselves an install-time code path
    if (/\bbuild-backend\s*=\s*"(?!setuptools\.build_meta|poetry\.core\.masonry\.api|hatchling\.build|flit_core\.buildapi|pdm\.backend)/.test(pyproject)) {
      return true;
    }
  }
  return false;
}

function detectComposerInstallScript(dir: string): boolean {
  const composer = readJson(path.join(dir, 'composer.json'));
  if (!composer) return false;
  const scripts = (composer as { scripts?: Record<string, unknown> }).scripts;
  return !!scripts && typeof scripts === 'object' && Object.keys(scripts).length > 0;
}

function detectRubygemsInstallScript(dir: string): boolean {
  // .gemspec extensions field declares native build hooks that run during
  // `gem install`. Find any *.gemspec at the root.
  let entries: string[] = [];
  try { entries = fs.readdirSync(dir); } catch { return false; }
  for (const f of entries) {
    if (!f.endsWith('.gemspec')) continue;
    const text = readText(path.join(dir, f));
    if (text && /\b\w+\.extensions\s*=|extensions\s*=\s*\[/.test(text)) return true;
  }
  return false;
}

function detectCargoInstallScript(dir: string): boolean {
  // build.rs runs on every `cargo build` consumed by downstream crates.
  if (fs.existsSync(path.join(dir, 'build.rs'))) return true;
  const cargoToml = readText(path.join(dir, 'Cargo.toml'));
  if (cargoToml && /^\s*build\s*=\s*"/m.test(cargoToml)) return true;
  return false;
}

function detectNugetInstallScript(dir: string): boolean {
  // Legacy NuGet packages ship install.ps1 / init.ps1 / uninstall.ps1
  // under tools/. NuGet PackageReference (sdk-style) packages don't honor
  // these — but we still flag them as supply-chain-relevant.
  const tools = path.join(dir, 'tools');
  if (!fs.existsSync(tools)) return false;
  let entries: string[] = [];
  try { entries = fs.readdirSync(tools); } catch { return false; }
  return entries.some((f) => /^(?:install|init|uninstall)\.ps1$/i.test(f));
}

function readText(p: string): string | null {
  try {
    return fs.readFileSync(p, 'utf8');
  } catch {
    return null;
  }
}

function readJson(p: string): unknown {
  const raw = readText(p);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}
