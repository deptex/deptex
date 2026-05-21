/**
 * v3 precision arc — cargo `[build-dependencies]` classification pin.
 *
 * The reachability classifier's dev-scope floor relies on
 * `collectCargoDevDeps` (sbom.ts) correctly tagging every crate under
 * `[dev-dependencies]` AND `[build-dependencies]` (plus target-specific
 * variants like `[target.'cfg(unix)'.build-dependencies]`) as non-prod.
 * The regex `/(?:^|\.)(?:dev|build)-dependencies$/` covers all four
 * shapes uniformly.
 *
 * No classifier work shipped for cargo in v3 — the existing regex was
 * already correct. This test fixture pins the wired behavior end-to-end
 * so a future refactor of `collectCargoDevDeps` can't silently regress
 * the cargo column on the reachability corpus.
 */

import * as fs from 'fs';
import * as path from 'path';
import { patchDevDependencies, type ParsedSbomDep } from '../sbom';

const FIXTURE_ROOT = path.join(
  __dirname,
  '..',
  '..',
  'test',
  'fixtures',
  'precision',
  'rust-build-dep',
);

function mkDep(name: string, isDirect: boolean): ParsedSbomDep {
  return {
    name,
    version: '1.0.0',
    namespace: null,
    license: null,
    is_direct: isDirect,
    source: isDirect ? 'dependencies' : 'transitive',
    devScoped: false,
    bomRef: `pkg:cargo/${name}@1.0.0`,
  };
}

describe('cargo build-dep classification — Cargo.toml fixture round-trip', () => {
  it('Cargo.toml fixture exists and parses', () => {
    const p = path.join(FIXTURE_ROOT, 'Cargo.toml');
    expect(fs.existsSync(p)).toBe(true);
    const content = fs.readFileSync(p, 'utf8');
    // Sanity: fixture contains every section we want the regex to catch.
    expect(content).toMatch(/^\[dev-dependencies\]$/m);
    expect(content).toMatch(/^\[build-dependencies\]$/m);
    expect(content).toMatch(/^\[target\..+\.build-dependencies\]$/m);
    expect(content).toMatch(/^\[dependencies\]$/m);
  });

  it('marks every direct dep under [dev-dependencies] and [build-dependencies] as devScoped', () => {
    // Seed the parsed deps with EVERY direct entry from the fixture's
    // four sections. The classifier must keep [dependencies] entries
    // as production-scope and flip the other three to devScoped=true.
    const deps: ParsedSbomDep[] = [
      // [dependencies] — must stay devScoped=false
      mkDep('serde', true),
      // [dev-dependencies] — must devScoped=true
      mkDep('mockall', true),
      mkDep('tokio-test', true),
      // [build-dependencies] — must devScoped=true
      mkDep('cc', true),
      mkDep('bindgen', true),
      // [target.'cfg(unix)'.build-dependencies] — must devScoped=true
      mkDep('pkg-config', true),
    ];
    patchDevDependencies(deps, FIXTURE_ROOT, 'cargo', [], true);
    const byName = new Map(deps.map((d) => [d.name, d]));
    expect(byName.get('serde')?.devScoped).toBe(false);
    expect(byName.get('mockall')?.devScoped).toBe(true);
    expect(byName.get('tokio-test')?.devScoped).toBe(true);
    expect(byName.get('cc')?.devScoped).toBe(true);
    expect(byName.get('bindgen')?.devScoped).toBe(true);
    expect(byName.get('pkg-config')?.devScoped).toBe(true);
  });

  it('source field reflects scope: dev-deps + build-deps both flip to devDependencies', () => {
    // Both scopes share the same source-string semantics — the
    // classifier doesn't distinguish dev from build at the source
    // level, only at the section-header level inside Cargo.toml. The
    // wired `source: 'devDependencies'` value is what travels to
    // `project_dependencies.environment` downstream.
    const deps: ParsedSbomDep[] = [
      mkDep('mockall', true),
      mkDep('cc', true),
    ];
    patchDevDependencies(deps, FIXTURE_ROOT, 'cargo', [], true);
    expect(deps[0].source).toBe('devDependencies');
    expect(deps[1].source).toBe('devDependencies');
  });
});
