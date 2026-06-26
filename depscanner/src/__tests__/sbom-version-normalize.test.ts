/**
 * SBOM version normalization (P1-10 dogfood fix).
 *
 * A dependency that the SBOM emits with a non-canonical leading `v`
 * (e.g. Packagist tags like `v5.2.16`) used to split into two
 * `project_dependencies` rows — once as `v5.2.16` (SBOM) and once as `5.2.16`
 * (the transitive resolver, which already strips the `v`) — doubling every CVE
 * attached to it. `normalizeSbomVersion` collapses them by stripping the
 * leading `v` for every ecosystem EXCEPT Go, whose versions are canonically
 * v-prefixed and matched on that exact form by OSV/dep-scan.
 */

import { normalizeSbomVersion, parseSbom, getBomRefToNameVersion, type CycloneDxSbom } from '../sbom';

describe('normalizeSbomVersion', () => {
  it('strips a non-canonical leading v for composer (Packagist tag shape)', () => {
    expect(normalizeSbomVersion('v5.2.16', 'pkg:composer/phpmailer/phpmailer@v5.2.16')).toBe('5.2.16');
  });

  it('preserves the canonical v-prefix on Go module versions', () => {
    expect(normalizeSbomVersion('v1.5.0', 'pkg:golang/github.com/gin-gonic/gin@v1.5.0')).toBe('v1.5.0');
    expect(normalizeSbomVersion('v2.2.2', 'pkg:golang/gopkg.in/yaml.v2@v2.2.2')).toBe('v2.2.2');
  });

  it('leaves already-canonical versions untouched', () => {
    expect(normalizeSbomVersion('4.17.20', 'pkg:npm/lodash@4.17.20')).toBe('4.17.20');
  });

  it('only strips when a digit follows the v (never mangles a letter-leading version)', () => {
    expect(normalizeSbomVersion('vendor-1.0', 'pkg:composer/acme/pkg@vendor-1.0')).toBe('vendor-1.0');
    expect(normalizeSbomVersion('V2', 'pkg:nuget/Acme.Pkg@V2')).toBe('2');
  });

  it('does not guess when the ecosystem (purl) is unknown', () => {
    expect(normalizeSbomVersion('v1.0.0', undefined)).toBe('v1.0.0');
  });
});

describe('parseSbom — version normalization', () => {
  const sbom: CycloneDxSbom = {
    components: [
      { 'bom-ref': 'php', name: 'phpmailer/phpmailer', version: 'v5.2.16', purl: 'pkg:composer/phpmailer/phpmailer@v5.2.16' },
      { 'bom-ref': 'gin', name: 'github.com/gin-gonic/gin', version: 'v1.5.0', purl: 'pkg:golang/github.com/gin-gonic/gin@v1.5.0' },
      { 'bom-ref': 'lodash', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
    ],
    // No wired dependency graph → parseSbom's fallback includes every component.
  };

  it('normalizes composer but preserves Go', () => {
    const { dependencies } = parseSbom(sbom);
    const byName = Object.fromEntries(dependencies.map((d) => [d.name, d.version]));
    expect(byName['phpmailer/phpmailer']).toBe('5.2.16');
    expect(byName['github.com/gin-gonic/gin']).toBe('v1.5.0');
    expect(byName['lodash']).toBe('4.17.20');
  });

  it('collapses the v-prefixed and bare forms of the same package to one version string', () => {
    // The SBOM's `v5.2.16` and the resolver's `5.2.16` now normalize to the
    // identical version, so the downstream upsert key dedups them into one row.
    const dual: CycloneDxSbom = {
      components: [
        { 'bom-ref': 'a', name: 'phpmailer/phpmailer', version: 'v5.2.16', purl: 'pkg:composer/phpmailer/phpmailer@v5.2.16' },
        { 'bom-ref': 'b', name: 'phpmailer/phpmailer', version: '5.2.16', purl: 'pkg:composer/phpmailer/phpmailer@5.2.16' },
      ],
    };
    const versions = parseSbom(dual).dependencies.map((d) => d.version);
    expect(versions).toEqual(['5.2.16', '5.2.16']);
  });
});

describe('getBomRefToNameVersion — version normalization', () => {
  it('normalizes the edge-map version the same way (so edges match dep rows)', () => {
    const sbom: CycloneDxSbom = {
      components: [
        { 'bom-ref': 'php', name: 'phpmailer/phpmailer', version: 'v5.2.16', purl: 'pkg:composer/phpmailer/phpmailer@v5.2.16' },
        { 'bom-ref': 'gin', name: 'github.com/gin-gonic/gin', version: 'v1.5.0', purl: 'pkg:golang/github.com/gin-gonic/gin@v1.5.0' },
      ],
    };
    const map = getBomRefToNameVersion(sbom);
    expect(map.get('php')?.version).toBe('5.2.16');
    expect(map.get('gin')?.version).toBe('v1.5.0');
  });
});
