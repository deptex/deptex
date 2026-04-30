import * as fs from 'fs';
import { parseSbom, patchDevDependencies, type ParsedSbomDep } from '../sbom';

jest.mock('fs', () => {
  const actual = jest.requireActual<typeof import('fs')>('fs');
  return {
    ...actual,
    readFileSync: jest.fn(),
  };
});

const BASIC_SBOM = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  metadata: { component: { 'bom-ref': 'root', name: 'my-app', version: '1.0.0' } },
  components: [
    { 'bom-ref': 'pkg:npm/lodash@4.17.21', name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21', licenses: [{ license: { id: 'MIT' } }] },
    { 'bom-ref': 'pkg:npm/express@4.18.0', name: 'express', version: '4.18.0', purl: 'pkg:npm/express@4.18.0' },
    { 'bom-ref': 'pkg:npm/body-parser@1.20.0', name: 'body-parser', version: '1.20.0', purl: 'pkg:npm/body-parser@1.20.0' },
  ],
  dependencies: [
    { ref: 'root', dependsOn: ['pkg:npm/lodash@4.17.21', 'pkg:npm/express@4.18.0'] },
    { ref: 'pkg:npm/express@4.18.0', dependsOn: ['pkg:npm/body-parser@1.20.0'] },
  ],
};

describe('parseSbom', () => {
  it('parses basic npm SBOM with direct and transitive deps', () => {
    const { dependencies } = parseSbom(BASIC_SBOM);
    expect(dependencies).toHaveLength(3);
    const lodash = dependencies.find((d) => d.name === 'lodash');
    const express = dependencies.find((d) => d.name === 'express');
    const bodyParser = dependencies.find((d) => d.name === 'body-parser');
    expect(lodash?.is_direct).toBe(true);
    expect(express?.is_direct).toBe(true);
    expect(bodyParser?.is_direct).toBe(false);
  });

  it('correctly identifies direct vs transitive based on root dependsOn', () => {
    const { dependencies } = parseSbom(BASIC_SBOM);
    const direct = dependencies.filter((d) => d.is_direct);
    const transitive = dependencies.filter((d) => !d.is_direct);
    expect(direct).toHaveLength(2);
    expect(transitive).toHaveLength(1);
    expect(direct.map((d) => d.name).sort()).toEqual(['express', 'lodash']);
    expect(transitive.map((d) => d.name)).toEqual(['body-parser']);
  });

  it('extracts license from CycloneDX license format (array of { license: { id } })', () => {
    const { dependencies } = parseSbom(BASIC_SBOM);
    const lodash = dependencies.find((d) => d.name === 'lodash');
    expect(lodash?.license).toBe('MIT');
  });

  it('extracts license from string format', () => {
    const sbom = {
      ...BASIC_SBOM,
      components: [{ 'bom-ref': 'pkg:npm/foo@1.0.0', name: 'foo', version: '1.0.0', licenses: 'Apache-2.0' }],
      dependencies: [{ ref: 'root', dependsOn: ['pkg:npm/foo@1.0.0'] }],
    };
    const { dependencies } = parseSbom(sbom);
    expect(dependencies[0].license).toBe('Apache-2.0');
  });

  it('returns empty array for SBOM with no components', () => {
    const { dependencies } = parseSbom({ ...BASIC_SBOM, components: [] });
    expect(dependencies).toEqual([]);
  });

  it('returns empty array for SBOM with no metadata root component', () => {
    const sbom = { ...BASIC_SBOM, metadata: {} };
    const { dependencies } = parseSbom(sbom);
    expect(dependencies).toEqual([]);
  });

  it('handles missing version gracefully (skips component)', () => {
    const sbom = {
      ...BASIC_SBOM,
      components: [
        { 'bom-ref': 'pkg:npm/nover@', name: 'nover', purl: 'pkg:npm/nover' },
      ],
      dependencies: [{ ref: 'root', dependsOn: ['pkg:npm/nover@'] }],
    };
    const { dependencies } = parseSbom(sbom);
    expect(dependencies).toHaveLength(0);
  });

  it('extracts relationships correctly', () => {
    const { relationships } = parseSbom(BASIC_SBOM);
    expect(relationships).toContainEqual({ parentBomRef: 'root', childBomRef: 'pkg:npm/lodash@4.17.21' });
    expect(relationships).toContainEqual({ parentBomRef: 'root', childBomRef: 'pkg:npm/express@4.18.0' });
    expect(relationships).toContainEqual({ parentBomRef: 'pkg:npm/express@4.18.0', childBomRef: 'pkg:npm/body-parser@1.20.0' });
  });

  it('uses purl for name/version when component fields are missing', () => {
    const sbom = {
      ...BASIC_SBOM,
      components: [{ 'bom-ref': 'pkg:npm/from-purl@2.0.0', purl: 'pkg:npm/from-purl@2.0.0' }],
      dependencies: [{ ref: 'root', dependsOn: ['pkg:npm/from-purl@2.0.0'] }],
    };
    const { dependencies } = parseSbom(sbom);
    expect(dependencies).toHaveLength(1);
    expect(dependencies[0].name).toBe('from-purl');
    expect(dependencies[0].version).toBe('2.0.0');
  });
});

describe('patchDevDependencies', () => {
  beforeEach(() => {
    (fs.readFileSync as jest.Mock).mockReset();
  });

  it('npm: patches direct deps that are in package.json devDependencies', () => {
    const deps: ParsedSbomDep[] = [
      { name: 'lodash', version: '4.17.21', license: null, is_direct: true, source: 'dependencies', bomRef: 'pkg:npm/lodash@4.17.21' },
      { name: 'jest', version: '29.0.0', license: null, is_direct: true, source: 'dependencies', bomRef: 'pkg:npm/jest@29.0.0' },
    ];
    (fs.readFileSync as jest.Mock).mockReturnValue(JSON.stringify({ devDependencies: { jest: '^29.0.0' } }));
    patchDevDependencies(deps, '/repo', 'npm');
    expect(deps[0].source).toBe('dependencies');
    expect(deps[1].source).toBe('devDependencies');
  });

  it('npm: does not patch transitive deps even if they match devDependencies names', () => {
    const deps: ParsedSbomDep[] = [
      { name: 'lodash', version: '4.17.21', license: null, is_direct: false, source: 'transitive', bomRef: 'pkg:npm/lodash@4.17.21' },
    ];
    (fs.readFileSync as jest.Mock).mockReturnValue(JSON.stringify({ devDependencies: { lodash: '^4.0.0' } }));
    patchDevDependencies(deps, '/repo', 'npm');
    expect(deps[0].source).toBe('transitive');
  });

  it('npm: does nothing when package.json has no devDependencies', () => {
    const deps: ParsedSbomDep[] = [
      { name: 'lodash', version: '4.17.21', license: null, is_direct: true, source: 'dependencies', bomRef: 'pkg:npm/lodash@4.17.21' },
    ];
    (fs.readFileSync as jest.Mock).mockReturnValue(JSON.stringify({ dependencies: { lodash: '^4.0.0' } }));
    patchDevDependencies(deps, '/repo', 'npm');
    expect(deps[0].source).toBe('dependencies');
  });

  it('npm: handles missing package.json gracefully (no crash)', () => {
    const deps: ParsedSbomDep[] = [
      { name: 'lodash', version: '4.17.21', license: null, is_direct: true, source: 'dependencies', bomRef: 'pkg:npm/lodash@4.17.21' },
    ];
    (fs.readFileSync as jest.Mock).mockImplementation(() => {
      throw new Error('ENOENT');
    });
    expect(() => patchDevDependencies(deps, '/repo', 'npm')).not.toThrow();
    expect(deps[0].source).toBe('dependencies');
  });
});
