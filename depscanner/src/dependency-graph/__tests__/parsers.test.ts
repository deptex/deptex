/**
 * Unit tests for dependency-graph recovery parsers.
 *
 * Covers the five manifest/lockfile parsers + the PyPI requirements fallback,
 * plus `depMatchKey` and `applyRecoveredDirectSet`. The Maven (`mvn
 * dependency:tree`) and PyPI pipdeptree paths shell out to external tools and
 * are exercised by the M0 spike / M4 corpus against real repos, not here.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  parseNpmDirectSet,
  parseComposerDirectSet,
  parseGolangDirectSet,
  parseCargoDirectSet,
  parseGemDirectSet,
  parsePypiDirectSet,
  normalizePypiName,
} from '../parsers';
import { depMatchKey, applyRecoveredDirectSet, type GraphRecoveryResult } from '../index';
import type { ParsedSbomDep } from '../../sbom';

function tmpRepo(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'depgraph-'));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

describe('parseNpmDirectSet', () => {
  it('collects dependencies + devDependencies + optional + peer', () => {
    const dir = tmpRepo({
      'package.json': JSON.stringify({
        dependencies: { express: '^4.0.0', lodash: '^4.17.0' },
        devDependencies: { jest: '^29.0.0' },
        optionalDependencies: { fsevents: '^2.0.0' },
        peerDependencies: { react: '^18.0.0' },
      }),
    });
    const set = parseNpmDirectSet(dir);
    expect(set).not.toBeNull();
    expect([...set!].sort()).toEqual(['express', 'fsevents', 'jest', 'lodash', 'react']);
  });

  it('returns null when package.json is absent', () => {
    expect(parseNpmDirectSet(tmpRepo({}))).toBeNull();
  });

  it('returns null on malformed package.json', () => {
    expect(parseNpmDirectSet(tmpRepo({ 'package.json': '{not json' }))).toBeNull();
  });
});

describe('parseComposerDirectSet', () => {
  it('collects require + require-dev, dropping php/ext-* platform entries', () => {
    const dir = tmpRepo({
      'composer.json': JSON.stringify({
        require: { php: '>=8.0', 'ext-json': '*', 'symfony/console': '^6.0' },
        'require-dev': { 'phpunit/phpunit': '^10.0' },
      }),
    });
    const set = parseComposerDirectSet(dir);
    expect([...set!].sort()).toEqual(['phpunit/phpunit', 'symfony/console']);
  });
});

describe('parseGolangDirectSet', () => {
  it('takes require entries but excludes // indirect ones', () => {
    const dir = tmpRepo({
      'go.mod': [
        'module example.com/app',
        'go 1.21',
        'require (',
        '\tgithub.com/gin-gonic/gin v1.9.1',
        '\tgolang.org/x/sys v0.1.0 // indirect',
        ')',
        'require github.com/single/dep v1.0.0',
      ].join('\n'),
    });
    const set = parseGolangDirectSet(dir);
    expect([...set!].sort()).toEqual(['github.com/gin-gonic/gin', 'github.com/single/dep']);
  });
});

describe('parseCargoDirectSet', () => {
  it('collects [dependencies] / [dev-dependencies] inline and sub-table forms', () => {
    const dir = tmpRepo({
      'Cargo.toml': [
        '[package]',
        'name = "myapp"',
        '[dependencies]',
        'serde = "1.0"',
        'tokio = { version = "1", features = ["full"] }',
        '[dev-dependencies]',
        'criterion = "0.5"',
        '[dependencies.axum]',
        'version = "0.7"',
      ].join('\n'),
    });
    const set = parseCargoDirectSet(dir);
    expect([...set!].sort()).toEqual(['axum', 'criterion', 'serde', 'tokio']);
  });
});

describe('parseGemDirectSet', () => {
  it('reads the DEPENDENCIES section of Gemfile.lock', () => {
    const dir = tmpRepo({
      'Gemfile.lock': [
        'GEM',
        '  specs:',
        '    rails (7.0.0)',
        '    rack (2.2.0)',
        '',
        'DEPENDENCIES',
        '  rails (~> 7.0)',
        '  rspec!',
        '',
        'BUNDLED WITH',
        '   2.4.0',
      ].join('\n'),
    });
    const set = parseGemDirectSet(dir);
    expect([...set!].sort()).toEqual(['rails', 'rspec']);
  });

  it('falls back to gem lines in the Gemfile when no lockfile', () => {
    const dir = tmpRepo({
      Gemfile: ["source 'https://rubygems.org'", "gem 'sinatra'", "gem \"puma\", '~> 6.0'"].join('\n'),
    });
    const set = parseGemDirectSet(dir);
    expect([...set!].sort()).toEqual(['puma', 'sinatra']);
  });
});

describe('parsePypiDirectSet (requirements.txt fallback)', () => {
  it('parses requirements.txt declarations when pipdeptree is unavailable', () => {
    // No installed env / pipdeptree in the unit-test sandbox, so this exercises
    // the requirements.txt fallback path.
    const dir = tmpRepo({
      'requirements.txt': ['# comment', 'Flask==2.0.0', 'requests>=2.28', '-r other.txt', ''].join('\n'),
    });
    const set = parsePypiDirectSet(dir);
    expect(set).not.toBeNull();
    expect(set!.has('flask')).toBe(true);
    expect(set!.has('requests')).toBe(true);
  });

  it('normalizes PyPI names (case + ._- equivalence)', () => {
    expect(normalizePypiName('Python_Dateutil')).toBe('python-dateutil');
    expect(normalizePypiName('ruamel.yaml')).toBe('ruamel-yaml');
  });
});

describe('depMatchKey', () => {
  it('keys Maven on groupId:artifactId', () => {
    expect(depMatchKey('spring-core', 'org.springframework', 'maven')).toBe(
      'org.springframework:spring-core',
    );
  });
  it('normalizes PyPI names', () => {
    expect(depMatchKey('Python_DateUtil', null, 'pypi')).toBe('python-dateutil');
  });
  it('lowercases the bare name for other ecosystems', () => {
    expect(depMatchKey('Express', null, 'npm')).toBe('express');
  });
});

describe('applyRecoveredDirectSet', () => {
  const mkDep = (name: string, is_direct: boolean): ParsedSbomDep => ({
    name,
    version: '1.0.0',
    namespace: null,
    license: null,
    is_direct,
    source: is_direct ? 'dependencies' : 'transitive',
    bomRef: `pkg:npm/${name}@1.0.0`,
  });

  it('flips is_direct/source to match the recovered set and counts changes', () => {
    const deps = [mkDep('express', false), mkDep('lodash', true), mkDep('debug', true)];
    const recovery: GraphRecoveryResult = {
      directKeys: new Set(['express']),
      method: 'manifest',
    };
    const changed = applyRecoveredDirectSet(deps, recovery, 'npm');
    expect(changed).toBe(3); // express false->true, lodash true->false, debug true->false
    expect(deps.find((d) => d.name === 'express')!.is_direct).toBe(true);
    expect(deps.find((d) => d.name === 'express')!.source).toBe('dependencies');
    expect(deps.find((d) => d.name === 'lodash')!.is_direct).toBe(false);
    expect(deps.find((d) => d.name === 'lodash')!.source).toBe('transitive');
    expect(deps.find((d) => d.name === 'debug')!.is_direct).toBe(false);
  });
});
