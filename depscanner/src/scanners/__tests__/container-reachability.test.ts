/**
 * Container reachability classifier tests.
 *
 * The classifier shells out to crane (image export/config) and readelf. Both
 * are injected: a fake ImageExtractor materializes a real on-disk fake image
 * filesystem (so dpkg/apk parsing and detectFileKind run for real), and a fake
 * readelf returns captured-shape DT_NEEDED / .rodata output.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  decorateContainerFindingsWithReachability,
  parseImageConfig,
  type ImageExtractor,
  type ReachabilityRunners,
} from '../container-reachability';
import type { ReadelfRunner } from '../elf-analyzer';
import type { ContainerFinding } from '../types';

// ---- fake image construction -----------------------------------------------

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);

interface FakeFile {
  kind: 'elf' | 'script' | 'data';
  /** DT_NEEDED sonames this binary declares (elf only). */
  dtNeeded?: string[];
  /** Strings to embed for the .rodata dlopen / subprocess-path scan. */
  rodata?: string[];
  /** Raw content (script only, or to seed string-scan for static binaries). */
  content?: string;
}

interface FakeImageSpec {
  /** image-internal path of the entrypoint binary. */
  entrypoint: FakeFile & { imagePath: string };
  /** other binaries/libs keyed by image-internal path. */
  files?: Record<string, FakeFile>;
  /** dpkg package → owned absolute file paths. */
  dpkg?: Record<string, string[]>;
  /** apk package → owned absolute file paths. */
  apk?: Record<string, string[]>;
  config: { Entrypoint?: string[]; Cmd?: string[]; Env?: string[] };
}

const READELF_STATIC = '\nThere is no dynamic section in this file.\n';

function readelfDynamic(sonames: string[]): string {
  return (
    'Dynamic section at offset 0x2dc8 contains 9 entries:\n' +
    sonames
      .map((s) => ` 0x0000000000000001 (NEEDED)  Shared library: [${s}]`)
      .join('\n') +
    '\n'
  );
}

function readelfRodata(strings: string[]): string {
  return (
    "String dump of section '.rodata':\n" +
    strings.map((s, i) => `  [  ${(i * 16).toString(16)}]  ${s}`).join('\n') +
    '\n'
  );
}

/** Write one fake file into the rootfs at its image-internal path. */
function writeFakeFile(rootDir: string, imagePath: string, file: FakeFile): void {
  const abs = path.join(rootDir, imagePath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  if (file.kind === 'elf') {
    // ELF magic + any embedded strings so the static-binary string scan works.
    fs.writeFileSync(abs, Buffer.concat([ELF_MAGIC, Buffer.from(file.content ?? '', 'latin1')]));
  } else if (file.kind === 'script') {
    fs.writeFileSync(abs, file.content ?? '#!/bin/sh\n');
  } else {
    fs.writeFileSync(abs, file.content ?? '');
  }
}

/**
 * Build injectable runners for a fake image. The extractor materializes the
 * rootfs on disk; the readelf runner answers from the spec keyed on basename.
 */
function buildFakeImage(spec: FakeImageSpec): {
  runners: ReachabilityRunners;
  configJson: string;
} {
  const allFiles: Record<string, FakeFile> = {
    [spec.entrypoint.imagePath]: spec.entrypoint,
    ...(spec.files ?? {}),
  };

  const extractor: ImageExtractor = {
    async extract(_imageRef, destDir) {
      const rootDir = path.join(destDir, 'rootfs');
      fs.mkdirSync(rootDir, { recursive: true });
      for (const [imagePath, file] of Object.entries(allFiles)) {
        writeFakeFile(rootDir, imagePath, file);
      }
      // dpkg database
      if (spec.dpkg) {
        const infoDir = path.join(rootDir, 'var/lib/dpkg/info');
        fs.mkdirSync(infoDir, { recursive: true });
        for (const [pkg, files] of Object.entries(spec.dpkg)) {
          fs.writeFileSync(path.join(infoDir, `${pkg}.list`), files.join('\n') + '\n');
        }
      }
      // apk database
      if (spec.apk) {
        const apkDir = path.join(rootDir, 'lib/apk/db');
        fs.mkdirSync(apkDir, { recursive: true });
        const records = Object.entries(spec.apk)
          .map(([pkg, files]) => {
            const fileLines = files
              .map((f) => `F:${path.posix.dirname(f).replace(/^\//, '')}\nR:${path.posix.basename(f)}`)
              .join('\n');
            return `P:${pkg}\nV:1.0\n${fileLines}`;
          })
          .join('\n\n');
        fs.writeFileSync(path.join(apkDir, 'installed'), records + '\n');
      }
    },
    async config() {
      return JSON.stringify({ config: spec.config });
    },
  };

  const readelf: ReadelfRunner = async (args) => {
    const binPath = args[args.length - 1];
    // binPath is a real on-disk path (platform separators); image-path keys
    // are posix — compare basenames computed with the matching dialect.
    const base = path.basename(binPath);
    const file = Object.entries(allFiles).find(
      ([imagePath]) => path.posix.basename(imagePath) === base
    )?.[1];
    if (!file || file.kind !== 'elf') return { stdout: '', exitCode: 1 };
    if (args[0] === '-d') {
      return {
        stdout: file.dtNeeded && file.dtNeeded.length > 0
          ? readelfDynamic(file.dtNeeded)
          : READELF_STATIC,
        exitCode: 0,
      };
    }
    if (args[0] === '-p') {
      return { stdout: readelfRodata(file.rodata ?? []), exitCode: 0 };
    }
    return { stdout: '', exitCode: 1 };
  };

  return {
    runners: { imageExtractor: extractor, readelf },
    configJson: JSON.stringify({ config: spec.config }),
  };
}

function finding(pkg: string, cve: string): ContainerFinding {
  return {
    scanner_version: 'trivy@0.69.3',
    image_reference: 'node:20-slim',
    image_digest: 'a'.repeat(64),
    os_package_name: pkg,
    os_package_version: '1.0',
    os_package_ecosystem: 'debian',
    osv_id: null,
    cve_id: cve,
    severity: 'HIGH',
    cvss_score: 7.5,
    epss_score: null,
    is_kev: false,
    fix_versions: [],
    layer_digest: null,
    description: null,
    rule_doc_url: null,
    container_fingerprint: `${pkg}@${cve}`,
  };
}

let scratch: string;
beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-reach-test-'));
});
afterEach(() => {
  fs.rmSync(scratch, { recursive: true, force: true });
});

// ---- parseImageConfig ------------------------------------------------------

describe('parseImageConfig', () => {
  it('extracts Entrypoint, Cmd and PATH dirs', () => {
    const cfg = parseImageConfig(
      JSON.stringify({
        config: {
          Entrypoint: ['/usr/local/bin/node'],
          Cmd: ['server.js'],
          Env: ['PATH=/opt/bin:/usr/bin', 'NODE_ENV=production'],
        },
      })
    );
    expect(cfg.entrypoint).toEqual(['/usr/local/bin/node']);
    expect(cfg.cmd).toEqual(['server.js']);
    expect(cfg.pathDirs).toEqual(['/opt/bin', '/usr/bin']);
  });

  it('falls back to default PATH dirs on malformed JSON', () => {
    const cfg = parseImageConfig('not json{');
    expect(cfg.entrypoint).toEqual([]);
    expect(cfg.pathDirs).toContain('/usr/bin');
  });
});

// ---- core classification ---------------------------------------------------

describe('decorateContainerFindingsWithReachability', () => {
  it('returns an empty summary for no findings', async () => {
    const { runners } = buildFakeImage({
      entrypoint: { imagePath: '/usr/local/bin/node', kind: 'elf', dtNeeded: [] },
      config: { Entrypoint: ['/usr/local/bin/node'] },
    });
    const summary = await decorateContainerFindingsWithReachability([], {
      imageRef: 'node:20-slim',
      scratchDir: scratch,
      runners,
    });
    expect(summary.total).toBe(0);
  });

  it('marks a package owning a loaded library as module, an unloaded one as unreachable', async () => {
    const { runners } = buildFakeImage({
      entrypoint: {
        imagePath: '/usr/local/bin/node',
        kind: 'elf',
        dtNeeded: ['libssl.so.3', 'libc.so.6'],
      },
      files: {
        '/usr/lib/x86_64-linux-gnu/libssl.so.3': { kind: 'elf', dtNeeded: ['libc.so.6'] },
        '/lib/x86_64-linux-gnu/libc.so.6': { kind: 'elf', dtNeeded: [] },
      },
      dpkg: {
        libssl3: ['/usr/lib/x86_64-linux-gnu/libssl.so.3'],
        libxml2: ['/usr/lib/x86_64-linux-gnu/libxml2.so.2'],
        libc6: ['/lib/x86_64-linux-gnu/libc.so.6'],
      },
      config: { Entrypoint: ['/usr/local/bin/node'] },
    });
    const findings = [finding('libssl3', 'CVE-2024-0001'), finding('libxml2', 'CVE-2024-0002')];
    const summary = await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'node:20-slim',
      scratchDir: scratch,
      runners,
    });
    expect(findings[0].reachability_level).toBe('module');
    expect(findings[1].reachability_level).toBe('unreachable');
    expect(summary.module).toBe(1);
    expect(summary.unreachable).toBe(1);
    expect(summary.classified).toBe(2);
  });

  it('marks every OS package unreachable for a statically-linked entrypoint', async () => {
    const { runners } = buildFakeImage({
      entrypoint: { imagePath: '/app/server', kind: 'elf', dtNeeded: [] },
      dpkg: { libssl3: ['/usr/lib/libssl.so.3'] },
      config: { Entrypoint: ['/app/server'] },
    });
    const findings = [finding('libssl3', 'CVE-2024-0003')];
    const summary = await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'go-app:latest',
      scratchDir: scratch,
      runners,
    });
    expect(findings[0].reachability_level).toBe('unreachable');
    expect(findings[0].reachability_details?.static_linked).toBe(true);
    expect(summary.unreachable).toBe(1);
  });

  it('discovers subprocess libraries a static binary exec()s (skeptic-f10)', async () => {
    const { runners } = buildFakeImage({
      entrypoint: {
        imagePath: '/app/server',
        kind: 'elf',
        dtNeeded: [],
        // a static Go binary that shells out to /usr/bin/git
        content: 'spawn /usr/bin/git clone',
      },
      files: {
        '/usr/bin/git': { kind: 'elf', dtNeeded: ['libcurl.so.4'] },
        '/usr/lib/libcurl.so.4': { kind: 'elf', dtNeeded: [] },
      },
      dpkg: {
        libcurl4: ['/usr/lib/libcurl.so.4'],
        libxml2: ['/usr/lib/libxml2.so.2'],
      },
      config: { Entrypoint: ['/app/server'] },
    });
    const findings = [finding('libcurl4', 'CVE-2024-0004'), finding('libxml2', 'CVE-2024-0005')];
    await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'go-app:latest',
      scratchDir: scratch,
      runners,
    });
    // git's libcurl is reachable via the subprocess; libxml2 is not.
    expect(findings[0].reachability_level).toBe('module');
    expect(findings[1].reachability_level).toBe('unreachable');
  });

  it('chases a shell-wrapper entrypoint to its exec target', async () => {
    const { runners } = buildFakeImage({
      entrypoint: {
        imagePath: '/usr/local/bin/docker-entrypoint.sh',
        kind: 'script',
        content: '#!/bin/sh\nset -e\nexec /usr/local/bin/node "$@"\n',
      },
      files: {
        '/usr/local/bin/node': { kind: 'elf', dtNeeded: ['libssl.so.3'] },
        '/usr/lib/libssl.so.3': { kind: 'elf', dtNeeded: [] },
      },
      dpkg: { libssl3: ['/usr/lib/libssl.so.3'] },
      config: { Entrypoint: ['/usr/local/bin/docker-entrypoint.sh'] },
    });
    const findings = [finding('libssl3', 'CVE-2024-0006')];
    await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'node:20-slim',
      scratchDir: scratch,
      runners,
    });
    expect(findings[0].reachability_level).toBe('module');
    expect(findings[0].reachability_details?.wrapper_script).toBe(true);
  });

  it('falls back to module for a sh -c entrypoint', async () => {
    const { runners } = buildFakeImage({
      entrypoint: { imagePath: '/bin/sh', kind: 'elf', dtNeeded: [] },
      dpkg: { libssl3: ['/usr/lib/libssl.so.3'] },
      config: { Entrypoint: ['/bin/sh', '-c', 'node server.js'] },
    });
    const findings = [finding('libssl3', 'CVE-2024-0007')];
    const summary = await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'node:20-slim',
      scratchDir: scratch,
      runners,
    });
    expect(findings[0].reachability_level).toBe('module');
    expect(summary.fallbackReason).toBe('entrypoint_unparseable');
  });

  it('matches a library discovered only via a dlopen string', async () => {
    const { runners } = buildFakeImage({
      entrypoint: {
        imagePath: '/usr/local/bin/app',
        kind: 'elf',
        dtNeeded: ['libc.so.6'],
        rodata: ['libgssapi_krb5.so.2', '/etc/config'],
      },
      files: { '/lib/libc.so.6': { kind: 'elf', dtNeeded: [] } },
      dpkg: {
        'libgssapi-krb5-2': ['/usr/lib/libgssapi_krb5.so.2'],
        libc6: ['/lib/libc.so.6'],
      },
      config: { Entrypoint: ['/usr/local/bin/app'] },
    });
    const findings = [finding('libgssapi-krb5-2', 'CVE-2024-0008')];
    await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'app:latest',
      scratchDir: scratch,
      runners,
    });
    expect(findings[0].reachability_level).toBe('module');
  });

  it('leaves reachability null for a package not in the OS database', async () => {
    const { runners } = buildFakeImage({
      entrypoint: { imagePath: '/usr/local/bin/node', kind: 'elf', dtNeeded: ['libssl.so.3'] },
      files: { '/usr/lib/libssl.so.3': { kind: 'elf', dtNeeded: [] } },
      dpkg: { libssl3: ['/usr/lib/libssl.so.3'] },
      config: { Entrypoint: ['/usr/local/bin/node'] },
    });
    // 'express' is an npm package — never in the dpkg DB.
    const findings = [finding('express', 'CVE-2024-0009')];
    await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'node:20-slim',
      scratchDir: scratch,
      runners,
    });
    expect(findings[0].reachability_level).toBeNull();
    expect(findings[0].reachability_details?.reason).toBe('package_not_in_os_db');
  });

  it('classifies against an Alpine apk database', async () => {
    const { runners } = buildFakeImage({
      entrypoint: { imagePath: '/usr/bin/app', kind: 'elf', dtNeeded: ['libssl.so.3'] },
      files: { '/usr/lib/libssl.so.3': { kind: 'elf', dtNeeded: [] } },
      apk: {
        'libssl3': ['/usr/lib/libssl.so.3'],
        'libxml2': ['/usr/lib/libxml2.so.2'],
      },
      config: { Entrypoint: ['/usr/bin/app'] },
    });
    const findings = [finding('libssl3', 'CVE-2024-0010'), finding('libxml2', 'CVE-2024-0011')];
    await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'alpine-app:latest',
      scratchDir: scratch,
      runners,
    });
    expect(findings[0].reachability_level).toBe('module');
    expect(findings[1].reachability_level).toBe('unreachable');
  });

  it('falls back to module when image extraction fails', async () => {
    const failingRunners: ReachabilityRunners = {
      imageExtractor: {
        async extract() {
          throw new Error('crane export exit 1');
        },
        async config() {
          return '{}';
        },
      },
      readelf: async () => ({ stdout: '', exitCode: 1 }),
    };
    const findings = [finding('libssl3', 'CVE-2024-0012')];
    const summary = await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'private/img:latest',
      scratchDir: scratch,
      runners: failingRunners,
    });
    expect(findings[0].reachability_level).toBe('module');
    expect(summary.fallbackReason).toBe('image_extraction_failed');
  });

  it('falls back to module when crane config fails', async () => {
    const { runners } = buildFakeImage({
      entrypoint: { imagePath: '/usr/bin/app', kind: 'elf', dtNeeded: [] },
      config: { Entrypoint: ['/usr/bin/app'] },
    });
    runners.imageExtractor.config = async () => {
      throw new Error('crane config exit 1');
    };
    const findings = [finding('libssl3', 'CVE-2024-0013')];
    const summary = await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'img:latest',
      scratchDir: scratch,
      runners,
    });
    expect(findings[0].reachability_level).toBe('module');
    expect(summary.fallbackReason).toBe('image_config_failed');
  });

  it('falls back to module when the budget is already exhausted', async () => {
    const { runners } = buildFakeImage({
      entrypoint: { imagePath: '/usr/bin/app', kind: 'elf', dtNeeded: [] },
      config: { Entrypoint: ['/usr/bin/app'] },
    });
    const findings = [finding('libssl3', 'CVE-2024-0014')];
    const summary = await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'img:latest',
      scratchDir: scratch,
      runners,
      budgetMs: 0,
    });
    expect(findings[0].reachability_level).toBe('module');
    expect(summary.fallbackReason).toBe('reachability_timeout');
  });

  it('falls back to module when the entrypoint binary is missing on disk', async () => {
    const { runners } = buildFakeImage({
      entrypoint: { imagePath: '/usr/bin/present', kind: 'elf', dtNeeded: [] },
      config: { Entrypoint: ['/usr/bin/ghost'] }, // not written to the fake fs
    });
    const findings = [finding('libssl3', 'CVE-2024-0015')];
    const summary = await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'img:latest',
      scratchDir: scratch,
      runners,
    });
    expect(findings[0].reachability_level).toBe('module');
    expect(summary.fallbackReason).toBe('entrypoint_unparseable');
  });

  it('resolves a bare entrypoint command against the image PATH', async () => {
    const { runners } = buildFakeImage({
      entrypoint: { imagePath: '/usr/local/bin/node', kind: 'elf', dtNeeded: ['libssl.so.3'] },
      files: { '/usr/lib/libssl.so.3': { kind: 'elf', dtNeeded: [] } },
      dpkg: { libssl3: ['/usr/lib/libssl.so.3'] },
      config: { Cmd: ['node'], Env: ['PATH=/usr/local/bin:/usr/bin'] },
    });
    const findings = [finding('libssl3', 'CVE-2024-0016')];
    await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'node:20-slim',
      scratchDir: scratch,
      runners,
    });
    expect(findings[0].reachability_level).toBe('module');
  });

  it('records depth_capped evidence when the chain is deeper than the cap', async () => {
    const { runners } = buildFakeImage({
      entrypoint: { imagePath: '/usr/bin/app', kind: 'elf', dtNeeded: ['libA.so'] },
      files: {
        '/usr/lib/libA.so': { kind: 'elf', dtNeeded: ['libB.so'] },
        '/usr/lib/libB.so': { kind: 'elf', dtNeeded: ['libA.so'] },
      },
      dpkg: { liba: ['/usr/lib/libA.so'] },
      config: { Entrypoint: ['/usr/bin/app'] },
    });
    const findings = [finding('liba', 'CVE-2024-0017')];
    await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'app:latest',
      scratchDir: scratch,
      runners,
      // budget is fine; depth cap is internal — this asserts evidence shape
    });
    expect(findings[0].reachability_level).toBe('module');
    expect(findings[0].reachability_details).toHaveProperty('depth_capped');
  });

  it('classifies a mix of reachable, unreachable and unknown packages in one image', async () => {
    const { runners } = buildFakeImage({
      entrypoint: { imagePath: '/usr/local/bin/node', kind: 'elf', dtNeeded: ['libssl.so.3'] },
      files: { '/usr/lib/libssl.so.3': { kind: 'elf', dtNeeded: [] } },
      dpkg: {
        libssl3: ['/usr/lib/libssl.so.3'],
        libxml2: ['/usr/lib/libxml2.so.2'],
      },
      config: { Entrypoint: ['/usr/local/bin/node'] },
    });
    const findings = [
      finding('libssl3', 'CVE-2024-0018'),
      finding('libxml2', 'CVE-2024-0019'),
      finding('lodash', 'CVE-2024-0020'),
    ];
    const summary = await decorateContainerFindingsWithReachability(findings, {
      imageRef: 'node:20-slim',
      scratchDir: scratch,
      runners,
    });
    expect(findings.map((f) => f.reachability_level)).toEqual(['module', 'unreachable', null]);
    expect(summary.classified).toBe(2);
  });
});
