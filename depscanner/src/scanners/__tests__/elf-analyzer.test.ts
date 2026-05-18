/**
 * ELF analyzer unit tests.
 *
 * readelf is Linux-only and not present on a Windows dev box, so the analyzer
 * takes an injectable ReadelfRunner. These tests feed it captured real-shaped
 * readelf output rather than shelling out — deterministic on every platform.
 * The real-binary wall-clock spike (plan spikes 4/5) is measured separately
 * inside the depscanner Docker image during a real extraction.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  extractDtNeeded,
  extractDlopenStrings,
  detectFileKind,
  resolveWrapperScript,
  resolveLoadedLibraries,
  computeEntrypointSha256,
  type ReadelfRunner,
} from '../elf-analyzer';

// ---- captured real-shaped readelf output -----------------------------------

/** `readelf -d` on a dynamically-linked glibc binary. */
function readelfDynamic(sonames: string[]): string {
  const head =
    'Dynamic section at offset 0x2dc8 contains 27 entries:\n' +
    '  Tag        Type                         Name/Value\n';
  const needed = sonames
    .map(
      (s) =>
        ` 0x0000000000000001 (NEEDED)             Shared library: [${s}]`
    )
    .join('\n');
  const tail = '\n 0x000000000000000c (INIT)               0x4000\n';
  return head + needed + tail;
}

/** `readelf -d` on a statically-linked binary (Go CGO_ENABLED=0). */
const READELF_STATIC = '\nThere is no dynamic section in this file.\n';

/** `readelf -p .rodata` dump. */
function readelfRodata(strings: string[]): string {
  return (
    "String dump of section '.rodata':\n" +
    strings.map((s, i) => `  [  ${(i * 16).toString(16)}]  ${s}`).join('\n') +
    '\n'
  );
}

/**
 * Build a ReadelfRunner backed by a path → fixture map. The binary path is the
 * last argument readelf is invoked with (`-d <path>` / `-p .rodata <path>`).
 */
function makeRunner(
  fixtures: Record<string, { dynamic?: string; rodata?: string }>
): ReadelfRunner {
  return async (args) => {
    const binPath = args[args.length - 1];
    const fx = fixtures[binPath];
    if (!fx) return { stdout: '', exitCode: 1 };
    if (args[0] === '-d') {
      return { stdout: fx.dynamic ?? READELF_STATIC, exitCode: 0 };
    }
    if (args[0] === '-p') {
      if (fx.rodata === undefined) return { stdout: '', exitCode: 1 };
      return { stdout: fx.rodata, exitCode: 0 };
    }
    return { stdout: '', exitCode: 1 };
  };
}

let tmpRoot: string;
beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-elf-test-'));
});
afterEach(() => {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

// ---- extractDtNeeded -------------------------------------------------------

describe('extractDtNeeded', () => {
  it('parses every NEEDED soname from a dynamic section', async () => {
    const runner = makeRunner({
      '/app/node': { dynamic: readelfDynamic(['libssl.so.3', 'libcrypto.so.3', 'libc.so.6']) },
    });
    const r = await extractDtNeeded('/app/node', runner);
    expect(r.status).toBe('ok');
    expect(r.needed).toEqual(['libssl.so.3', 'libcrypto.so.3', 'libc.so.6']);
  });

  it('reports status ok with no sonames for a statically-linked binary', async () => {
    const runner = makeRunner({ '/app/server': { dynamic: READELF_STATIC } });
    const r = await extractDtNeeded('/app/server', runner);
    expect(r.status).toBe('ok');
    expect(r.needed).toEqual([]);
  });

  it('de-duplicates a soname that appears twice', async () => {
    const runner = makeRunner({
      '/app/bin': { dynamic: readelfDynamic(['libc.so.6', 'libc.so.6', 'libm.so.6']) },
    });
    expect((await extractDtNeeded('/app/bin', runner)).needed).toEqual([
      'libc.so.6',
      'libm.so.6',
    ]);
  });

  it('reports status unparsable (not static) when readelf exits non-zero', async () => {
    const runner: ReadelfRunner = async () => ({ stdout: '', exitCode: 1 });
    const r = await extractDtNeeded('/nope', runner);
    expect(r.status).toBe('unparsable');
    expect(r.needed).toEqual([]);
  });

  it('reports status unavailable (not static) when readelf cannot be spawned', async () => {
    const runner: ReadelfRunner = async () => {
      throw new Error('spawn failed');
    };
    const r = await extractDtNeeded('/app/bin', runner);
    expect(r.status).toBe('unavailable');
    expect(r.needed).toEqual([]);
  });
});

// ---- extractDlopenStrings --------------------------------------------------

describe('extractDlopenStrings', () => {
  it('extracts lib*.so* literals from a .rodata dump', async () => {
    const runner = makeRunner({
      '/app/bin': {
        rodata: readelfRodata(['/etc/ssl/certs', 'libnss_dns.so.2', 'libgssapi_krb5.so.2']),
      },
    });
    const r = await extractDlopenStrings('/app/bin', runner);
    expect(r.status).toBe('ok');
    expect(r.libraries.sort()).toEqual(['libgssapi_krb5.so.2', 'libnss_dns.so.2']);
  });

  it('de-duplicates and lower-cases matched literals', async () => {
    const runner = makeRunner({
      '/app/bin': { rodata: readelfRodata(['libfoo.so', 'LibFoo.so', 'libfoo.so']) },
    });
    expect((await extractDlopenStrings('/app/bin', runner)).libraries).toEqual(['libfoo.so']);
  });

  it('returns no libraries when the .rodata section is absent', async () => {
    const runner = makeRunner({ '/app/bin': { dynamic: READELF_STATIC } }); // no rodata key
    const r = await extractDlopenStrings('/app/bin', runner);
    expect(r.status).toBe('ok');
    expect(r.libraries).toEqual([]);
  });

  it('reports status unavailable when readelf cannot be spawned', async () => {
    const runner: ReadelfRunner = async () => {
      throw new Error('spawn failed');
    };
    const r = await extractDlopenStrings('/app/bin', runner);
    expect(r.status).toBe('unavailable');
    expect(r.libraries).toEqual([]);
  });

  it('ignores strings that are not shared-library names', async () => {
    const runner = makeRunner({
      '/app/bin': { rodata: readelfRodata(['GET / HTTP/1.1', 'some.config.value', '/proc/self/exe']) },
    });
    expect((await extractDlopenStrings('/app/bin', runner)).libraries).toEqual([]);
  });
});

// ---- detectFileKind + resolveWrapperScript ---------------------------------

describe('detectFileKind', () => {
  it('classifies an ELF magic-byte file as elf', async () => {
    const f = path.join(tmpRoot, 'bin');
    fs.writeFileSync(f, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01]));
    expect(await detectFileKind(f)).toBe('elf');
  });

  it('classifies a shebang file as script', async () => {
    const f = path.join(tmpRoot, 'entry.sh');
    fs.writeFileSync(f, '#!/bin/sh\nexec /usr/local/bin/node "$@"\n');
    expect(await detectFileKind(f)).toBe('script');
  });

  it('classifies an unknown file as other', async () => {
    const f = path.join(tmpRoot, 'data');
    fs.writeFileSync(f, 'plain text content');
    expect(await detectFileKind(f)).toBe('other');
  });
});

describe('resolveWrapperScript', () => {
  it('chases the exec target of a shell wrapper', async () => {
    const f = path.join(tmpRoot, 'docker-entrypoint.sh');
    fs.writeFileSync(f, '#!/bin/sh\nset -e\nexec /usr/local/bin/node "$@"\n');
    const r = await resolveWrapperScript(f);
    expect(r.isWrapperScript).toBe(true);
    expect(r.target).toBe('/usr/local/bin/node');
  });

  it('reports an ELF entrypoint as not-a-wrapper, unchanged target', async () => {
    const f = path.join(tmpRoot, 'node');
    fs.writeFileSync(f, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02]));
    const r = await resolveWrapperScript(f);
    expect(r.isWrapperScript).toBe(false);
    expect(r.target).toBe(f);
  });

  it('marks a script with no exec target as a wrapper but leaves target unchanged (fail-closed)', async () => {
    const f = path.join(tmpRoot, 'noop.sh');
    fs.writeFileSync(f, '#!/bin/sh\necho "hello"\n');
    const r = await resolveWrapperScript(f);
    expect(r.isWrapperScript).toBe(true);
    expect(r.target).toBe(f);
  });
});

// ---- resolveLoadedLibraries ------------------------------------------------

/** Create an empty stub library file under rootDir at an image-internal path. */
function stubLib(rootDir: string, imagePath: string): string {
  const abs = path.join(rootDir, imagePath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, '');
  return abs;
}

describe('resolveLoadedLibraries', () => {
  it('walks the DT_NEEDED chain recursively into resolved libraries', async () => {
    const entry = path.join(tmpRoot, 'app', 'node');
    fs.mkdirSync(path.dirname(entry), { recursive: true });
    fs.writeFileSync(entry, '');
    const libssl = stubLib(tmpRoot, '/usr/lib/x86_64-linux-gnu/libssl.so.3');
    const libcrypto = stubLib(tmpRoot, '/usr/lib/x86_64-linux-gnu/libcrypto.so.3');
    stubLib(tmpRoot, '/lib/x86_64-linux-gnu/libc.so.6');

    const runner = makeRunner({
      [entry]: { dynamic: readelfDynamic(['libssl.so.3', 'libc.so.6']) },
      [libssl]: { dynamic: readelfDynamic(['libcrypto.so.3', 'libc.so.6']) },
      [libcrypto]: { dynamic: readelfDynamic(['libc.so.6']) },
    });

    const r = await resolveLoadedLibraries({ entrypointPath: entry, rootDir: tmpRoot, runner });
    expect(r.loaded.sort()).toEqual(['libc.so.6', 'libcrypto.so.3', 'libssl.so.3']);
    expect(r.chain['<entrypoint>']).toEqual(['libssl.so.3', 'libc.so.6']);
    expect(r.chain['libssl.so.3']).toEqual(['libcrypto.so.3', 'libc.so.6']);
    expect(r.depth_capped).toBe(false);
    expect(r.budget_exceeded).toBe(false);
  });

  it('is cycle-safe when libraries depend on each other', async () => {
    const entry = path.join(tmpRoot, 'bin');
    fs.writeFileSync(entry, '');
    const libA = stubLib(tmpRoot, '/usr/lib/libA.so.1');
    const libB = stubLib(tmpRoot, '/usr/lib/libB.so.1');

    const runner = makeRunner({
      [entry]: { dynamic: readelfDynamic(['libA.so.1']) },
      [libA]: { dynamic: readelfDynamic(['libB.so.1']) },
      [libB]: { dynamic: readelfDynamic(['libA.so.1']) }, // cycle back
    });

    const r = await resolveLoadedLibraries({ entrypointPath: entry, rootDir: tmpRoot, runner });
    expect(r.loaded.sort()).toEqual(['libA.so.1', 'libB.so.1']);
    expect(r.budget_exceeded).toBe(false);
  });

  it('records a soname in loaded even when the file is unresolvable, without recursing', async () => {
    const entry = path.join(tmpRoot, 'bin');
    fs.writeFileSync(entry, '');
    const runner = makeRunner({
      [entry]: { dynamic: readelfDynamic(['libphantom.so.9']) },
    });
    const r = await resolveLoadedLibraries({ entrypointPath: entry, rootDir: tmpRoot, runner });
    expect(r.loaded).toEqual(['libphantom.so.9']);
    expect(r.chain['libphantom.so.9']).toBeUndefined();
  });

  it('sets depth_capped when the chain is deeper than maxDepth', async () => {
    const entry = path.join(tmpRoot, 'bin');
    fs.writeFileSync(entry, '');
    const l1 = stubLib(tmpRoot, '/usr/lib/l1.so');
    const l2 = stubLib(tmpRoot, '/usr/lib/l2.so');
    const runner = makeRunner({
      [entry]: { dynamic: readelfDynamic(['l1.so']) },
      [l1]: { dynamic: readelfDynamic(['l2.so']) },
      [l2]: { dynamic: readelfDynamic(['l1.so']) },
    });
    const r = await resolveLoadedLibraries({
      entrypointPath: entry,
      rootDir: tmpRoot,
      runner,
      maxDepth: 1,
    });
    expect(r.depth_capped).toBe(true);
  });

  it('sets width_capped when unique libraries exceed maxWidth', async () => {
    const entry = path.join(tmpRoot, 'bin');
    fs.writeFileSync(entry, '');
    const runner = makeRunner({
      [entry]: { dynamic: readelfDynamic(['a.so', 'b.so', 'c.so', 'd.so', 'e.so']) },
    });
    const r = await resolveLoadedLibraries({
      entrypointPath: entry,
      rootDir: tmpRoot,
      runner,
      maxWidth: 3,
    });
    expect(r.width_capped).toBe(true);
    expect(r.loaded.length).toBe(3);
  });

  it('sets budget_exceeded when the wall-clock budget runs out', async () => {
    const entry = path.join(tmpRoot, 'bin');
    fs.writeFileSync(entry, '');
    // A resolvable chain so the walk iterates more than once; the budget check
    // runs at the top of each iteration and trips after the first slow readelf.
    const libA = stubLib(tmpRoot, '/usr/lib/libA.so');
    stubLib(tmpRoot, '/usr/lib/libB.so');
    const slowRunner: ReadelfRunner = async (args) => {
      await new Promise((res) => setTimeout(res, 15));
      const binPath = args[args.length - 1];
      const needed = binPath === entry ? ['libA.so'] : ['libB.so'];
      return { stdout: readelfDynamic(needed), exitCode: 0 };
    };
    const r = await resolveLoadedLibraries({
      entrypointPath: entry,
      rootDir: tmpRoot,
      runner: slowRunner,
      budgetMs: 1,
    });
    expect(r.budget_exceeded).toBe(true);
    // libA was reached; libB was not — the walk stopped mid-flight.
    expect(r.loaded).toContain('libA.so');
    void libA;
  });
});

// ---- computeEntrypointSha256 -----------------------------------------------

describe('computeEntrypointSha256', () => {
  it('produces a stable SHA-256 over the binary contents', async () => {
    const f = path.join(tmpRoot, 'bin');
    fs.writeFileSync(f, 'deterministic-bytes');
    const a = await computeEntrypointSha256(f);
    const b = await computeEntrypointSha256(f);
    expect(a).toBe(b);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
  });

  it('produces different hashes for different contents', async () => {
    const f1 = path.join(tmpRoot, 'a');
    const f2 = path.join(tmpRoot, 'b');
    fs.writeFileSync(f1, 'content-one');
    fs.writeFileSync(f2, 'content-two');
    expect(await computeEntrypointSha256(f1)).not.toBe(await computeEntrypointSha256(f2));
  });
});
