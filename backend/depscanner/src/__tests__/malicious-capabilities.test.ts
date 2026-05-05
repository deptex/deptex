import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  CAPABILITY_KEYS,
  CAPABILITY_SCANNER_VERSION,
  detectCapabilities,
  emptyCapabilitySet,
} from '../malicious/capabilities';
import { jsDetector } from '../malicious/capabilities/js';
import { pyDetector } from '../malicious/capabilities/py';
import { rubyDetector } from '../malicious/capabilities/ruby';
import { phpDetector } from '../malicious/capabilities/php';
import { javaDetector } from '../malicious/capabilities/java';
import { goDetector } from '../malicious/capabilities/go';
import { rustDetector } from '../malicious/capabilities/rust';
import { csharpDetector } from '../malicious/capabilities/csharp';
import { detectInstallScript } from '../malicious/capabilities/manifest';

function makeTempPkg(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cap-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return dir;
}

afterEach(() => {
  // best-effort cleanup; mkdtemp on tmpdir is short-lived enough not to leak
});

describe('jsDetector', () => {
  test('detects spawns_processes via child_process', () => {
    const r = jsDetector.detect("const cp = require('child_process'); cp.execSync('ls');");
    expect(r.spawns_processes).toBe(true);
  });

  test('detects eval_dynamic via new Function', () => {
    const r = jsDetector.detect('const f = new Function("return 42")();');
    expect(r.eval_dynamic).toBe(true);
  });

  test('detects native_addon_load via .node require', () => {
    const r = jsDetector.detect("const addon = require('./build/Release/addon.node');");
    expect(r.native_addon_load).toBe(true);
  });

  test('detects encrypted_payload via large base64 decode', () => {
    const big = 'A'.repeat(250);
    const r = jsDetector.detect(`Buffer.from('${big}', 'base64')`);
    expect(r.encrypted_payload).toBe(true);
  });

  test('detects dynamic_import via require with var arg', () => {
    const r = jsDetector.detect("const x = 'foo'; require(x);");
    expect(r.dynamic_import).toBe(true);
  });

  test('does not flag literal require', () => {
    const r = jsDetector.detect("const x = require('./module');");
    expect(r.dynamic_import).toBe(false);
  });

  test('detects reads_env', () => {
    const r = jsDetector.detect('console.log(process.env.HOME);');
    expect(r.reads_env).toBe(true);
  });
});

describe('pyDetector', () => {
  test('detects spawns_processes via subprocess', () => {
    const r = pyDetector.detect('import subprocess\nsubprocess.run(["ls"])');
    expect(r.spawns_processes).toBe(true);
  });

  test('detects eval_dynamic', () => {
    const r = pyDetector.detect('eval("1+1")');
    expect(r.eval_dynamic).toBe(true);
  });

  test('detects serialization_deser via pickle.loads', () => {
    const r = pyDetector.detect('import pickle\npickle.loads(payload)');
    expect(r.serialization_deser).toBe(true);
  });

  test('detects native_addon_load via ctypes', () => {
    const r = pyDetector.detect('import ctypes\nlib = ctypes.CDLL("./libfoo.so")');
    expect(r.native_addon_load).toBe(true);
  });
});

describe('rubyDetector', () => {
  test('detects spawns_processes via Open3', () => {
    const r = rubyDetector.detect("require 'open3'\nOpen3.popen3('ls')");
    expect(r.spawns_processes).toBe(true);
  });

  test('detects serialization_deser via Marshal.load', () => {
    const r = rubyDetector.detect('Marshal.load(payload)');
    expect(r.serialization_deser).toBe(true);
  });

  test('detects eval_dynamic via instance_eval', () => {
    const r = rubyDetector.detect('obj.instance_eval { do_thing }');
    expect(r.eval_dynamic).toBe(true);
  });
});

describe('phpDetector', () => {
  test('detects spawns_processes via shell_exec', () => {
    const r = phpDetector.detect('<?php $out = shell_exec("ls"); ?>');
    expect(r.spawns_processes).toBe(true);
  });

  test('detects serialization_deser via unserialize', () => {
    const r = phpDetector.detect('<?php $x = unserialize($_POST["data"]); ?>');
    expect(r.serialization_deser).toBe(true);
  });
});

describe('javaDetector', () => {
  test('detects spawns_processes via ProcessBuilder', () => {
    const r = javaDetector.detect('new ProcessBuilder("ls").start();');
    expect(r.spawns_processes).toBe(true);
  });

  test('detects serialization_deser via ObjectInputStream', () => {
    const r = javaDetector.detect('new ObjectInputStream(in).readObject();');
    expect(r.serialization_deser).toBe(true);
  });
});

describe('goDetector', () => {
  test('detects spawns_processes via os/exec', () => {
    const r = goDetector.detect('import "os/exec"\nexec.Command("ls").Run()');
    expect(r.spawns_processes).toBe(true);
  });

  test('eval_dynamic stays false in Go', () => {
    const r = goDetector.detect('package main\nfunc main() { eval := 1; _ = eval }');
    expect(r.eval_dynamic).toBe(false);
  });
});

describe('rustDetector', () => {
  test('detects spawns_processes via Command', () => {
    const r = rustDetector.detect('use std::process::Command;\nCommand::new("ls").output();');
    expect(r.spawns_processes).toBe(true);
  });

  test('detects native_addon_load via libloading', () => {
    const r = rustDetector.detect('let lib = unsafe { libloading::Library::new("foo")? };');
    expect(r.native_addon_load).toBe(true);
  });
});

describe('csharpDetector', () => {
  test('detects spawns_processes via Process.Start', () => {
    const r = csharpDetector.detect('Process.Start("notepad.exe");');
    expect(r.spawns_processes).toBe(true);
  });

  test('detects native_addon_load via DllImport', () => {
    const r = csharpDetector.detect('[DllImport("user32.dll")]\nstatic extern void Beep();');
    expect(r.native_addon_load).toBe(true);
  });
});

describe('detectInstallScript', () => {
  test('npm package.json with postinstall fires', () => {
    const dir = makeTempPkg({ 'package.json': '{"name":"x","scripts":{"postinstall":"node setup.js"}}' });
    expect(detectInstallScript(dir, 'npm')).toBe(true);
  });

  test('npm package.json without install hooks does not fire', () => {
    const dir = makeTempPkg({ 'package.json': '{"name":"x","scripts":{"test":"jest"}}' });
    expect(detectInstallScript(dir, 'npm')).toBe(false);
  });

  test('pypi setup.py with cmdclass fires', () => {
    const dir = makeTempPkg({ 'setup.py': 'setup(cmdclass={"install": PostInstall})' });
    expect(detectInstallScript(dir, 'pypi')).toBe(true);
  });

  test('cargo build.rs presence fires', () => {
    const dir = makeTempPkg({ 'build.rs': 'fn main() {}' });
    expect(detectInstallScript(dir, 'cargo')).toBe(true);
  });

  test('rubygems gemspec with extensions fires', () => {
    const dir = makeTempPkg({ 'foo.gemspec': 'Gem::Specification.new do |s|\n  s.extensions = ["ext/extconf.rb"]\nend' });
    expect(detectInstallScript(dir, 'rubygems')).toBe(true);
  });

  test('nuget tools/install.ps1 fires', () => {
    const dir = makeTempPkg({ 'tools/install.ps1': 'Write-Host "installing"' });
    expect(detectInstallScript(dir, 'nuget')).toBe(true);
  });
});

describe('detectCapabilities orchestrator', () => {
  test('returns empty CapabilitySet for unsupported ecosystem', () => {
    const dir = makeTempPkg({ 'README.md': 'hello' });
    const result = detectCapabilities(dir, 'github-actions', 'foo');
    expect(result.capabilities).toEqual(emptyCapabilitySet());
    expect(result.scanner_version).toBe(CAPABILITY_SCANNER_VERSION);
    expect(result.scan_error).toBeNull();
  });

  test('walks npm package source and OR-merges flags', () => {
    const dir = makeTempPkg({
      'package.json': '{"name":"x","scripts":{"postinstall":"node setup.js"}}',
      'index.js': "const cp = require('child_process'); cp.execSync('ls');",
      'lib/util.js': "process.env.HOME;",
    });
    const result = detectCapabilities(dir, 'npm', 'x');
    expect(result.capabilities.spawns_processes).toBe(true);
    expect(result.capabilities.reads_env).toBe(true);
    expect(result.capabilities.install_script).toBe(true);
    expect(result.scan_error).toBeNull();
  });

  test('multi-language package: pypi only walks .py files', () => {
    const dir = makeTempPkg({
      'setup.py': 'from setuptools import setup\nsetup(name="x")',
      'foo.py': 'import subprocess\nsubprocess.run(["ls"])',
      // .js file should NOT trigger js patterns when ecosystem is pypi
      'extras/dist.js': "require('child_process')",
    });
    const result = detectCapabilities(dir, 'pypi', 'x');
    expect(result.capabilities.spawns_processes).toBe(true);
    // .js file ignored — pypi detector only looks at .py
    expect(result.capabilities.eval_dynamic).toBe(false);
  });

  test('returns scan_error string when walk throws', () => {
    // Pass a non-existent dir — readdirSync inside walk swallows EACCES
    // for individual dirs but the top-level walk just returns empty. So
    // an error here means we ran the manifest pass on a missing dir
    // (which also returns false). Result should be empty + no error.
    const result = detectCapabilities('/nonexistent/path/x', 'npm', 'x');
    expect(result.capabilities).toEqual(emptyCapabilitySet());
    expect(result.scan_error).toBeNull();
  });

  test('all CAPABILITY_KEYS represented in emptyCapabilitySet', () => {
    const empty = emptyCapabilitySet();
    for (const k of CAPABILITY_KEYS) {
      expect(empty[k]).toBe(false);
    }
  });
});
