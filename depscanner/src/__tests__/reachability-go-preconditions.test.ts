/**
 * Go / net-http framework-mediated reachability model — the Go-module mirror of
 * the Java / PHP / Ruby feature-precondition + always-on-runtime gates, keyed on
 * the PRECISE subpackage import graph. Verdicts are grounded in the caddy 2.x
 * triage (48 dependency-CVEs, all at `module`).
 *
 * Covers:
 *   1. the pure decision functions with injected signals (no filesystem):
 *      - `evaluateGoAlwaysOnRuntimePromotion` (x/net/http2 server DoS → visible on
 *        a deployed HTTP server that imports http2; the html/idna siblings are
 *        excluded; a non-server / a repo that doesn't import http2 refuses),
 *      - `evaluateGoSubpackageDemotion` (x/crypto/ssh, x/net/html, x/net/idna →
 *        unreachable when the affected subpackage is provably not imported;
 *        blocked when it — or a descendant — IS imported; descendant blocks,
 *        ancestor does not; truncation / unrecognized refuse).
 *   2. end-to-end through `updateReachabilityLevels` with `ecosystem: 'golang'`,
 *      proving the Go server signal unblocks promotion with ZERO http-route
 *      entry points (a caddy-shaped module-routed server).
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { updateReachabilityLevels } from '../reachability';
import type { Storage } from '../storage';
import {
  evaluateGoAlwaysOnRuntimePromotion,
  evaluateGoSubpackageDemotion,
  gatherGoImportSignals,
  emptyGoImportSignals,
  type GoImportSignals,
} from '../reachability-go-preconditions';
import {
  emptyTransitiveImportIndex,
  type TransitiveImportIndex,
} from '../transitive-imports';

// ---------------------------------------------------------------------------
// Representative advisory summaries (real caddy CVE phrasings)
// ---------------------------------------------------------------------------

const HTTP2_RAPID_RESET = 'HTTP/2 rapid reset can cause excessive work in net/http';
const HTTP2_STREAM_CANCEL = 'HTTP/2 Stream Cancellation Attack';
const HTTP2_MEMORY_GROWTH = 'golang.org/x/net/http2 vulnerable to possible excessive memory growth';
const HTTP2_CONTINUATION = 'net/http, x/net/http2: close connections when receiving too many headers';
const HTTP2_MEMORY_UNBOUNDED = 'Unbounded memory growth in net/http and golang.org/x/net/http2';
const NET_HTML_TEXTNODE = 'Improper rendering of text nodes in golang.org/x/net/html';
const NET_HTML_XSS = 'golang.org/x/net vulnerable to Cross-site Scripting';
const NET_HTML_NONLINEAR = 'Non-linear parsing of case-insensitive content in golang.org/x/net/html';
const NET_IDNA_PUNYCODE = 'Invoking failure to reject ASCII-only Punycode-encoded labels in golang.org/x/net/idna';
const SSH_PANIC = 'x/crypto/ssh vulnerable to panic via malformed packets';
const SSH_TERRAPIN =
  'Prefix Truncation Attack against ChaCha20-Poly1305 and Encrypt-then-MAC aka Terrapin';
const SSH_PUBKEY_BYPASS =
  'Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto';
const SSH_AGENT_DOS = 'Potential denial of service in golang.org/x/crypto/ssh/agent';
const SSH_KNOWNHOSTS =
  'Invoking auth bypass via unenforced @revoked status in golang.org/x/crypto/ssh/knownhosts';
const CRYPTO_ACME = 'Vulnerability in golang.org/x/crypto/acme autocert cache directory';

/**
 * A recognized caddy-shaped Go project: a deployed HTTP/2 server (`package main`
 * that serves) importing x/net/http2 (+ h2c, httpguts) and only bcrypt/scrypt out
 * of x/crypto — NO ssh, acme, or x/net/html.
 */
function goSignals(over: Partial<GoImportSignals> = {}): GoImportSignals {
  return {
    ...emptyGoImportSignals(),
    recognized: true,
    truncated: false,
    isDeployedHttpServer: true,
    importedPackages: new Set([
      'golang.org/x/net/http2',
      'golang.org/x/net/http2/h2c',
      'golang.org/x/net/http/httpguts',
      'golang.org/x/crypto/bcrypt',
      'golang.org/x/crypto/scrypt',
    ]),
    ...over,
  };
}

// ---------------------------------------------------------------------------
// 1. Pure decision functions — PROMOTION (x/net/http2 always-on server stack)
// ---------------------------------------------------------------------------

describe('evaluateGoAlwaysOnRuntimePromotion', () => {
  const NET = 'golang.org/x/net';

  it('promotes an HTTP/2 rapid-reset DoS to function on a deployed server importing http2', () => {
    // Tier is function, not data_flow: the default inbound h2 parser is the Go
    // STDLIB bundle; the x/net module's copy is first-party wired (h2c opt-in /
    // upstream transport) but not unconditionally on the inbound path —
    // corrected by the caddy ground-truth verification (2026-07-02).
    const r = evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary: HTTP2_RAPID_RESET, signals: goSignals() });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('function');
    expect(r.sink).toBe('go-http2-server');
    expect(r.threatTag).toBe('requires_untrusted_request');
  });

  it('promotes the HTTP/2 stream-cancellation attack', () => {
    expect(evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary: HTTP2_STREAM_CANCEL, signals: goSignals() }).promote).toBe(true);
  });

  it('promotes the explicit x/net/http2 excessive-memory-growth CVE', () => {
    expect(evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary: HTTP2_MEMORY_GROWTH, signals: goSignals() }).promote).toBe(true);
  });

  it('promotes the CONTINUATION-flood (too many headers) CVE', () => {
    expect(evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary: HTTP2_CONTINUATION, signals: goSignals() }).promote).toBe(true);
  });

  it('promotes the net/http + x/net/http2 unbounded-memory CVE', () => {
    expect(evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary: HTTP2_MEMORY_UNBOUNDED, signals: goSignals() }).promote).toBe(true);
  });

  it('does NOT promote an x/net/html XSS when the server does not import x/net/html (caddy)', () => {
    // caddy-shape goSignals() imports http2 but NOT html → the html promotion's
    // requiredSubpackage gate refuses (and the demotion keeps it unreachable).
    expect(evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary: NET_HTML_XSS, signals: goSignals() }).promote).toBe(false);
  });

  it('does NOT promote an x/net/html text-node CVE when the server does not import x/net/html (caddy)', () => {
    expect(evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary: NET_HTML_TEXTNODE, signals: goSignals() }).promote).toBe(false);
  });

  // --- x/net/html PROMOTION on a server that DOES import x/net/html (gitea) ---
  it('PROMOTES x/net/html parser CVEs to data_flow when the server imports x/net/html (gitea markdown pipeline)', () => {
    const gitea = goSignals({
      importedPackages: new Set(['golang.org/x/net/html', 'golang.org/x/net/html/atom', 'golang.org/x/crypto/ssh']),
    });
    const htmlSummaries = [
      'Improper rendering of text nodes in golang.org/x/net/html',
      'golang.org/x/net vulnerable to Cross-site Scripting',
      'Infinite parsing loop in golang.org/x/net',
      'Go Net HTML parser is vulnerable to denial of service',
      'Invoking incorrect handling of character references in DOCTYPE nodes in golang.org/x/net/html',
      'Invoking duplicate attributes can cause XSS in golang.org/x/net/html',
      'Invoking incorrect handling of HTML elements in foreign content in golang.org/x/net/html',
      'Invoking incorrect handling of namespaced elements in foreign content in golang.org/x/net/html',
    ];
    for (const summary of htmlSummaries) {
      const r = evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary, signals: gitea });
      expect(r.promote).toBe(true);
      expect(r.promoteTo).toBe('data_flow');
      expect(r.sink).toBe('go-net-html-parser');
      expect(r.threatTag).toBe('requires_untrusted_html');
    }
  });

  it('does NOT let the html promotion catch an http2 CVE on a gitea-shape server (exclude guard)', () => {
    const gitea = goSignals({ importedPackages: new Set(['golang.org/x/net/html']) });
    // gitea imports html but NOT http2 → the http2 row refuses (no http2 import)
    // and the html row's exclude vetoes the http2 summary → no promotion.
    expect(evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary: HTTP2_RAPID_RESET, signals: gitea }).promote).toBe(false);
  });

  it('refuses the html promotion when the server does not serve HTTP (imports html but not a server)', () => {
    const nonServer = goSignals({ isDeployedHttpServer: false, importedPackages: new Set(['golang.org/x/net/html']) });
    expect(evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary: NET_HTML_XSS, signals: nonServer }).promote).toBe(false);
  });

  // --- x/text/language Accept-Language ReDoS on a server that imports it (gitea) ---
  it('PROMOTES the x/text Accept-Language ReDoS to data_flow when the server imports x/text/language (gitea locale middleware)', () => {
    const gitea = goSignals({ importedPackages: new Set(['golang.org/x/text/language']) });
    const r = evaluateGoAlwaysOnRuntimePromotion({
      depName: 'golang.org/x/text',
      summary: 'golang.org/x/text/language Denial of service via crafted Accept-Language header',
      signals: gitea,
    });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('data_flow');
    expect(r.sink).toBe('go-text-accept-language');
  });

  it('does NOT promote the x/text Accept-Language CVE when the server does not import x/text/language (caddy)', () => {
    // caddy-shape goSignals() does not import x/text/language → the CVE is
    // demoted-unreachable by the import heuristic and the promotion refuses.
    const r = evaluateGoAlwaysOnRuntimePromotion({
      depName: 'golang.org/x/text',
      summary: 'golang.org/x/text/language Denial of service via crafted Accept-Language header',
      signals: goSignals(),
    });
    expect(r.promote).toBe(false);
  });

  it('refuses to promote when the project is not a deployed HTTP server', () => {
    const r = evaluateGoAlwaysOnRuntimePromotion({
      depName: NET,
      summary: HTTP2_RAPID_RESET,
      signals: goSignals({ isDeployedHttpServer: false }),
    });
    expect(r.promote).toBe(false);
  });

  it('refuses to promote when the repo does not import http2 (client that never serves h2)', () => {
    const r = evaluateGoAlwaysOnRuntimePromotion({
      depName: NET,
      summary: HTTP2_RAPID_RESET,
      signals: goSignals({ importedPackages: new Set(['golang.org/x/net/proxy']) }),
    });
    expect(r.promote).toBe(false);
  });

  it('refuses to promote a non-http2 module (x/crypto)', () => {
    expect(evaluateGoAlwaysOnRuntimePromotion({ depName: 'golang.org/x/crypto', summary: SSH_PANIC, signals: goSignals() }).promote).toBe(false);
  });

  it('refuses on null summary / unrecognized signals', () => {
    expect(evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary: null, signals: goSignals() }).promote).toBe(false);
    expect(evaluateGoAlwaysOnRuntimePromotion({ depName: NET, summary: HTTP2_RAPID_RESET, signals: emptyGoImportSignals() }).promote).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. Pure decision functions — DEMOTION (subpackage provably not imported)
// ---------------------------------------------------------------------------

describe('evaluateGoSubpackageDemotion', () => {
  const CRYPTO = 'golang.org/x/crypto';
  const NET = 'golang.org/x/net';

  it('demotes an x/crypto/ssh CVE when the server imports no ssh subpackage', () => {
    const r = evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: SSH_PANIC, signals: goSignals() });
    expect(r.demote).toBe(true);
    expect(r.subpackage).toBe('golang.org/x/crypto/ssh');
  });

  it('demotes the Terrapin SSH transport attack (no literal "ssh" in the summary)', () => {
    const r = evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: SSH_TERRAPIN, signals: goSignals() });
    expect(r.demote).toBe(true);
    expect(r.subpackage).toBe('golang.org/x/crypto/ssh');
  });

  it('demotes the PublicKeyCallback / ServerConfig ssh CVE', () => {
    expect(evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: SSH_PUBKEY_BYPASS, signals: goSignals() }).demote).toBe(true);
  });

  it('demotes an x/crypto/ssh/agent CVE to the agent subpackage', () => {
    const r = evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: SSH_AGENT_DOS, signals: goSignals() });
    expect(r.demote).toBe(true);
    expect(r.subpackage).toBe('golang.org/x/crypto/ssh/agent');
  });

  it('demotes an x/crypto/ssh/knownhosts CVE to the knownhosts subpackage', () => {
    const r = evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: SSH_KNOWNHOSTS, signals: goSignals() });
    expect(r.demote).toBe(true);
    expect(r.subpackage).toBe('golang.org/x/crypto/ssh/knownhosts');
  });

  it('demotes an x/crypto/acme CVE when acme is not imported', () => {
    const r = evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: CRYPTO_ACME, signals: goSignals() });
    expect(r.demote).toBe(true);
    expect(r.subpackage).toBe('golang.org/x/crypto/acme');
  });

  it('demotes an x/net/html text-node CVE when html is not imported', () => {
    const r = evaluateGoSubpackageDemotion({ depName: NET, summary: NET_HTML_TEXTNODE, signals: goSignals() });
    expect(r.demote).toBe(true);
    expect(r.subpackage).toBe('golang.org/x/net/html');
  });

  it('demotes the x/net Cross-site-Scripting CVE to the html subpackage', () => {
    expect(evaluateGoSubpackageDemotion({ depName: NET, summary: NET_HTML_XSS, signals: goSignals() }).demote).toBe(true);
  });

  it('does NOT demote an x/net/idna Punycode CVE (idna gate removed — compiled transitively via certmagic-class chains)', () => {
    // Ground-truth verification proved first-party import absence is unsound
    // for idna: go-mod-why traces gitea→certmagic→x/net/idna, and caddy's h2
    // transport executes idna.ToASCII. Restore only with Arc-2 transitive proof.
    const r = evaluateGoSubpackageDemotion({ depName: NET, summary: NET_IDNA_PUNYCODE, signals: goSignals() });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote an x/net/http2 CVE (not in the demotion gate — it is the promotion path)', () => {
    expect(evaluateGoSubpackageDemotion({ depName: NET, summary: HTTP2_RAPID_RESET, signals: goSignals() }).demote).toBe(false);
  });

  it('does NOT demote an ssh CVE when the repo DOES import ssh', () => {
    const withSsh = goSignals({
      importedPackages: new Set(['golang.org/x/crypto/ssh', 'golang.org/x/crypto/bcrypt']),
    });
    expect(evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: SSH_PANIC, signals: withSsh }).demote).toBe(false);
  });

  it('a DESCENDANT import blocks a parent-package demotion (imports ssh/agent → do not demote an ssh CVE)', () => {
    const withAgent = goSignals({
      importedPackages: new Set(['golang.org/x/crypto/ssh/agent']),
    });
    expect(evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: SSH_PANIC, signals: withAgent }).demote).toBe(false);
  });

  it('an ANCESTOR import does NOT block a child-package demotion (imports ssh → still demote an ssh/agent CVE)', () => {
    const withSshOnly = goSignals({
      importedPackages: new Set(['golang.org/x/crypto/ssh']),
    });
    const r = evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: SSH_AGENT_DOS, signals: withSshOnly });
    expect(r.demote).toBe(true);
    expect(r.subpackage).toBe('golang.org/x/crypto/ssh/agent');
  });

  it('refuses to demote when the import scan was truncated (absence unprovable)', () => {
    expect(evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: SSH_PANIC, signals: goSignals({ truncated: true }) }).demote).toBe(false);
  });

  it('refuses to demote on unrecognized signals / null summary / a module with no gate', () => {
    expect(evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: SSH_PANIC, signals: emptyGoImportSignals() }).demote).toBe(false);
    expect(evaluateGoSubpackageDemotion({ depName: CRYPTO, summary: null, signals: goSignals() }).demote).toBe(false);
    expect(evaluateGoSubpackageDemotion({ depName: 'github.com/go-chi/chi', summary: 'chi has a bug', signals: goSignals() }).demote).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2b. gatherGoImportSignals — filesystem import extraction (regression)
// ---------------------------------------------------------------------------

describe('gatherGoImportSignals — import extraction', () => {
  function withGoWorkspace(mainGo: string, fn: (root: string) => void): void {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'go-precond-'));
    try {
      fs.writeFileSync(path.join(dir, 'go.mod'), 'module example.com/app\n');
      fs.writeFileSync(path.join(dir, 'main.go'), mainGo);
      fn(dir);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
  const has = (s: GoImportSignals, p: string) =>
    [...s.importedPackages].some((x) => x === p || x.startsWith(p + '/'));

  it('captures imports after a comment containing ")" inside the import block (gitea openpgp regression)', () => {
    // A ")" in a comment must NOT prematurely close the factored import block —
    // gitea's GPG file has `// OpenPGP (RFC 4880)` above the openpgp import; the
    // un-stripped non-greedy block match dropped every import after it, so the
    // openpgp CVE looked un-imported and got wrongly demoted to unreachable.
    const src =
      'package main\n' +
      'import (\n' +
      '\t"fmt"\n' +
      '\t// OpenPGP (RFC 4880) armored signatures support\n' +
      '\t"golang.org/x/crypto/openpgp"\n' +
      '\t"golang.org/x/crypto/openpgp/armor" /* block (paren) comment */\n' +
      '\t"golang.org/x/crypto/ssh"\n' +
      ')\n' +
      'func main() { fmt.Println("http://x") }\n';
    withGoWorkspace(src, (root) => {
      const s = gatherGoImportSignals(root);
      expect(s.recognized).toBe(true);
      expect(s.truncated).toBe(false);
      expect(has(s, 'golang.org/x/crypto/openpgp')).toBe(true);
      expect(has(s, 'golang.org/x/crypto/openpgp/armor')).toBe(true);
      expect(has(s, 'golang.org/x/crypto/ssh')).toBe(true);
    });
  });

  it('detects a deployed HTTP server (package main + serves) and captures single-line imports', () => {
    const src =
      'package main\n' +
      'import "golang.org/x/net/http2"\n' +
      'import "net/http"\n' +
      'func main() { http.ListenAndServe(":8080", nil) }\n';
    withGoWorkspace(src, (root) => {
      const s = gatherGoImportSignals(root);
      expect(s.isDeployedHttpServer).toBe(true);
      expect(has(s, 'golang.org/x/net/http2')).toBe(true);
    });
  });

  it('returns unrecognized signals for a non-Go workspace (no go.mod)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nongo-'));
    try {
      fs.writeFileSync(path.join(dir, 'main.go'), 'package main\nimport "golang.org/x/net/http2"\n');
      const s = gatherGoImportSignals(dir);
      expect(s.recognized).toBe(false);
      expect(s.importedPackages.size).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// 3. End-to-end through updateReachabilityLevels (ecosystem: 'golang')
// ---------------------------------------------------------------------------

interface TableState { rows: any[] }

class FakeStorage {
  tables: Record<string, TableState> = {};
  updates: Array<{ table: string; filter: Record<string, unknown>; values: any }> = [];

  set(table: string, rows: any[]) {
    this.tables[table] = { rows };
  }

  from(table: string): any {
    const state = this.tables[table] ?? { rows: [] };
    const filters: Array<{ col: string; val: unknown }> = [];
    const filterRows = () => {
      let rows = state.rows;
      for (const f of filters) rows = rows.filter((r) => r[f.col] === f.val);
      return rows;
    };
    const builder: any = {
      select() { return builder; },
      eq(col: string, val: unknown) { filters.push({ col, val }); return builder; },
      in() { return builder; },
      maybeSingle() { return Promise.resolve({ data: filterRows()[0] ?? null, error: null }); },
      single() {
        const rows = filterRows();
        return Promise.resolve({
          data: rows[0] ?? null,
          error: rows.length === 0 ? { code: 'PGRST116', message: 'not found' } : null,
        });
      },
      insert: () => Promise.resolve({ data: null, error: null }),
      upsert: (rows: any) => {
        const arr = Array.isArray(rows) ? rows : [rows];
        for (const r of arr) this.updates.push({ table, filter: { id: r.id }, values: r });
        return Promise.resolve({ data: null, error: null });
      },
      then(onFulfilled: any) {
        return Promise.resolve({ data: filterRows(), error: null }).then(onFulfilled);
      },
    };
    return builder;
  }
}

const log = {
  info: jest.fn().mockResolvedValue(undefined),
  success: jest.fn().mockResolvedValue(undefined),
  warn: jest.fn().mockResolvedValue(undefined),
  error: jest.fn().mockResolvedValue(undefined),
};

const PROJECT_ID = 'proj-1';
const RUN_ID = 'run-1';

/** Seed one direct Go module dep (namespace null, full module path) that lands at `module`. */
function seedGoDep(
  fsk: FakeStorage,
  opts: { name: string; osvId: string; summary: string },
) {
  fsk.set('project_dependency_findings', [
    {
      id: 'pdv-1',
      project_dependency_id: 'pd-1',
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      osv_id: opts.osvId,
      aliases: [],
      summary: opts.summary,
    },
  ]);
  fsk.set('project_dependencies', [
    {
      id: 'pd-1',
      project_id: PROJECT_ID,
      last_seen_extraction_run_id: RUN_ID,
      dependency_id: 'dep-1',
      dependency_version_id: 'dv-1',
      is_direct: true,
      files_importing_count: 4,
      environment: 'prod',
      name: opts.name,
      namespace: null,
    },
  ]);
  fsk.set('project_reachable_flows', []);
  fsk.set('project_reachable_flow_suppressions', []);
  fsk.set('dependency_version_edges', []);
  // Generic first-party usage slice sharing no token with a Go module path, so the
  // function-tier name-match heuristic never fires and the dep floors at `module`
  // via the direct/imported branch, exactly as a real Go scan does.
  fsk.set('project_usage_slices', [
    {
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      file_path: 'server/handler.go',
      line_number: 1,
      target_name: 'app.server.serve',
      target_type: 'app.server.serve',
      resolved_method: 'app.server.serve',
    },
  ]);
}

function verdictOf(fsk: FakeStorage, pdvId: string): { level?: string; details?: any } {
  const u = fsk.updates.find(
    (x) => x.table === 'project_dependency_findings' && x.filter.id === pdvId && 'reachability_level' in x.values,
  );
  return { level: u?.values.reachability_level, details: u?.values.reachability_details };
}

// The caddy-shaped signal set, injected directly (no filesystem walk).
const caddySignals = (): GoImportSignals => goSignals();

async function runGo(fsk: FakeStorage, signals: GoImportSignals) {
  await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
    ecosystem: 'golang',
    workspaceRoot: '/nonexistent',
    goImportSignals: signals,
    // A caddy-shaped server routes via its own module system — ZERO http-route
    // entry points. The Go server signal (carried in goImportSignals) is what
    // unblocks promotion.
    httpEntryPointCount: 0,
  });
}

beforeEach(() => jest.clearAllMocks());

describe('updateReachabilityLevels — Go framework-mediated model', () => {
  it('PROMOTES an x/net/http2 rapid-reset DoS to function on a module-routed server (0 http-route entry points)', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: 'golang.org/x/net', osvId: 'CVE-2023-39325', summary: HTTP2_RAPID_RESET });
    await runGo(fsk, caddySignals());
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('function');
    expect(details?.verdict).toBe('always_on_framework_runtime');
    expect(details?.sink).toBe('go-http2-server');
  });

  it('DEMOTES an x/crypto/ssh CVE to unreachable on a server that imports no ssh', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: 'golang.org/x/crypto', osvId: 'CVE-2021-43565', summary: SSH_PANIC });
    await runGo(fsk, caddySignals());
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('go_subpackage_not_imported');
    expect(details?.feature).toBe('golang.org/x/crypto/ssh');
  });

  it('DEMOTES an x/net/html parser CVE to unreachable on a server that parses no HTML', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: 'golang.org/x/net', osvId: 'CVE-2024-45338', summary: NET_HTML_NONLINEAR });
    await runGo(fsk, caddySignals());
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.feature).toBe('golang.org/x/net/html');
  });

  it('LEAVES a module with no subpackage gate (go-chi/chi) at module', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: 'github.com/go-chi/chi', osvId: 'CVE-2025-69725', summary: 'go-chi/chi has a host-routing bypass' });
    await runGo(fsk, caddySignals());
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });

  it('does NOT promote http2 when the project is not a deployed server (stays module)', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: 'golang.org/x/net', osvId: 'CVE-2023-39325', summary: HTTP2_RAPID_RESET });
    await runGo(fsk, caddySignals().isDeployedHttpServer ? goSignals({ isDeployedHttpServer: false }) : caddySignals());
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });

  it('still DEMOTES an ssh CVE on a non-server (demotion is server-independent)', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: 'golang.org/x/crypto', osvId: 'CVE-2021-43565', summary: SSH_PANIC });
    await runGo(fsk, goSignals({ isDeployedHttpServer: false }));
    expect(verdictOf(fsk, 'pdv-1').level).toBe('unreachable');
  });

  it('refuses to demote (stays module) when the import scan was truncated', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: 'golang.org/x/crypto', osvId: 'CVE-2021-43565', summary: SSH_PANIC });
    await runGo(fsk, goSignals({ truncated: true }));
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });
});

// ---------------------------------------------------------------------------
// Arc 2 — transitive compile-set proofs (dependency-source import graphs)
// ---------------------------------------------------------------------------

describe('evaluateGoSubpackageDemotion — Arc 2 transitive compile-set proofs', () => {
  const NET = 'golang.org/x/net';
  const PROTOBUF = 'google.golang.org/protobuf';
  const PROTOJSON_LOOP =
    'Infinite loop in protojson.Unmarshal when unmarshaling certain forms of invalid JSON in google.golang.org/protobuf';
  // A core-protobuf CVE whose summary mentions JSON generically but never names
  // the protojson subpackage — must NOT ride the protojson rule (pattern criterion).
  const CORE_PROTO_JSON_MENTION =
    'proto.Unmarshal in google.golang.org/protobuf mishandles certain messages, unlike JSON unmarshaling';

  it('idna (requiresTransitiveProof): refuses with no transitive data — first-party absence alone is known-unsound', () => {
    const r = evaluateGoSubpackageDemotion({
      depName: NET,
      summary: NET_IDNA_PUNYCODE,
      signals: goSignals(),
    });
    expect(r.demote).toBe(false);
  });

  it('idna: demotes on a COMPLETE compile set that lacks idna, stamped prod_path', () => {
    const r = evaluateGoSubpackageDemotion({
      depName: NET,
      summary: NET_IDNA_PUNYCODE,
      signals: goSignals({
        transitiveComplete: true,
        transitiveImportedPackages: new Set(['golang.org/x/net/http2', 'github.com/some/dep']),
      }),
    });
    expect(r.demote).toBe(true);
    expect(r.subpackage).toBe('golang.org/x/net/idna');
    expect(r.proofStandard).toBe('prod_path');
  });

  it('idna: refuses when the compile set CONTAINS idna (the gitea→certmagic / caddy-h2 shape)', () => {
    const r = evaluateGoSubpackageDemotion({
      depName: NET,
      summary: NET_IDNA_PUNYCODE,
      signals: goSignals({
        transitiveComplete: true,
        transitiveImportedPackages: new Set(['golang.org/x/net/idna']),
      }),
    });
    expect(r.demote).toBe(false);
  });

  it('idna: an INCOMPLETE compile set never proves absence, but its positive hit still vetoes', () => {
    // absence on incomplete → refuse
    expect(
      evaluateGoSubpackageDemotion({
        depName: NET,
        summary: NET_IDNA_PUNYCODE,
        signals: goSignals({
          transitiveComplete: false,
          transitiveImportedPackages: new Set(['github.com/some/dep']),
        }),
      }).demote,
    ).toBe(false);
    // positive on incomplete → also refuse (veto path)
    expect(
      evaluateGoSubpackageDemotion({
        depName: NET,
        summary: NET_IDNA_PUNYCODE,
        signals: goSignals({
          transitiveComplete: false,
          transitiveImportedPackages: new Set(['golang.org/x/net/idna']),
        }),
      }).demote,
    ).toBe(false);
  });

  it('idna: a first-party idna import refuses regardless of the oracle', () => {
    const r = evaluateGoSubpackageDemotion({
      depName: NET,
      summary: NET_IDNA_PUNYCODE,
      signals: goSignals({
        importedPackages: new Set(['golang.org/x/net/idna']),
        transitiveComplete: true,
        transitiveImportedPackages: new Set<string>(),
      }),
    });
    expect(r.demote).toBe(false);
  });

  it('protojson: two-directional — demotes on the gitea shape, refuses on the caddy (cel-go) shape', () => {
    const gitea = evaluateGoSubpackageDemotion({
      depName: PROTOBUF,
      summary: PROTOJSON_LOOP,
      signals: goSignals({
        transitiveComplete: true,
        transitiveImportedPackages: new Set(['google.golang.org/protobuf/proto']),
      }),
    });
    expect(gitea.demote).toBe(true);
    expect(gitea.subpackage).toBe('google.golang.org/protobuf/encoding/protojson');
    expect(gitea.proofStandard).toBe('prod_path');

    const caddy = evaluateGoSubpackageDemotion({
      depName: PROTOBUF,
      summary: PROTOJSON_LOOP,
      signals: goSignals({
        transitiveComplete: true,
        transitiveImportedPackages: new Set([
          'google.golang.org/protobuf/proto',
          'google.golang.org/protobuf/encoding/protojson',
        ]),
      }),
    });
    expect(caddy.demote).toBe(false);
  });

  it('protojson: a core-protobuf CVE that only mentions JSON generically never matches the rule', () => {
    const r = evaluateGoSubpackageDemotion({
      depName: PROTOBUF,
      summary: CORE_PROTO_JSON_MENTION,
      signals: goSignals({
        transitiveComplete: true,
        transitiveImportedPackages: new Set<string>(),
      }),
    });
    expect(r.demote).toBe(false);
  });

  it('legacy rule (x/net/html): first_party demotion is UNAFFECTED by the compile set — compiled-but-dormant is the normal Go case', () => {
    // caddy compiles smallstep's ssh wrappers + x/net/html via its PKI chain
    // yet never drives them; the labels bless unreachable. A blanket
    // compiled-in veto reversed 35 labelled-correct demotions in validation.
    const without = evaluateGoSubpackageDemotion({
      depName: NET,
      summary: NET_HTML_TEXTNODE,
      signals: goSignals(),
    });
    expect(without.demote).toBe(true);
    expect(without.proofStandard).toBe('first_party');

    const withCompiledIn = evaluateGoSubpackageDemotion({
      depName: NET,
      summary: NET_HTML_TEXTNODE,
      signals: goSignals({
        transitiveComplete: true,
        transitiveImportedPackages: new Set(['golang.org/x/net/html']),
      }),
    });
    expect(withCompiledIn.demote).toBe(true);
    expect(withCompiledIn.proofStandard).toBe('first_party');
  });

  it('a descendant in the compile set counts as compiled (belt-and-suspenders refusal)', () => {
    const r = evaluateGoSubpackageDemotion({
      depName: NET,
      summary: NET_IDNA_PUNYCODE,
      signals: goSignals({
        transitiveComplete: true,
        transitiveImportedPackages: new Set(['golang.org/x/net/idna/internal']),
      }),
    });
    expect(r.demote).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Arc 2 e2e — options.transitiveImports merge through updateReachabilityLevels
// ---------------------------------------------------------------------------

describe('updateReachabilityLevels — Arc 2 transitive compile-set wiring', () => {
  const PROTOBUF_MOD = 'google.golang.org/protobuf';
  const PROTOJSON_SUMMARY =
    'Infinite loop in protojson.Unmarshal when unmarshaling certain forms of invalid JSON in google.golang.org/protobuf';

  function goIdx(
    modules: string[],
    status: TransitiveImportIndex['status'] = 'complete',
  ): TransitiveImportIndex {
    const idx = emptyTransitiveImportIndex('golang');
    idx.status = status;
    idx.perPackage.set('__modules__', { modules: new Set(modules), tokenHits: new Set() });
    idx.extractedPackages.add('__modules__');
    return idx;
  }

  async function runGoIdx(fsk: FakeStorage, signals: GoImportSignals, idx?: TransitiveImportIndex) {
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'golang',
      workspaceRoot: '/nonexistent',
      goImportSignals: signals,
      transitiveImports: idx,
      httpEntryPointCount: 0,
    });
  }

  it('gitea shape: protojson absent from a COMPLETE compile set → module→unreachable, prod_path verdict', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: PROTOBUF_MOD, osvId: 'CVE-2024-24786', summary: PROTOJSON_SUMMARY });
    await runGoIdx(fsk, caddySignals(), goIdx(['google.golang.org/protobuf/proto', 'github.com/some/dep']));
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('go_subpackage_not_on_prod_path');
    expect(details?.feature).toBe('google.golang.org/protobuf/encoding/protojson');
    expect(String(details?.reason)).toContain('production dependency path');
  });

  it('caddy shape: protojson IN the compile set (cel-go) → stays module', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: PROTOBUF_MOD, osvId: 'CVE-2024-24786', summary: PROTOJSON_SUMMARY });
    await runGoIdx(
      fsk,
      caddySignals(),
      goIdx(['google.golang.org/protobuf/proto', 'google.golang.org/protobuf/encoding/protojson']),
    );
    const { level } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
  });

  it('no index: the requiresTransitiveProof rule refuses; a legacy rule still demotes with the byte-stable verdict', async () => {
    // protojson without any oracle → stays module
    const fsk1 = new FakeStorage();
    seedGoDep(fsk1, { name: PROTOBUF_MOD, osvId: 'CVE-2024-24786', summary: PROTOJSON_SUMMARY });
    await runGoIdx(fsk1, caddySignals(), undefined);
    expect(verdictOf(fsk1, 'pdv-1').level).toBe('module');

    // legacy x/net/html first-party demotion is unchanged
    const fsk2 = new FakeStorage();
    seedGoDep(fsk2, { name: 'golang.org/x/net', osvId: 'GHSA-x-html', summary: NET_HTML_TEXTNODE });
    await runGoIdx(fsk2, caddySignals(), undefined);
    const { level, details } = verdictOf(fsk2, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('go_subpackage_not_imported');
  });

  it('an UNAVAILABLE index is not merged — behaves exactly like no index', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: PROTOBUF_MOD, osvId: 'CVE-2024-24786', summary: PROTOJSON_SUMMARY });
    await runGoIdx(fsk, caddySignals(), goIdx([], 'unavailable'));
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });

  it('merge rule: injected pre-merged signals WIN over options.transitiveImports', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: PROTOBUF_MOD, osvId: 'CVE-2024-24786', summary: PROTOJSON_SUMMARY });
    // The injected signals already carry a compile set CONTAINING protojson —
    // the options index (absent, complete) must NOT clobber them.
    const injected = goSignals({
      transitiveImportedPackages: new Set(['google.golang.org/protobuf/encoding/protojson']),
      transitiveComplete: true,
    });
    await runGoIdx(fsk, injected, goIdx(['github.com/some/dep']));
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });

  it('records the oracle status in silence_events classifier_inputs', async () => {
    const fsk = new FakeStorage();
    seedGoDep(fsk, { name: PROTOBUF_MOD, osvId: 'CVE-2024-24786', summary: PROTOJSON_SUMMARY });
    await runGoIdx(fsk, caddySignals(), goIdx(['github.com/some/dep']));
    const se = fsk.updates.find((x) => x.table === 'silence_events');
    expect(se).toBeTruthy();
    expect(se!.values.classifier_inputs.transitive_import_status).toBe('complete');
    expect(se!.values.classifier_inputs.transitive_extracted_count).toBe(1);
    expect(se!.values.classifier_inputs.transitive_failed_count).toBe(0);
  });
});
