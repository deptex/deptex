/**
 * PHP / Symfony framework-mediated reachability model — the composer mirror of
 * the Java feature-precondition + always-on-runtime gates.
 *
 * Covers:
 *   1. the pure decision functions with injected signals (no filesystem):
 *      - `evaluateSymfonyAlwaysOnRuntimePromotion` (http-foundation request
 *        parser → data_flow; firewall login → function; fail-safes),
 *      - `evaluateSymfonyFeaturePreconditionDemotion` (twig sandbox, untrusted
 *        yaml, x509, unanimous → unreachable when absent; blocked when present),
 *      - `evaluateComposerDevOnlyDemotion` (composer.lock packages-dev;
 *        framework-independent — fires on Laravel / plain-PHP, not only Symfony).
 *   2. end-to-end through `updateReachabilityLevels` with `ecosystem: 'composer'`
 *      + injected `symfonyFeatureSignals`:
 *      - PROMOTE http-foundation authz-bypass module → data_flow on a web app,
 *      - DEV-ONLY DEMOTE symfony/process module → unreachable,
 *      - FEATURE DEMOTE a twig-sandbox CVE module → unreachable,
 *      - DEMOTE regardless of entry points; PROMOTE gated on the web-app signal.
 */

import { updateReachabilityLevels } from '../reachability';
import type { Storage } from '../storage';
import {
  evaluateSymfonyAlwaysOnRuntimePromotion,
  evaluateSymfonyFeaturePreconditionDemotion,
  evaluateComposerDevOnlyDemotion,
  emptySymfonyFeatureSignals,
  type SymfonyFeatureSignals,
} from '../reachability-symfony-preconditions';

// ---------------------------------------------------------------------------
// Representative advisory summaries (real CVE phrasings from symfony/demo)
// ---------------------------------------------------------------------------

const HTTP_FOUNDATION_AUTHZ_BYPASS =
  'Symfony HttpFoundation mishandled PATH_INFO parsing, allowing an authorization bypass on protected routes.';
const FIREWALL_SESSION_FIXATION =
  'Symfony Security incorrectly regenerated the CSRF token on login, enabling a session fixation attack.';
const FIREWALL_USER_ENUMERATION =
  'Symfony Security allowed user enumeration through the form login authenticator.';
const TWIG_SANDBOX_BYPASS =
  'Twig sandbox mode could be bypassed via the object __toString method, allowing SSTI.';
const YAML_BILLION_LAUGHS =
  'Symfony Yaml parser was vulnerable to uncontrolled resource consumption (Billion Laughs) on nested anchors.';
const X509_SPOOFING =
  'Symfony Security X509Authenticator trusted a spoofable client certificate DN.';
const UNANIMOUS_STRATEGY =
  'Symfony Security access decision manager mis-evaluated the unanimous voting strategy.';
const PROCESS_WINDOWS_HIJACK =
  'Symfony Process could execute a hijacked binary on Windows due to argument escaping.';

/**
 * A recognized symfony/demo-shaped project: firewall + form_login + access_control
 * configured, NO sandbox / untrusted-yaml / x509 / unanimous / HttpCache. Dev-only
 * tree: symfony/process + symfony/dom-crawler.
 */
function demoSignals(over: Partial<SymfonyFeatureSignals> = {}): SymfonyFeatureSignals {
  return {
    ...emptySymfonyFeatureSignals(),
    recognized: true,
    lockParsed: true,
    lockProd: new Set([
      'symfony/framework-bundle',
      'symfony/http-foundation',
      'symfony/security-bundle',
      'symfony/security-core',
      'symfony/security-http',
      'symfony/yaml',
      'symfony/cache',
      'twig/twig',
    ]),
    lockDev: new Set([
      'symfony/process',
      'symfony/dom-crawler',
      'friendsofphp/php-cs-fixer',
    ]),
    securityYamlText:
      'security:\n  firewalls:\n    main:\n      form_login:\n        csrf_token_generator: security.csrf.token_manager\n  access_control:\n    - { path: ^/admin, roles: role_admin }\n',
    configText: 'framework:\n  secret: x\n',
    codeText:
      "namespace app\\controller;\nclass blogcontroller { public function index() { return $this->render('blog/index.html.twig'); } }\n",
    ...over,
  };
}

// ---------------------------------------------------------------------------
// 1. Pure decision functions
// ---------------------------------------------------------------------------

describe('evaluateSymfonyAlwaysOnRuntimePromotion', () => {
  it('promotes an http-foundation authorization-bypass CVE to data_flow on a web app', () => {
    const r = evaluateSymfonyAlwaysOnRuntimePromotion({
      depName: 'http-foundation',
      summary: HTTP_FOUNDATION_AUTHZ_BYPASS,
      hasHttpRouteEntryPoint: true,
      signals: demoSignals(),
    });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('data_flow');
    expect(r.sink).toBe('symfony-http-foundation-request-parser');
    expect(r.threatTag).toBe('requires_protected_route');
  });

  it('promotes a firewall session-fixation CVE to function when a firewall + form_login is configured', () => {
    const r = evaluateSymfonyAlwaysOnRuntimePromotion({
      depName: 'security-bundle',
      summary: FIREWALL_SESSION_FIXATION,
      hasHttpRouteEntryPoint: true,
      signals: demoSignals(),
    });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('function');
    expect(r.sink).toBe('symfony-security-firewall-login');
  });

  it('promotes a firewall user-enumeration CVE (security-core owner) to function', () => {
    const r = evaluateSymfonyAlwaysOnRuntimePromotion({
      depName: 'security-core',
      summary: FIREWALL_USER_ENUMERATION,
      hasHttpRouteEntryPoint: true,
      signals: demoSignals(),
    });
    expect(r.promote).toBe(true);
    expect(r.sink).toBe('symfony-security-firewall-login');
  });

  // --- fail-safes ---
  it('does NOT promote the firewall CVE when NO firewall is configured (requires() false)', () => {
    const r = evaluateSymfonyAlwaysOnRuntimePromotion({
      depName: 'security-bundle',
      summary: FIREWALL_SESSION_FIXATION,
      hasHttpRouteEntryPoint: true,
      signals: demoSignals({ securityYamlText: '' }),
    });
    expect(r.promote).toBe(false);
  });

  it('does NOT promote without an HTTP-route entry point (library / CLI repo)', () => {
    const r = evaluateSymfonyAlwaysOnRuntimePromotion({
      depName: 'http-foundation',
      summary: HTTP_FOUNDATION_AUTHZ_BYPASS,
      hasHttpRouteEntryPoint: false,
      signals: demoSignals(),
    });
    expect(r.promote).toBe(false);
  });

  it('does NOT promote on an owner mismatch (twig with a request-parser summary)', () => {
    const r = evaluateSymfonyAlwaysOnRuntimePromotion({
      depName: 'twig',
      summary: HTTP_FOUNDATION_AUTHZ_BYPASS,
      hasHttpRouteEntryPoint: true,
      signals: demoSignals(),
    });
    expect(r.promote).toBe(false);
  });

  it('does NOT promote an x509 CVE (summary names no always-on class)', () => {
    const r = evaluateSymfonyAlwaysOnRuntimePromotion({
      depName: 'security-http',
      summary: X509_SPOOFING,
      hasHttpRouteEntryPoint: true,
      signals: demoSignals(),
    });
    expect(r.promote).toBe(false);
  });
});

describe('evaluateSymfonyFeaturePreconditionDemotion', () => {
  it('demotes a twig-sandbox CVE to unreachable when the sandbox is absent', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'twig',
      summary: TWIG_SANDBOX_BYPASS,
      signals: demoSignals(),
    });
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('twig-sandbox');
  });

  it('does NOT demote a twig-sandbox CVE when the sandbox IS enabled', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'twig',
      summary: TWIG_SANDBOX_BYPASS,
      signals: demoSignals({ codeText: 'new \\twig\\extension\\sandboxextension(new securitypolicy())' }),
    });
    expect(r.demote).toBe(false);
  });

  it('demotes a yaml Billion-Laughs CVE when no untrusted YAML parse exists in first-party code', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'yaml',
      summary: YAML_BILLION_LAUGHS,
      signals: demoSignals(),
    });
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('symfony-yaml-untrusted-parse');
  });

  it('does NOT demote the yaml CVE when the app parses untrusted YAML', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'yaml',
      summary: YAML_BILLION_LAUGHS,
      signals: demoSignals({ codeText: '$data = yaml::parse($request->getcontent());' }),
    });
    expect(r.demote).toBe(false);
  });

  it('demotes an x509 CVE when no x509 authenticator is configured', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'security-http',
      summary: X509_SPOOFING,
      signals: demoSignals(),
    });
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('symfony-security-x509');
  });

  it('does NOT demote the x509 CVE when an x509 firewall IS configured', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'security-http',
      summary: X509_SPOOFING,
      signals: demoSignals({ securityYamlText: 'firewalls:\n  main:\n    x509:\n      provider: users\n' }),
    });
    expect(r.demote).toBe(false);
  });

  it('demotes an `unanimous` strategy CVE when the strategy is not configured', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'security-http',
      summary: UNANIMOUS_STRATEGY,
      signals: demoSignals(),
    });
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('symfony-security-unanimous');
  });

  it('refuses every demotion for an unrecognized (non-Symfony) project', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'twig',
      summary: TWIG_SANDBOX_BYPASS,
      signals: emptySymfonyFeatureSignals(),
    });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote when the summary names no gated feature', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'twig',
      summary: 'Twig had a minor rendering performance regression.',
      signals: demoSignals(),
    });
    expect(r.demote).toBe(false);
  });

  // --- deferred levers added in the follow-up pass ---
  it('demotes a twig profiler HtmlDumper CVE when the WebProfilerBundle is dev/test-only', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'twig',
      summary: 'XSS in the profiler HtmlDumper when rendering a dumped variable.',
      signals: demoSignals({ configText: "webprofilerbundle::class => ['dev' => true, 'test' => true]," }),
    });
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('twig-profiler');
  });

  it('does NOT demote the profiler CVE when the WebProfilerBundle runs in prod', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'twig',
      summary: 'XSS in the profiler HtmlDumper when rendering a dumped variable.',
      signals: demoSignals({ configText: "webprofilerbundle::class => ['all' => true]," }),
    });
    expect(r.demote).toBe(false);
  });

  it('demotes a twig template-name-injection CVE when template names are static', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'twig',
      summary: 'Twig loaded a template outside the configured directory via the filesystem loader.',
      signals: demoSignals(),
    });
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('twig-user-controlled-template-name');
  });

  it('does NOT demote the template-name CVE when a render uses a variable template name', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'twig',
      summary: 'Twig loaded a template outside the configured directory via the filesystem loader.',
      signals: demoSignals({ codeText: 'class c { function f($t){ return $this->render($t); } }' }),
    });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote the template-name CVE when the template name is a string concatenated with a variable', () => {
    // symfony/demo's real shape: `->render('blog/index.'.$_format.'.twig')`.
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'twig',
      summary: 'Twig may load a template outside a configured directory when using the filesystem loader.',
      signals: demoSignals({ codeText: "return \\$this->render('blog/index.'.\\$_format.'.twig', []);" }),
    });
    expect(r.demote).toBe(false);
  });

  it('DOES demote the template-name CVE when only static renders + a config loader exist (Kernel.php $loader->load must not block)', () => {
    // Every Symfony Kernel.php has `$loader->load($confDir…)` — the config
    // loader, NOT a Twig template loader. It must not falsely count as a
    // user-controlled template name (that would make the row dead on every app).
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'twig',
      summary: 'Twig may load a template outside a configured directory when using the filesystem loader.',
      signals: demoSignals({
        codeText:
          "class kernel { function c(\\$loader){ \\$loader->load(\\$confDir.'/{packages}/*'); } }\n" +
          "class ctrl { function i(){ return \\$this->render('blog/index.html.twig', []); } }",
      }),
    });
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('twig-user-controlled-template-name');
  });

  it('demotes the monolog-bridge server:log deserialization CVE (CLI-only, never on an HTTP path)', () => {
    const r = evaluateSymfonyFeaturePreconditionDemotion({
      depName: 'monolog-bridge',
      summary: 'Unauthenticated deserialization in the server:log command listener.',
      signals: demoSignals(),
    });
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('symfony-monolog-serverlog');
  });
});

describe('evaluateComposerDevOnlyDemotion', () => {
  it('demotes a package that is dev-only (packages-dev, not in packages)', () => {
    const r = evaluateComposerDevOnlyDemotion({ packageName: 'symfony/process', signals: demoSignals() });
    expect(r.demote).toBe(true);
    expect(r.package).toBe('symfony/process');
  });

  it('does NOT demote a production dependency', () => {
    const r = evaluateComposerDevOnlyDemotion({ packageName: 'symfony/http-foundation', signals: demoSignals() });
    expect(r.demote).toBe(false);
  });

  it('matches a short name against the full lock entry (trailing-segment fallback)', () => {
    const r = evaluateComposerDevOnlyDemotion({ packageName: 'process', signals: demoSignals() });
    expect(r.demote).toBe(true);
  });

  it('refuses to demote when the lockfile was never parsed', () => {
    const r = evaluateComposerDevOnlyDemotion({ packageName: 'symfony/process', signals: emptySymfonyFeatureSignals() });
    expect(r.demote).toBe(false);
  });

  // Framework-independence regression (the monica/Laravel gap): a composer app
  // that is NOT recognized as Symfony (`recognized: false`) but whose lockfile
  // WAS parsed (`lockParsed: true`) still gets its dev-only deps demoted. This
  // is the whole point of keying on `lockParsed` instead of `recognized`.
  it('demotes a dev-only dep on a non-Symfony (Laravel) app when the lockfile is parsed', () => {
    const laravelSignals: SymfonyFeatureSignals = {
      ...emptySymfonyFeatureSignals(),
      recognized: false, // NOT a Symfony app (no symfony/framework-bundle)
      lockParsed: true,
      lockProd: new Set(['laravel/framework', 'league/commonmark', 'symfony/http-foundation']),
      lockDev: new Set(['phpunit/phpunit', 'maximebf/debugbar', 'psy/psysh', 'symfony/yaml']),
    };
    // dev-only transitives are demoted...
    expect(evaluateComposerDevOnlyDemotion({ packageName: 'phpunit/phpunit', signals: laravelSignals }).demote).toBe(true);
    expect(evaluateComposerDevOnlyDemotion({ packageName: 'maximebf/debugbar', signals: laravelSignals }).demote).toBe(true);
    expect(evaluateComposerDevOnlyDemotion({ packageName: 'symfony/yaml', signals: laravelSignals }).demote).toBe(true);
    // ...but a prod dep on the same app is left alone.
    expect(evaluateComposerDevOnlyDemotion({ packageName: 'laravel/framework', signals: laravelSignals }).demote).toBe(false);
  });

  // A package present in BOTH packages and packages-dev (prod requires it) is
  // never demoted — prod scope wins, framework-independent.
  it('does NOT demote a dep that also appears in the production tree', () => {
    const signals: SymfonyFeatureSignals = {
      ...emptySymfonyFeatureSignals(),
      recognized: false,
      lockParsed: true,
      lockProd: new Set(['symfony/yaml']),
      lockDev: new Set(['symfony/yaml']),
    };
    expect(evaluateComposerDevOnlyDemotion({ packageName: 'symfony/yaml', signals }).demote).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. End-to-end through updateReachabilityLevels (ecosystem: 'composer')
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

/** Seed one composer transitive dep (namespace/name) that lands at `module`. */
function seedComposerDep(
  fsk: FakeStorage,
  opts: { namespace: string; name: string; osvId: string; summary: string; filesImporting?: number },
) {
  fsk.set('project_dependency_vulnerabilities', [
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
      is_direct: false,
      files_importing_count: opts.filesImporting ?? 1,
      environment: null,
      name: opts.name,
      namespace: opts.namespace,
    },
  ]);
  fsk.set('project_reachable_flows', []);
  fsk.set('project_reachable_flow_suppressions', []);
  fsk.set('dependency_version_edges', []);
  // Generic first-party usage slice that does NOT contain any dependency name —
  // so the classifier's function-tier name-match heuristic never fires and the
  // dep lands at `module` via the (callgraph-credited) coarse-callgraph branch,
  // exactly as a real Symfony scan does. This lets the e2e exercise the demotion
  // / promotion post-passes on a clean `module` base.
  fsk.set('project_usage_slices', [
    {
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      file_path: 'src/Controller/BlogController.php',
      line_number: 1,
      target_name: 'app.controller.index',
      target_type: 'app.controller.index',
      resolved_method: 'app.controller.index',
    },
  ]);
}

function verdictOf(fsk: FakeStorage, pdvId: string): { level?: string; details?: any } {
  const u = fsk.updates.find(
    (x) => x.table === 'project_dependency_vulnerabilities' && x.filter.id === pdvId && 'reachability_level' in x.values,
  );
  return { level: u?.values.reachability_level, details: u?.values.reachability_details };
}

beforeEach(() => jest.clearAllMocks());

describe('updateReachabilityLevels — Symfony framework-mediated model', () => {
  it('PROMOTES an http-foundation authz-bypass module finding to data_flow on a deployed web app', async () => {
    const fsk = new FakeStorage();
    seedComposerDep(fsk, {
      namespace: 'symfony',
      name: 'http-foundation',
      osvId: 'CVE-2025-64500',
      summary: HTTP_FOUNDATION_AUTHZ_BYPASS,
    });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'composer',
      usedTransitives: new Set(['http-foundation']),
      symfonyFeatureSignals: demoSignals(),
      httpEntryPointCount: 13,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('data_flow');
    expect(details?.verdict).toBe('always_on_framework_runtime');
    expect(details?.sink).toBe('symfony-http-foundation-request-parser');
    expect(details?.threat_tag).toBe('requires_protected_route');
  });

  it('DEV-ONLY DEMOTE: symfony/process (packages-dev) module → unreachable', async () => {
    const fsk = new FakeStorage();
    seedComposerDep(fsk, {
      namespace: 'symfony',
      name: 'process',
      osvId: 'CVE-2024-51736',
      summary: PROCESS_WINDOWS_HIJACK,
      filesImporting: 0,
    });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'composer',
      usedTransitives: new Set(['process']),
      symfonyFeatureSignals: demoSignals(),
      httpEntryPointCount: 13,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('dev_only_dependency');
    expect(details?.package).toBe('symfony/process');
  });

  it('FEATURE DEMOTE: a twig-sandbox CVE module → unreachable (sandbox absent)', async () => {
    const fsk = new FakeStorage();
    seedComposerDep(fsk, {
      namespace: 'twig',
      name: 'twig',
      osvId: 'CVE-2024-45411',
      summary: TWIG_SANDBOX_BYPASS,
    });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'composer',
      usedTransitives: new Set(['twig']),
      symfonyFeatureSignals: demoSignals(),
      httpEntryPointCount: 13,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('feature_precondition_absent');
    expect(details?.feature).toBe('twig-sandbox');
  });

  it('DEMOTE applies even on a non-web-app (0 routes): the x509 CVE → unreachable', async () => {
    const fsk = new FakeStorage();
    seedComposerDep(fsk, {
      namespace: 'symfony',
      name: 'security-http',
      osvId: 'CVE-2026-45063',
      summary: X509_SPOOFING,
    });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'composer',
      usedTransitives: new Set(['security-http']),
      symfonyFeatureSignals: demoSignals(),
      httpEntryPointCount: 0,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.feature).toBe('symfony-security-x509');
  });

  it('STAYS module: http-foundation authz-bypass on a library repo (0 routes → no promotion)', async () => {
    const fsk = new FakeStorage();
    seedComposerDep(fsk, {
      namespace: 'symfony',
      name: 'http-foundation',
      osvId: 'CVE-2025-64500',
      summary: HTTP_FOUNDATION_AUTHZ_BYPASS,
    });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'composer',
      usedTransitives: new Set(['http-foundation']),
      symfonyFeatureSignals: demoSignals(),
      httpEntryPointCount: 0,
    });
    const { level } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
  });
});
