/**
 * Python / Django framework-mediated reachability model — the pypi mirror of
 * the Java / PHP / Ruby / Go feature-precondition + always-on-runtime gates.
 * Verdicts are grounded in the saleor 3.14 triage (68 dependency-CVEs at
 * `module`, hand-triaged → 5 promote / ~25 demote / 38 honest module).
 *
 * Covers:
 *   1. the pure decision functions with injected signals (no filesystem):
 *      - `evaluateDjangoAlwaysOnRuntimePromotion` (django uri_to_iri /
 *        log-response / validator ReDoS + pillow WebP decode → visible on a
 *        deployed app; ids-matching for PYSEC-2023-175's useless summary),
 *      - `evaluateDjangoFeaturePreconditionDemotion` (pillow/cryptography
 *        submodule gates, humanize, windows-only, brotli-scrapy, h11,
 *        sqlparse, fonttools, setuptools → unreachable when provably absent),
 *      - `evaluateDjangoDevOnlyDemotion` (manifest dev groups).
 *   2. `gatherDjangoFeatureSignals` filesystem extraction — incl. the
 *      parenthesized-import-with-comment-paren regression (the Python analog
 *      of the Go gitea openpgp catch).
 *   3. end-to-end through `updateReachabilityLevels` with `ecosystem: 'pypi'`,
 *      proving the Django deployed-app signal unblocks promotion with ZERO
 *      http-route entry points (a GraphQL-only saleor-shaped app).
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { updateReachabilityLevels } from '../reachability';
import type { Storage } from '../storage';
import {
  evaluateDjangoAlwaysOnRuntimePromotion,
  evaluateDjangoFeaturePreconditionDemotion,
  evaluateDjangoDevOnlyDemotion,
  gatherDjangoFeatureSignals,
  extractPythonImports,
  emptyDjangoFeatureSignals,
  djangoTransitiveQuestionRegistry,
  type DjangoFeatureSignals,
} from '../reachability-django-preconditions';
import {
  emptyTransitiveImportIndex,
  type TransitiveImportIndex,
} from '../transitive-imports';

// ---------------------------------------------------------------------------
// Representative advisory summaries (real saleor CVE phrasings)
// ---------------------------------------------------------------------------

const DJ_URI_TO_IRI = 'Django Denial of service vulnerability in django.utils.encoding.uri_to_iri';
const DJ_LOG_RESPONSE = 'Django Improper Output Neutralization for Logs vulnerability';
const DJ_VALIDATOR_REDOS =
  'Django has regular expression denial of service vulnerability in EmailValidator/URLValidator';
const DJ_TRUNCATOR = 'Django Denial-of-service in django.utils.text.Truncator';
const DJ_INTCOMMA = 'Django denial-of-service attack in the intcomma template filter';
const DJ_USERNAME_WINDOWS =
  'Django potential denial of service vulnerability in UsernameField on Windows';
const PIL_WEBP = 'libwebp: OOB write in BuildHuffmanTable';
const PIL_FONT = 'Pillow has an integer overflow when processing fonts';
const PIL_PDF = 'Pillow has a PDF Parsing Trailer Infinite Loop (DoS)';
const PIL_IMAGEMATH = 'Arbitrary Code Execution in Pillow';
const PIL_GENERIC_DOS = 'Pillow Denial of Service vulnerability';
const CRYPTO_PKCS7 = 'cryptography vulnerable to NULL-dereference when loading PKCS7 certificates';
const CRYPTO_PKCS12 = 'Null pointer dereference in PKCS12 parsing';
const CRYPTO_SSH = 'cryptography mishandles SSH certificates';
const CRYPTO_BLEICHENBACHER =
  'Python Cryptography package vulnerable to Bleichenbacher timing oracle attack';
const BROTLI_SCRAPY =
  'Scrapy is vulnerable to a denial of service (DoS) attack due to flaws in brotli decompress';
const H11_CHUNKED = 'h11 accepts some malformed Chunked-Encoding bodies';
const SQLPARSE_DOS = 'sqlparse parsing heavily nested list leads to Denial of Service';
const FONTTOOLS_XXE = 'fonttools XML External Entity Injection (XXE) Vulnerability';
const SETUPTOOLS_CMD = 'setuptools vulnerable to Command Injection via package URL';
const SETUPTOOLS_TRAVERSAL =
  'setuptools has a path traversal vulnerability in PackageIndex.download that leads to Arbitrary File Write';
const TQDM_CLI = 'tqdm CLI arguments injection attack';
const FILELOCK_SOFT =
  'filelock Time-of-Check-Time-of-Use (TOCTOU) Symlink Vulnerability in SoftFileLock';

/**
 * A recognized saleor-shaped Django project: a deployed (asgi/wsgi) web app
 * with an image-upload surface + an auth/validator surface, importing pillow
 * as `PIL.Image` only (no ImageFont/PdfParser/ImageMath), httptools present
 * (shadows h11), pytest dev-only — and NO humanize / pkcs7 / paramiko /
 * scrapy / sqlparse / fontTools anywhere.
 */
function djSignals(over: Partial<DjangoFeatureSignals> = {}): DjangoFeatureSignals {
  return {
    ...emptyDjangoFeatureSignals(),
    recognized: true,
    truncated: false,
    devDeps: new Set(['pytest', 'pytest-django']),
    depUniverse: new Set([
      'django', 'pillow', 'cryptography', 'weasyprint', 'fonttools', 'uvicorn',
      'httptools', 'h11', 'brotli', 'sqlparse', 'setuptools', 'pytest', 'pytest-django',
    ]),
    importedModules: new Set(['django', 'django.db', 'pil', 'pil.image', 'celery']),
    codeText: [
      'installed_apps = ["django.contrib.auth", "django.contrib.contenttypes"]',
      'wsgi_application = "saleor.wsgi.application"',
      'image = models.imagefield(upload_to="products")',
      'from pil import image',
    ].join('\n'),
    isDeployedWebApp: true,
    usesImageUploads: true,
    ...over,
  };
}

// ---------------------------------------------------------------------------
// 1. Pure decision functions — PROMOTION (always-on Django request path)
// ---------------------------------------------------------------------------

describe('evaluateDjangoAlwaysOnRuntimePromotion', () => {
  const base = { deployedWebApp: true, signals: djSignals() };

  it('promotes the uri_to_iri request-path DoS to data_flow', () => {
    const r = evaluateDjangoAlwaysOnRuntimePromotion({ depName: 'django', summary: DJ_URI_TO_IRI, ...base });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('data_flow');
    expect(r.sink).toBe('django-uri-to-iri');
    expect(r.threatTag).toBe('requires_untrusted_request');
  });

  it('promotes the response-logging injection to data_flow', () => {
    const r = evaluateDjangoAlwaysOnRuntimePromotion({ depName: 'django', summary: DJ_LOG_RESPONSE, ...base });
    expect(r.promote).toBe(true);
    expect(r.sink).toBe('django-log-response-injection');
  });

  it('promotes the Email/URLValidator ReDoS to function when a validator surface exists', () => {
    const r = evaluateDjangoAlwaysOnRuntimePromotion({ depName: 'django', summary: DJ_VALIDATOR_REDOS, ...base });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('function');
  });

  it('refuses the validator ReDoS when no validator surface exists in code', () => {
    const bare = djSignals({ codeText: 'wsgi_application = "app.wsgi"' });
    const r = evaluateDjangoAlwaysOnRuntimePromotion({
      depName: 'django', summary: DJ_VALIDATOR_REDOS, deployedWebApp: true, signals: bare,
    });
    expect(r.promote).toBe(false);
  });

  it('promotes pillow WebP decode by summary on an app with image uploads', () => {
    const r = evaluateDjangoAlwaysOnRuntimePromotion({ depName: 'pillow', summary: PIL_WEBP, ...base });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('function');
    expect(r.sink).toBe('pillow-webp-decode');
    expect(r.threatTag).toBe('requires_untrusted_upload');
  });

  it('promotes PYSEC-2023-175 by advisory ID (its summary is the literal string "Summary")', () => {
    const r = evaluateDjangoAlwaysOnRuntimePromotion({
      depName: 'pillow', summary: 'Summary', osvIds: ['PYSEC-2023-175', 'CVE-2023-4863'], ...base,
    });
    expect(r.promote).toBe(true);
    expect(r.sink).toBe('pillow-webp-decode');
    expect(r.matchedPattern).toMatch(/^id:/);
  });

  it('refuses pillow WebP when the app has no image-upload surface', () => {
    const r = evaluateDjangoAlwaysOnRuntimePromotion({
      depName: 'pillow', summary: PIL_WEBP, deployedWebApp: true, signals: djSignals({ usesImageUploads: false }),
    });
    expect(r.promote).toBe(false);
  });

  it('vetoes a font-sibling summary on the WebP row (exclude guard)', () => {
    const r = evaluateDjangoAlwaysOnRuntimePromotion({
      depName: 'pillow', summary: 'Pillow WebP font table overflow', ...base,
    });
    expect(r.promote).toBe(false);
  });

  it('does NOT promote a django CVE outside the promote set (Truncator DoS)', () => {
    expect(evaluateDjangoAlwaysOnRuntimePromotion({ depName: 'django', summary: DJ_TRUNCATOR, ...base }).promote).toBe(false);
  });

  it('refuses when the project is not a deployed web app', () => {
    const r = evaluateDjangoAlwaysOnRuntimePromotion({
      depName: 'django', summary: DJ_URI_TO_IRI, deployedWebApp: false, signals: djSignals(),
    });
    expect(r.promote).toBe(false);
  });

  it('refuses on unrecognized signals', () => {
    const r = evaluateDjangoAlwaysOnRuntimePromotion({
      depName: 'django', summary: DJ_URI_TO_IRI, deployedWebApp: true, signals: emptyDjangoFeatureSignals(),
    });
    expect(r.promote).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. Pure decision functions — DEMOTION (feature provably absent)
// ---------------------------------------------------------------------------

describe('evaluateDjangoFeaturePreconditionDemotion', () => {
  const sig = () => djSignals();
  const demote = (depName: string, summary: string, signals = sig()) =>
    evaluateDjangoFeaturePreconditionDemotion({ depName, summary, signals });

  it('demotes the intcomma/humanize DoS when "humanize" appears nowhere', () => {
    const r = demote('django', DJ_INTCOMMA);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('django-contrib-humanize');
  });

  it('refuses the humanize demotion when a template loads humanize', () => {
    const withHumanize = djSignals({ codeText: djSignals().codeText + '\n{% load humanize %}' });
    expect(demote('django', DJ_INTCOMMA, withHumanize).demote).toBe(false);
  });

  it('demotes a Windows-only django CVE (structurally absent on container deploys)', () => {
    const r = demote('django', DJ_USERNAME_WINDOWS);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('django-windows-only');
  });

  it('demotes the pillow font CVE when ImageFont is never touched', () => {
    const r = demote('pillow', PIL_FONT);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('pillow-imagefont');
  });

  it('refuses the font demotion when PIL.ImageFont is imported', () => {
    const withFont = djSignals({
      importedModules: new Set([...djSignals().importedModules, 'pil.imagefont']),
    });
    expect(demote('pillow', PIL_FONT, withFont).demote).toBe(false);
  });

  it('refuses the font demotion when a captcha lib (transitive ImageFont consumer) is present', () => {
    const withCaptcha = djSignals({
      depUniverse: new Set([...djSignals().depUniverse, 'django-simple-captcha']),
    });
    expect(demote('pillow', PIL_FONT, withCaptcha).demote).toBe(false);
  });

  it('demotes the pillow PDF trailer-parsing loop when PdfParser is never touched', () => {
    const r = demote('pillow', PIL_PDF);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('pillow-pdfparser');
  });

  it('demotes the ImageMath code-execution CVE when ImageMath is never touched', () => {
    const r = demote('pillow', PIL_IMAGEMATH);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('pillow-imagemath');
  });

  it('leaves a component-less pillow DoS alone (honest module — no rule matches)', () => {
    expect(demote('pillow', PIL_GENERIC_DOS).demote).toBe(false);
  });

  it('demotes cryptography PKCS7 when nothing touches pkcs7', () => {
    const r = demote('cryptography', CRYPTO_PKCS7);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('cryptography-pkcs7');
  });

  it('refuses PKCS7 when an ACME client (transitive consumer) is present', () => {
    const withAcme = djSignals({ depUniverse: new Set([...djSignals().depUniverse, 'acme']) });
    expect(demote('cryptography', CRYPTO_PKCS7, withAcme).demote).toBe(false);
  });

  it('demotes cryptography PKCS12 when nothing touches pkcs12', () => {
    expect(demote('cryptography', CRYPTO_PKCS12).demote).toBe(true);
  });

  it('demotes cryptography SSH certificates when no SSH lib / loader usage exists', () => {
    expect(demote('cryptography', CRYPTO_SSH).demote).toBe(true);
  });

  it('refuses the SSH demotion when paramiko is present', () => {
    const withParamiko = djSignals({ depUniverse: new Set([...djSignals().depUniverse, 'paramiko']) });
    expect(demote('cryptography', CRYPTO_SSH, withParamiko).demote).toBe(false);
  });

  it('leaves the Bleichenbacher RSA oracle alone (honest module — no rule matches)', () => {
    expect(demote('cryptography', CRYPTO_BLEICHENBACHER).demote).toBe(false);
  });

  it('demotes the brotli-via-Scrapy CVE when scrapy is not a dependency', () => {
    const r = demote('brotli', BROTLI_SCRAPY);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('brotli-scrapy-consumer');
  });

  it('refuses the brotli demotion when scrapy IS a dependency', () => {
    const withScrapy = djSignals({ depUniverse: new Set([...djSignals().depUniverse, 'scrapy']) });
    expect(demote('brotli', BROTLI_SCRAPY, withScrapy).demote).toBe(false);
  });

  it('demotes the h11 chunked-encoding CVE when httptools shadows the h11 parser', () => {
    const r = demote('h11', H11_CHUNKED);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('h11-parser-shadowed-by-httptools');
  });

  it('refuses the h11 demotion when httptools is absent (uvicorn falls back to h11)', () => {
    const noHttptools = djSignals({
      depUniverse: new Set([...djSignals().depUniverse].filter((d) => d !== 'httptools')),
    });
    expect(demote('h11', H11_CHUNKED, noHttptools).demote).toBe(false);
  });

  it('refuses the h11 demotion when hypercorn (always-h11) is present', () => {
    const withHypercorn = djSignals({ depUniverse: new Set([...djSignals().depUniverse, 'hypercorn']) });
    expect(demote('h11', H11_CHUNKED, withHypercorn).demote).toBe(false);
  });

  it('demotes the sqlparse DoS when first-party code never imports sqlparse', () => {
    expect(demote('sqlparse', SQLPARSE_DOS).demote).toBe(true);
  });

  it('refuses the sqlparse demotion when first-party code imports it', () => {
    const withSqlparse = djSignals({
      importedModules: new Set([...djSignals().importedModules, 'sqlparse']),
    });
    expect(demote('sqlparse', SQLPARSE_DOS, withSqlparse).demote).toBe(false);
  });

  it('a DEV-ONLY consumer lib does not block a demotion (saleor: dev-scoped debug-toolbar vs sqlparse)', () => {
    // A proven-dev-only dependency is not evidence about production
    // reachability — django-debug-toolbar at dev scope can't feed sqlparse in
    // prod, so the demotion must still fire.
    const devToolbar = djSignals({
      depUniverse: new Set([...djSignals().depUniverse, 'django-debug-toolbar']),
      devDeps: new Set([...djSignals().devDeps, 'django-debug-toolbar']),
    });
    expect(demote('sqlparse', SQLPARSE_DOS, devToolbar).demote).toBe(true);
    // At PROD scope the same lib blocks it.
    const prodToolbar = djSignals({
      depUniverse: new Set([...djSignals().depUniverse, 'django-debug-toolbar']),
    });
    expect(demote('sqlparse', SQLPARSE_DOS, prodToolbar).demote).toBe(false);
  });

  it('a DEV-ONLY httptools does not enable the h11 demotion (h11 still parses prod traffic)', () => {
    const devHttptools = djSignals({
      devDeps: new Set([...djSignals().devDeps, 'httptools']),
    });
    expect(demote('h11', H11_CHUNKED, devHttptools).demote).toBe(false);
  });

  it('demotes the fontTools XXE when fontTools is never driven directly', () => {
    expect(demote('fonttools', FONTTOOLS_XXE).demote).toBe(true);
  });

  it('demotes both setuptools PackageIndex CVEs (build-time tooling)', () => {
    expect(demote('setuptools', SETUPTOOLS_CMD).demote).toBe(true);
    expect(demote('setuptools', SETUPTOOLS_TRAVERSAL).demote).toBe(true);
  });

  it('demotes the tqdm CLI-injection CVE (functionSafe) when the CLI is never imported/invoked', () => {
    const tqdmLib = djSignals({
      depUniverse: new Set([...djSignals().depUniverse, 'tqdm']),
      importedModules: new Set([...djSignals().importedModules, 'tqdm']),
    });
    const r = demote('tqdm', TQDM_CLI, tqdmLib);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('tqdm-cli-injection');
    expect(r.functionSafe).toBe(true);
  });

  it('refuses the tqdm demotion when the CLI submodule IS imported', () => {
    const tqdmCli = djSignals({
      depUniverse: new Set([...djSignals().depUniverse, 'tqdm']),
      importedModules: new Set([...djSignals().importedModules, 'tqdm', 'tqdm.cli']),
    });
    expect(demote('tqdm', TQDM_CLI, tqdmCli).demote).toBe(false);
  });

  it('demotes the filelock SoftFileLock CVE (functionSafe) when only default FileLock is used', () => {
    const fileLock = djSignals({
      depUniverse: new Set([...djSignals().depUniverse, 'filelock']),
      codeText: djSignals().codeText + '\nfrom filelock import filelock\nwith filelock(media_lock): pass',
    });
    const r = demote('filelock', FILELOCK_SOFT, fileLock);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('filelock-softfilelock');
    expect(r.functionSafe).toBe(true);
  });

  it('refuses the filelock demotion when SoftFileLock IS referenced', () => {
    const softLock = djSignals({
      depUniverse: new Set([...djSignals().depUniverse, 'filelock']),
      codeText: djSignals().codeText + '\nfrom filelock import softfilelock',
    });
    expect(demote('filelock', FILELOCK_SOFT, softLock).demote).toBe(false);
  });

  it('marks pillow/cryptography submodule demotions functionSafe, but broad rows NOT', () => {
    // Import-gated submodule/API rows are functionSafe (may demote a function-level finding).
    expect(demote('pillow', PIL_IMAGEMATH).functionSafe).toBe(true);
    expect(demote('cryptography', CRYPTO_PKCS7).functionSafe).toBe(true);
    // Broad feature/platform rows are NOT functionSafe (stay module-only).
    expect(demote('django', DJ_USERNAME_WINDOWS).functionSafe).toBe(false);
    expect(demote('django', DJ_INTCOMMA).functionSafe).toBe(false);
  });

  it('refuses every demotion when the code scan was truncated', () => {
    const truncated = djSignals({ truncated: true });
    expect(demote('django', DJ_INTCOMMA, truncated).demote).toBe(false);
    expect(demote('pillow', PIL_FONT, truncated).demote).toBe(false);
    // windows-only is summary-structural, not code-scan-dependent — still fires.
    expect(demote('django', DJ_USERNAME_WINDOWS, truncated).demote).toBe(true);
  });

  it('refuses on unrecognized signals / null summary', () => {
    expect(demote('pillow', PIL_FONT, emptyDjangoFeatureSignals()).demote).toBe(false);
    expect(
      evaluateDjangoFeaturePreconditionDemotion({ depName: 'pillow', summary: null, signals: sig() }).demote,
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2b. Dev-only demotion
// ---------------------------------------------------------------------------

describe('evaluateDjangoDevOnlyDemotion', () => {
  it('demotes a dev-group package (pytest)', () => {
    const r = evaluateDjangoDevOnlyDemotion({ depName: 'pytest', signals: djSignals() });
    expect(r.demote).toBe(true);
    expect(r.package).toBe('pytest');
  });

  it('normalizes underscores/case (Pytest_Django → pytest-django)', () => {
    expect(evaluateDjangoDevOnlyDemotion({ depName: 'Pytest_Django', signals: djSignals() }).demote).toBe(true);
  });

  it('does NOT demote a prod package', () => {
    expect(evaluateDjangoDevOnlyDemotion({ depName: 'django', signals: djSignals() }).demote).toBe(false);
  });

  it('refuses on unrecognized signals', () => {
    expect(evaluateDjangoDevOnlyDemotion({ depName: 'pytest', signals: emptyDjangoFeatureSignals() }).demote).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 3. gatherDjangoFeatureSignals — filesystem extraction (regression)
// ---------------------------------------------------------------------------

describe('gatherDjangoFeatureSignals — extraction', () => {
  function withWorkspace(files: Record<string, string>, fn: (root: string) => void): void {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'django-precond-'));
    try {
      for (const [rel, content] of Object.entries(files)) {
        const full = path.join(dir, rel);
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, content);
      }
      fn(dir);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  const POETRY_PYPROJECT = [
    '[tool.poetry.dependencies]',
    'python = "^3.11"',
    'Django = "^4.2"',
    'Pillow = "^10.0"',
    '',
    '[tool.poetry.group.dev.dependencies]',
    'pytest = "^8.0"',
    'pytest-django = "^4.5"',
  ].join('\n');

  it('captures parenthesized multi-line imports with a ")" inside a comment (gitea-lesson regression)', () => {
    // A ")" in a comment inside the import list must NOT prematurely close the
    // non-greedy parenthesized match — the exact silence-FN shape the Go
    // model's second-app validation caught (a genuinely-imported submodule
    // would look un-imported and get wrongly demoted).
    const models = [
      'from PIL import (  # image tools (RFC-style paren) comment',
      '    Image,',
      '    ImageOps,',
      ')',
      'from django.db import models',
      'import sqlparse',
    ].join('\n');
    withWorkspace(
      { 'pyproject.toml': POETRY_PYPROJECT, 'manage.py': '#!/usr/bin/env python\nimport django\n', 'app/models.py': models },
      (root) => {
        const s = gatherDjangoFeatureSignals(root);
        expect(s.recognized).toBe(true);
        expect(s.truncated).toBe(false);
        expect(s.importedModules.has('pil.image')).toBe(true);
        expect(s.importedModules.has('pil.imageops')).toBe(true);
        expect(s.importedModules.has('sqlparse')).toBe(true);
      },
    );
  });

  it('parses poetry scopes: dev group is dev-only, prod deps are not', () => {
    withWorkspace(
      { 'pyproject.toml': POETRY_PYPROJECT, 'manage.py': 'import django\n' },
      (root) => {
        const s = gatherDjangoFeatureSignals(root);
        expect(s.devDeps.has('pytest')).toBe(true);
        expect(s.devDeps.has('pytest-django')).toBe(true);
        expect(s.devDeps.has('django')).toBe(false);
        expect(s.depUniverse.has('pillow')).toBe(true);
      },
    );
  });

  it('parses Pipfile scopes (paperless-ngx shape) + PEP 621 arrays with extras', () => {
    const pipfile = [
      '[packages]',
      'django = "~=4.1"',
      '"pdfminer.six" = "*"',
      '[dev-packages]',
      'coveralls = "*"',
    ].join('\n');
    const pep621 = [
      '[project]',
      'dependencies = [',
      '  "uvicorn[standard]>=0.20",',
      '  "whitenoise~=6.3",',
      ']',
    ].join('\n');
    withWorkspace(
      { Pipfile: pipfile, 'pyproject.toml': pep621, 'manage.py': 'import django\n' },
      (root) => {
        const s = gatherDjangoFeatureSignals(root);
        expect(s.depUniverse.has('django')).toBe(true);
        expect(s.depUniverse.has('pdfminer.six')).toBe(true);
        expect(s.devDeps.has('coveralls')).toBe(true);
        expect(s.depUniverse.has('uvicorn')).toBe(true); // extras stripped
        expect(s.depUniverse.has('whitenoise')).toBe(true);
      },
    );
  });

  it('prod scope wins: a package declared dev in one manifest and prod in another is never dev-only', () => {
    withWorkspace(
      {
        'pyproject.toml': POETRY_PYPROJECT,
        'requirements.txt': 'pytest==8.0.0\n',
        'manage.py': 'import django\n',
      },
      (root) => {
        const s = gatherDjangoFeatureSignals(root);
        expect(s.devDeps.has('pytest')).toBe(false);
      },
    );
  });

  it('detects the deployed-app + image-upload surfaces', () => {
    withWorkspace(
      {
        'pyproject.toml': POETRY_PYPROJECT,
        'proj/wsgi.py': 'application = get_wsgi_application()\n',
        'app/models.py': 'from django.db import models\nimage = models.ImageField()\n',
      },
      (root) => {
        const s = gatherDjangoFeatureSignals(root);
        expect(s.recognized).toBe(true); // wsgi.py is a project marker
        expect(s.isDeployedWebApp).toBe(true);
        expect(s.usesImageUploads).toBe(true);
      },
    );
  });

  it('returns unrecognized signals for a non-Django Python workspace', () => {
    withWorkspace(
      { 'pyproject.toml': '[tool.poetry.dependencies]\nrequests = "*"\n', 'main.py': 'import requests\n' },
      (root) => {
        expect(gatherDjangoFeatureSignals(root).recognized).toBe(false);
      },
    );
  });
});

describe('extractPythonImports', () => {
  it('handles import / from-import / aliases / backslash continuation, skips relative + star', () => {
    const src = [
      'import os, sys',
      'import PIL.Image as img',
      'from cryptography.hazmat.primitives.serialization import pkcs7',
      'from . import local',
      'from .models import Product',
      'from django.core import validators, \\',
      '    checks',
      'from weasyprint import *',
    ].join('\n');
    const mods = new Set(extractPythonImports(src));
    expect(mods.has('os')).toBe(true);
    expect(mods.has('pil.image')).toBe(true);
    expect(mods.has('cryptography.hazmat.primitives.serialization.pkcs7')).toBe(true);
    expect(mods.has('django.core.validators')).toBe(true);
    expect(mods.has('django.core.checks')).toBe(true);
    expect(mods.has('weasyprint')).toBe(true); // base recorded; star target skipped
    expect([...mods].some((m) => m.startsWith('.'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 4. End-to-end through updateReachabilityLevels (ecosystem: 'pypi')
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

/** Seed one direct pypi dep (imported by tests/app files) that lands at `module`. */
function seedPypiDep(
  fsk: FakeStorage,
  opts: { name: string; osvId: string; summary: string; aliases?: string[] },
) {
  fsk.set('project_dependency_vulnerabilities', [
    {
      id: 'pdv-1',
      project_dependency_id: 'pd-1',
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      osv_id: opts.osvId,
      aliases: opts.aliases ?? [],
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
  // Generic first-party usage slice sharing no token with any pypi dep name, so
  // the function-tier name-match heuristic never fires and the dep floors at
  // `module` via the direct/imported branch, exactly as a real saleor scan does.
  fsk.set('project_usage_slices', [
    {
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      file_path: 'saleor/graphql/api.py',
      line_number: 1,
      target_name: 'app.graphql.execute',
      target_type: 'app.graphql.execute',
      resolved_method: 'app.graphql.execute',
    },
  ]);
}

function verdictOf(fsk: FakeStorage, pdvId: string): { level?: string; details?: any } {
  const u = fsk.updates.find(
    (x) => x.table === 'project_dependency_vulnerabilities' && x.filter.id === pdvId && 'reachability_level' in x.values,
  );
  return { level: u?.values.reachability_level, details: u?.values.reachability_details };
}

async function runDjango(fsk: FakeStorage, signals: DjangoFeatureSignals) {
  await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
    ecosystem: 'pypi',
    workspaceRoot: '/nonexistent',
    djangoFeatureSignals: signals,
    // A GraphQL-only Django app emits ZERO detected http-route entry points —
    // the deployed-app signal carried in djangoFeatureSignals is what unblocks
    // promotion.
    httpEntryPointCount: 0,
  });
}

beforeEach(() => jest.clearAllMocks());

describe('updateReachabilityLevels — Django framework-mediated model', () => {
  it('PROMOTES the uri_to_iri DoS to data_flow on a routeless (GraphQL-only) deployed app', async () => {
    const fsk = new FakeStorage();
    seedPypiDep(fsk, { name: 'django', osvId: 'CVE-2023-41164', summary: DJ_URI_TO_IRI });
    await runDjango(fsk, djSignals());
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('data_flow');
    expect(details?.verdict).toBe('always_on_framework_runtime');
    expect(details?.sink).toBe('django-uri-to-iri');
  });

  it('PROMOTES PYSEC-2023-175 (summary "Summary") by advisory ID to function', async () => {
    const fsk = new FakeStorage();
    seedPypiDep(fsk, {
      name: 'pillow', osvId: 'PYSEC-2023-175', summary: 'Summary', aliases: ['CVE-2023-4863'],
    });
    await runDjango(fsk, djSignals());
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('function');
    expect(details?.sink).toBe('pillow-webp-decode');
  });

  it('DEMOTES the pillow font CVE to unreachable when ImageFont is never touched', async () => {
    const fsk = new FakeStorage();
    seedPypiDep(fsk, { name: 'pillow', osvId: 'CVE-2026-42308', summary: PIL_FONT });
    await runDjango(fsk, djSignals());
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('feature_precondition_absent');
    expect(details?.feature).toBe('pillow-imagefont');
  });

  it('DEMOTES a dev-group package (pytest) to unreachable', async () => {
    const fsk = new FakeStorage();
    seedPypiDep(fsk, { name: 'pytest', osvId: 'CVE-2025-71176', summary: 'pytest has vulnerable tmpdir handling' });
    await runDjango(fsk, djSignals());
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('dev_only_dependency');
  });

  it('LEAVES an honest-middle CVE (cryptography Bleichenbacher) at module', async () => {
    const fsk = new FakeStorage();
    seedPypiDep(fsk, { name: 'cryptography', osvId: 'CVE-2023-50782', summary: CRYPTO_BLEICHENBACHER });
    await runDjango(fsk, djSignals());
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });

  it('does NOT promote when the app is not deployed (no wsgi/asgi, no routes)', async () => {
    const fsk = new FakeStorage();
    seedPypiDep(fsk, { name: 'django', osvId: 'CVE-2023-41164', summary: DJ_URI_TO_IRI });
    await runDjango(fsk, djSignals({ isDeployedWebApp: false }));
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });

  it('refuses code-scan demotions (stays module) when the scan was truncated', async () => {
    const fsk = new FakeStorage();
    seedPypiDep(fsk, { name: 'pillow', osvId: 'CVE-2026-42308', summary: PIL_FONT });
    await runDjango(fsk, djSignals({ truncated: true }));
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });
});

// ---------------------------------------------------------------------------
// Arc 2 — transitive consumer VETO (dependency-source import graphs, v1)
// ---------------------------------------------------------------------------

describe('Arc 2 transitive consumer veto (owner-excluded, veto-only)', () => {
  const PIL_FONT_A2 = 'Pillow has an integer overflow when processing fonts';
  const CRYPTO_PKCS7_A2 = 'cryptography vulnerable to NULL-dereference when loading PKCS7 certificates';
  const SQLPARSE_DOS_A2 = 'sqlparse parsing heavily nested list leads to Denial of Service';

  function a2Signals(over: Partial<DjangoFeatureSignals> = {}): DjangoFeatureSignals {
    return {
      ...emptyDjangoFeatureSignals(),
      recognized: true,
      truncated: false,
      devDeps: new Set<string>(),
      depUniverse: new Set(['django', 'pillow', 'cryptography', 'sqlparse']),
      importedModules: new Set(['django', 'pil', 'pil.image']),
      codeText: 'installed_apps = ["django.contrib.auth"]\nwsgi_application = "app.wsgi"',
      isDeployedWebApp: true,
      ...over,
    };
  }

  function idx(
    entries: Record<string, { modules?: string[]; tokens?: string[] }>,
    status: TransitiveImportIndex['status'] = 'partial',
  ): TransitiveImportIndex {
    const out = emptyTransitiveImportIndex('pypi');
    out.status = status;
    for (const [pkg, { modules = [], tokens = [] }] of Object.entries(entries)) {
      out.perPackage.set(pkg, { modules: new Set(modules), tokenHits: new Set(tokens) });
      out.extractedPackages.add(pkg);
    }
    return out;
  }

  const demoteA2 = (depName: string, summary: string, signals: DjangoFeatureSignals) =>
    evaluateDjangoFeaturePreconditionDemotion({ depName, summary, signals });

  it('OWNER self-hit only: pillow mentioning its own ImageFont never vetoes — the demotion keeps firing', () => {
    const signals = a2Signals({
      transitiveImports: idx({
        pillow: { modules: ['pil.imagefont'], tokens: ['imagefont', 'truetype('] },
      }),
    });
    const r = demoteA2('pillow', PIL_FONT_A2, signals);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('pillow-imagefont');
  });

  it('a NON-OWNER dist importing pil.imagefont vetoes the pillow demotion', () => {
    const signals = a2Signals({
      transitiveImports: idx({
        pillow: { tokens: ['imagefont'] },
        'weird-thumbnailer': { modules: ['pil.imagefont'] },
      }),
    });
    expect(demoteA2('pillow', PIL_FONT_A2, signals).demote).toBe(false);
  });

  it('a NON-OWNER token hit does NOT veto in v1 — dependency sources MENTIONING a submodule is the dormant-wrapper case', () => {
    // pyopenssl's sources contain 'pkcs7', pip's contain 'easy_install' — a
    // token veto reversed 11 labelled-unreachable saleor/paperless demotions
    // in validation. Tokens are cached for the v2 absence direction only.
    const signals = a2Signals({
      transitiveImports: idx({ captchagen: { tokens: ['truetype('] } }),
    });
    expect(demoteA2('pillow', PIL_FONT_A2, signals).demote).toBe(true);
    const pkcs = a2Signals({
      transitiveImports: idx({ pyopenssl: { tokens: ['pkcs7'] } }),
    });
    expect(demoteA2('cryptography', CRYPTO_PKCS7_A2, pkcs).demote).toBe(true);
  });

  it('positive IMPORT veto evidence is valid on a PARTIAL index', () => {
    const partial = idx({ 'weird-thumbnailer': { modules: ['pil.imagefont'] } }, 'partial');
    partial.failedPackages.push('some-failed-dist');
    const signals = a2Signals({ transitiveImports: partial });
    expect(demoteA2('pillow', PIL_FONT_A2, signals).demote).toBe(false);
  });

  it('an UNAVAILABLE index changes nothing — today’s behavior', () => {
    const signals = a2Signals({
      transitiveImports: idx({ acmeclient: { tokens: ['pkcs7'] } }, 'unavailable'),
    });
    expect(demoteA2('cryptography', CRYPTO_PKCS7_A2, signals).demote).toBe(true);
  });

  it('no index at all: every demotion behaves exactly as before', () => {
    expect(demoteA2('pillow', PIL_FONT_A2, a2Signals()).demote).toBe(true);
    expect(demoteA2('cryptography', CRYPTO_PKCS7_A2, a2Signals()).demote).toBe(true);
  });

  it('consumer-semantics rows are UNTOUCHED: django importing sqlparse never vetoes the sqlparse demotion (the paperless labels)', () => {
    // django statically imports sqlparse (sqlmigrate — trusted SQL); sqlparse
    // self-imports absolutely. Neither may reverse the labelled demotion.
    const signals = a2Signals({
      transitiveImports: idx({
        django: { modules: ['sqlparse'], tokens: ['sqlparse'] },
        sqlparse: { modules: ['sqlparse.engine'], tokens: ['sqlparse'] },
      }),
    });
    const r = demoteA2('sqlparse', SQLPARSE_DOS_A2, signals);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('sqlparse-untrusted-sql');
  });

  it('the question registry is DERIVED from the rows: submodule-load owners in, consumer-semantics owners out', () => {
    const reg = djangoTransitiveQuestionRegistry();
    expect(reg.owners).toEqual(
      expect.arrayContaining(['pillow', 'cryptography', 'fonttools', 'setuptools', 'tqdm', 'filelock']),
    );
    expect(reg.owners).not.toContain('sqlparse');
    expect(reg.owners).not.toContain('brotli');
    expect(reg.owners).not.toContain('h11');
    expect(reg.tokens).toEqual(
      expect.arrayContaining(['imagefont', 'truetype(', 'pkcs7', 'pkcs12', 'load_ssh', 'softfilelock']),
    );
    expect(reg.modules).toEqual(expect.arrayContaining(['pil.imagefont', 'fonttools', 'tqdm.cli']));
  });

  it('owner normalization is PEP-503: a "Pillow"-cased dep name still excludes the pillow dist', () => {
    const signals = a2Signals({
      transitiveImports: idx({ pillow: { modules: ['pil.imagefont'], tokens: ['imagefont'] } }),
    });
    expect(demoteA2('Pillow', PIL_FONT_A2, signals).demote).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Arc 2 e2e — options.transitiveImports merge (pypi) through updateReachabilityLevels
// ---------------------------------------------------------------------------

describe('updateReachabilityLevels — Arc 2 pypi transitive-veto wiring', () => {
  const PIL_FONT_E2E = 'Pillow has an integer overflow when processing fonts';

  function pypiIdx(
    entries: Record<string, { modules?: string[]; tokens?: string[] }>,
    status: TransitiveImportIndex['status'] = 'partial',
  ): TransitiveImportIndex {
    const out = emptyTransitiveImportIndex('pypi');
    out.status = status;
    for (const [pkg, { modules = [], tokens = [] }] of Object.entries(entries)) {
      out.perPackage.set(pkg, { modules: new Set(modules), tokenHits: new Set(tokens) });
      out.extractedPackages.add(pkg);
    }
    return out;
  }

  async function runDjangoIdx(
    fsk: FakeStorage,
    signals: DjangoFeatureSignals,
    idx?: TransitiveImportIndex,
  ) {
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'pypi',
      workspaceRoot: '/nonexistent',
      djangoFeatureSignals: signals,
      transitiveImports: idx,
      httpEntryPointCount: 0,
    });
  }

  it('a NON-OWNER dist importing pil.imagefont VETOES the pillow demotion end-to-end (stays module)', async () => {
    const fsk = new FakeStorage();
    seedPypiDep(fsk, { name: 'pillow', osvId: 'CVE-2026-42308', summary: PIL_FONT_E2E });
    await runDjangoIdx(fsk, djSignals(), pypiIdx({ 'weird-thumbnailer': { modules: ['pil.imagefont'] } }));
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });

  it('OWNER self-hits only: the demotion still fires end-to-end (owner exclusion through the merge)', async () => {
    const fsk = new FakeStorage();
    seedPypiDep(fsk, { name: 'pillow', osvId: 'CVE-2026-42308', summary: PIL_FONT_E2E });
    await runDjangoIdx(
      fsk,
      djSignals(),
      pypiIdx({ pillow: { modules: ['pil.imagefont'], tokens: ['imagefont', 'truetype('] } }),
    );
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.feature).toBe('pillow-imagefont');
  });

  it('a golang-ecosystem index is never merged into pypi signals', async () => {
    const fsk = new FakeStorage();
    seedPypiDep(fsk, { name: 'pillow', osvId: 'CVE-2026-42308', summary: PIL_FONT_E2E });
    const goIdx = emptyTransitiveImportIndex('golang');
    goIdx.status = 'complete';
    goIdx.perPackage.set('x', { modules: new Set(['pil.imagefont']), tokenHits: new Set() });
    await runDjangoIdx(fsk, djSignals(), goIdx);
    // wrong-ecosystem index ignored → demotion fires as with no index
    expect(verdictOf(fsk, 'pdv-1').level).toBe('unreachable');
  });
});
