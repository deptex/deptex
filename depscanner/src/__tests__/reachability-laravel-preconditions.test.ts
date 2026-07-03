/**
 * Laravel framework-mediated reachability model — the composer sibling of the
 * Symfony model, but FEATURE-GATED (Laravel request-path CVEs are reachable only
 * when the app uses the specific feature). Two-app calibrated on monica (uses
 * signed URLs) vs koel (does not).
 *
 * Covers the pure decision functions with injected signals (no filesystem):
 *   - `evaluateLaravelAlwaysOnRuntimePromotion` (signed-URL → data_flow when the
 *     app uses signed URLs; file-validation → function when it validates uploads),
 *   - `evaluateLaravelFeaturePreconditionDemotion` (signed-URL CVE → unreachable
 *     when the app provably uses NO signed URLs),
 *   - the detectors + fail-safes (unrecognized / no-entry-point refuse every move).
 */

import {
  evaluateLaravelAlwaysOnRuntimePromotion,
  evaluateLaravelFeaturePreconditionDemotion,
  usesSignedUrls,
  hasFileUploadValidation,
  emptyLaravelFeatureSignals,
  type LaravelFeatureSignals,
} from '../reachability-laravel-preconditions';

// Real advisory summaries (byte-identical on monica + koel scans).
const SIGNED_URL = 'Laravel Framework: Temporary Signed URL Path Confusion';
const FILE_VALIDATION = 'Laravel has a File Validation Bypass';

/**
 * monica-shape: a recognized Laravel app that USES signed URLs (a
 * temporarySignedRoute invitation) AND validates file uploads (mimes rules).
 */
function monicaSignals(over: Partial<LaravelFeatureSignals> = {}): LaravelFeatureSignals {
  return {
    ...emptyLaravelFeatureSignals(),
    recognized: true,
    lockProd: new Set(['laravel/framework', 'symfony/http-foundation']),
    codeText:
      "class kernel { protected \$routemiddleware = ['signed' => validatesignature::class]; }\n" +
      "url::temporarysignedroute('invitation.show', now()->adddays(7), ['uuid' => \$uuid]);\n" +
      "request()->validate(['avatar' => 'required|image|mimes:jpg,png|max:2048']);\n",
    ...over,
  };
}

/**
 * koel-shape: a recognized Laravel app that uses NO signed URLs (API-first, no
 * ValidateSignature / temporarySignedRoute anywhere) but DOES validate uploads.
 */
function koelSignals(over: Partial<LaravelFeatureSignals> = {}): LaravelFeatureSignals {
  return {
    ...emptyLaravelFeatureSignals(),
    recognized: true,
    lockProd: new Set(['laravel/framework']),
    codeText:
      "class uploadrequest extends formrequest { public function rules() { return ['file' => 'required|file']; } }\n" +
      "\$request->file('file')->storeas(\$dir, \$name);\n",
    ...over,
  };
}

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

describe('detectors', () => {
  it('usesSignedUrls: present on monica-shape, absent on koel-shape', () => {
    expect(usesSignedUrls(monicaSignals())).toBe(true);
    expect(usesSignedUrls(koelSignals())).toBe(false);
  });

  it('usesSignedUrls: matches each signed-URL API individually', () => {
    for (const api of ['temporarysignedroute', 'signedroute', 'hasvalidsignature', 'validatesignature', 'url::signedroute']) {
      expect(usesSignedUrls({ ...emptyLaravelFeatureSignals(), codeText: `foo ${api} bar` })).toBe(true);
    }
  });

  it('hasFileUploadValidation: present on both shapes (both validate uploads)', () => {
    expect(hasFileUploadValidation(monicaSignals())).toBe(true);
    expect(hasFileUploadValidation(koelSignals())).toBe(true);
  });

  it('hasFileUploadValidation: absent on an app with no upload handling', () => {
    expect(hasFileUploadValidation({ ...emptyLaravelFeatureSignals(), codeText: "return ['name' => 'required|string'];" })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Always-on promotion
// ---------------------------------------------------------------------------

describe('evaluateLaravelAlwaysOnRuntimePromotion', () => {
  const P = (summary: string, signals: LaravelFeatureSignals) =>
    evaluateLaravelAlwaysOnRuntimePromotion({ depName: 'laravel/framework', summary, hasHttpRouteEntryPoint: true, signals });

  it('promotes the signed-URL CVE to data_flow when the app USES signed URLs (monica)', () => {
    const r = P(SIGNED_URL, monicaSignals());
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('data_flow');
    expect(r.sink).toBe('laravel-signed-url-validation');
    expect(r.threatTag).toBe('requires_signed_route');
  });

  it('does NOT promote the signed-URL CVE when the app uses NO signed URLs (koel)', () => {
    expect(P(SIGNED_URL, koelSignals()).promote).toBe(false);
  });

  it('promotes the file-validation CVE to function when the app validates uploads (both apps)', () => {
    for (const s of [monicaSignals(), koelSignals()]) {
      const r = P(FILE_VALIDATION, s);
      expect(r.promote).toBe(true);
      expect(r.promoteTo).toBe('function');
      expect(r.sink).toBe('laravel-file-validation');
    }
  });

  it('does NOT promote the file-validation CVE when the app never validates uploads', () => {
    const noUpload = koelSignals({ codeText: "return ['name' => 'required|string'];" });
    expect(P(FILE_VALIDATION, noUpload).promote).toBe(false);
  });

  it('does NOT promote on a library repo (no HTTP route entry point)', () => {
    expect(
      evaluateLaravelAlwaysOnRuntimePromotion({ depName: 'laravel/framework', summary: SIGNED_URL, hasHttpRouteEntryPoint: false, signals: monicaSignals() }).promote,
    ).toBe(false);
  });

  it('does NOT promote a non-laravel dep', () => {
    expect(
      evaluateLaravelAlwaysOnRuntimePromotion({ depName: 'guzzlehttp/guzzle', summary: SIGNED_URL, hasHttpRouteEntryPoint: true, signals: monicaSignals() }).promote,
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Feature-precondition demotion (the two-directional signed-URL gate)
// ---------------------------------------------------------------------------

describe('evaluateLaravelFeaturePreconditionDemotion', () => {
  const D = (summary: string, signals: LaravelFeatureSignals) =>
    evaluateLaravelFeaturePreconditionDemotion({ depName: 'laravel/framework', summary, signals });

  it('demotes the signed-URL CVE to unreachable when the app uses NO signed URLs (koel)', () => {
    const r = D(SIGNED_URL, koelSignals());
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('laravel-signed-url');
  });

  it('does NOT demote the signed-URL CVE when the app DOES use signed URLs (monica)', () => {
    expect(D(SIGNED_URL, monicaSignals()).demote).toBe(false);
  });

  it('refuses to demote when the code scan was truncated (absence unproven)', () => {
    const truncated = koelSignals({ truncated: true });
    expect(D(SIGNED_URL, truncated).demote).toBe(false);
  });

  it('refuses to demote an unrecognized (non-Laravel) project', () => {
    expect(D(SIGNED_URL, emptyLaravelFeatureSignals()).demote).toBe(false);
  });

  it('does NOT demote a CVE whose summary matches no precondition row', () => {
    expect(D('Laravel has a File Validation Bypass', koelSignals()).demote).toBe(false);
  });

  // The whole point of the two-directional gate: the SAME CVE demotes on koel and
  // is left for promotion on monica.
  it('is two-directional: signed-URL CVE demoted on koel, promoted on monica', () => {
    expect(D(SIGNED_URL, koelSignals()).demote).toBe(true);
    expect(D(SIGNED_URL, monicaSignals()).demote).toBe(false);
    expect(evaluateLaravelAlwaysOnRuntimePromotion({ depName: 'laravel/framework', summary: SIGNED_URL, hasHttpRouteEntryPoint: true, signals: monicaSignals() }).promoteTo).toBe('data_flow');
  });
});
