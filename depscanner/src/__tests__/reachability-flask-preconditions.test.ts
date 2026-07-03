/**
 * Flask/FastAPI framework reachability model (7th model). Two-directional,
 * feature-gated: the SAME rows promote a request-path CVE on the matching app
 * and stay silent on the opposite-shape app. Grounded in the FlaskBB (Flask-WTF
 * forms) and fastapi-realworld (pure-JSON, JWT auth) blind-triage ground truth.
 */

import {
  emptyFlaskFeatureSignals,
  evaluateFlaskFeaturePreconditionDemotion,
  evaluateFlaskAlwaysOnRuntimePromotion,
  evaluateFlaskDevOnlyDemotion,
  type FlaskFeatureSignals,
} from '../reachability-flask-preconditions';

function flaskbb(): FlaskFeatureSignals {
  return {
    ...emptyFlaskFeatureSignals(),
    recognized: true,
    framework: 'flask',
    isDeployedWebApp: true,
    usesForms: true,
    usesEmailValidation: true,
    depUniverse: new Set(['flask', 'werkzeug', 'email-validator']),
  };
}
function realworld(): FlaskFeatureSignals {
  return {
    ...emptyFlaskFeatureSignals(),
    recognized: true,
    framework: 'fastapi',
    isDeployedWebApp: true,
    usesForms: false,
    usesJwtAuth: true,
    usesH11: true,
    usesEmailValidation: true,
    depUniverse: new Set(['fastapi', 'starlette', 'pydantic', 'uvicorn', 'pyjwt', 'h11', 'email-validator']),
  };
}
const promote = (dep: string, osv: string, summary: string, s: FlaskFeatureSignals) =>
  evaluateFlaskAlwaysOnRuntimePromotion({ depName: dep, summary, osvIds: [osv], deployedWebApp: true, signals: s });
const demote = (dep: string, osv: string, summary: string, s: FlaskFeatureSignals) =>
  evaluateFlaskFeaturePreconditionDemotion({ depName: dep, summary, osvIds: [osv], signals: s });

describe('Flask model — FlaskBB (Flask-WTF forms present)', () => {
  it('promotes the Werkzeug multipart-parser DoS to data_flow when forms are present', () => {
    const r = promote('werkzeug', 'CVE-2023-46136', 'Werkzeug DoS: High resource usage when parsing multipart form data', flaskbb());
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('data_flow');
  });
  it('does NOT demote the multipart CVE when forms are present', () => {
    expect(demote('werkzeug', 'CVE-2023-46136', '... parsing multipart form data', flaskbb()).demote).toBe(false);
  });
  it('does NOT promote the Werkzeug nameless-cookie confusion CVE (adversarially refuted → stays module)', () => {
    expect(promote('werkzeug', 'CVE-2023-23934', 'Incorrect parsing of nameless cookies leads to __Host- confusion', flaskbb()).promote).toBe(false);
  });
});

describe('Flask model — fastapi-realworld (pure-JSON, no forms, JWT auth)', () => {
  it('demotes the fastapi multipart Content-Type ReDoS by ID when no forms (functionSafe)', () => {
    const r = demote('fastapi', 'CVE-2024-24762', 'FastAPI is a web framework for building APIs', realworld());
    expect(r.demote).toBe(true);
    expect(r.functionSafe).toBe(true);
  });
  it('promotes the h11 request-parser CVE when uvicorn has no httptools', () => {
    expect(promote('h11', 'CVE-2025-43859', 'h11 accepts some malformed Chunked-Encoding bodies', realworld()).promote).toBe(true);
  });
  it('promotes pydantic email ReDoS + idna encode when request emails validate', () => {
    expect(promote('pydantic', 'CVE-2024-3772', 'Pydantic regular expression denial of service', realworld()).promote).toBe(true);
    expect(promote('idna', 'CVE-2026-45409', 'Internationalized Domain Names in Applications (IDNA): Specific', realworld()).promote).toBe(true);
  });
  it('promotes the PyJWT crit-header CVE but NOT the PyJWKClient siblings', () => {
    expect(promote('pyjwt', 'CVE-2026-32597', 'PyJWT accepts unknown `crit` header extensions', realworld()).promote).toBe(true);
    expect(promote('pyjwt', 'CVE-2026-48522', 'PyJWKClient: missing scheme allowlist enables SSRF', realworld()).promote).toBe(false);
  });
  it('does NOT promote the Starlette multipart CVE on a pure-JSON API (no forms)', () => {
    expect(promote('starlette', 'CVE-2024-47874', 'Starlette Denial of service via multipart/form-data', realworld()).promote).toBe(false);
  });
});

describe('Flask model — guards', () => {
  it('refuses every promotion/demotion when signals are unrecognized', () => {
    const unrec = { ...flaskbb(), recognized: false };
    expect(promote('werkzeug', 'CVE-2023-23934', 'nameless cookie', unrec).promote).toBe(false);
    expect(demote('fastapi', 'CVE-2024-24762', 'FastAPI is a web framework', { ...realworld(), recognized: false }).demote).toBe(false);
  });
  it('demotes a dev-only manifest dependency', () => {
    const s = { ...realworld(), devDeps: new Set(['pytest']), depUniverse: new Set(['fastapi', 'pytest']) };
    expect(evaluateFlaskDevOnlyDemotion({ depName: 'pytest', signals: s }).demote).toBe(true);
    expect(evaluateFlaskDevOnlyDemotion({ depName: 'fastapi', signals: s }).demote).toBe(false);
  });
});
