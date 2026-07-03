/**
 * Flask/FastAPI framework reachability model (7th model). Two-directional,
 * feature-gated: the SAME rows promote a request-path CVE on the matching app
 * and stay silent on the opposite-shape app. Grounded in the FlaskBB (Flask-WTF
 * forms) and fastapi-realworld (pure-JSON, JWT auth) blind-triage ground truth.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  emptyFlaskFeatureSignals,
  evaluateFlaskFeaturePreconditionDemotion,
  evaluateFlaskAlwaysOnRuntimePromotion,
  evaluateFlaskDevOnlyDemotion,
  gatherFlaskFeatureSignals,
  type FlaskFeatureSignals,
} from '../reachability-flask-preconditions';
import { updateReachabilityLevels } from '../reachability';
import type { Storage } from '../storage';

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

// ---------------------------------------------------------------------------
// gatherFlaskFeatureSignals — filesystem extraction. The pure eval tests above
// inject signals directly; these exercise the workspace reader that DERIVES them
// (recognition, usesForms incl. Flask-RESTful reqparse, usesH11 incl. the
// uvicorn[standard] dead-guard fix, usesEmailValidation, dev-scope).
// ---------------------------------------------------------------------------

describe('gatherFlaskFeatureSignals — extraction', () => {
  let root = '';
  afterEach(() => {
    if (root) { try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* ignore */ } root = ''; }
  });
  const workspace = (files: Record<string, string>): string => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'flask-precond-'));
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(root, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return root;
  };

  it('recognizes a Flask app (requirements.txt + wsgi.py) and detects WTForms forms', () => {
    const s = gatherFlaskFeatureSignals(workspace({
      'requirements.txt': 'Flask==2.0.1\nWerkzeug==2.0.1\nemail-validator==1.1.3\n',
      'wsgi.py': 'from myapp import app\n',
      'myapp/forms.py': 'from flask_wtf import FlaskForm\nfrom wtforms import StringField\nclass LoginForm(FlaskForm):\n    email = StringField()\n',
    }));
    expect(s.recognized).toBe(true);
    expect(s.framework).toBe('flask');
    expect(s.usesForms).toBe(true);
    expect(s.usesEmailValidation).toBe(true);
  });

  it('recognizes a FastAPI app; usesH11 true for plain uvicorn, usesForms false (pure JSON)', () => {
    const s = gatherFlaskFeatureSignals(workspace({
      'pyproject.toml': '[tool.poetry.dependencies]\nfastapi = "^0.79.1"\nuvicorn = "^0.18.2"\npydantic = "^1.9"\n',
      'app/main.py': 'from fastapi import FastAPI\napp = FastAPI()\n',
      'app/schemas.py': 'from pydantic import BaseModel, EmailStr\nclass User(BaseModel):\n    email: EmailStr\n',
    }));
    expect(s.recognized).toBe(true);
    expect(s.framework).toBe('fastapi');
    expect(s.usesForms).toBe(false);
    expect(s.usesH11).toBe(true);
    expect(s.usesEmailValidation).toBe(true);
  });

  it('usesH11 is FALSE when uvicorn[standard] pulls httptools transitively (dead-guard fix)', () => {
    const s = gatherFlaskFeatureSignals(workspace({
      'requirements.txt': 'fastapi>=0.79\nuvicorn[standard]>=0.18\n',
      'app/main.py': 'from fastapi import FastAPI\napp = FastAPI()\n',
    }));
    expect(s.usesH11).toBe(false);
  });

  it('usesForms detects Flask-RESTful reqparse file uploads (broadened markers)', () => {
    const s = gatherFlaskFeatureSignals(workspace({
      'requirements.txt': 'Flask==2.0.1\nFlask-RESTful==0.3.9\n',
      'app.py': 'from flask import Flask\napp = Flask(__name__)\n',
      'resources.py': "from flask_restful import reqparse\nparser = reqparse.RequestParser()\nparser.add_argument('avatar', location='files')\n",
    }));
    expect(s.usesForms).toBe(true);
  });

  it('recognizes a pure-Starlette app instantiated as Starlette(routes=...) with no asgi.py', () => {
    const s = gatherFlaskFeatureSignals(workspace({
      'requirements.txt': 'starlette>=0.19\nuvicorn>=0.18\n',
      'app.py': 'from starlette.applications import Starlette\napp = Starlette(routes=[])\n',
    }));
    expect(s.recognized).toBe(true);
    expect(s.framework).toBe('fastapi');
  });

  it('classifies poetry dev-dependencies as dev-scope', () => {
    const s = gatherFlaskFeatureSignals(workspace({
      'pyproject.toml': '[tool.poetry.dependencies]\nfastapi = "^0.79"\n\n[tool.poetry.dev-dependencies]\npytest = "^7.1"\n',
      'app/main.py': 'from fastapi import FastAPI\napp = FastAPI()\n',
    }));
    expect(s.devDeps.has('pytest')).toBe(true);
    expect(s.depUniverse.has('fastapi')).toBe(true);
  });

  it('refuses recognition for a non-Flask/FastAPI project (cannot-reason sentinel)', () => {
    const s = gatherFlaskFeatureSignals(workspace({
      'requirements.txt': 'django==4.2\n',
      'manage.py': 'import django\n',
    }));
    expect(s.recognized).toBe(false);
  });

  it('returns the empty sentinel for a missing root', () => {
    expect(gatherFlaskFeatureSignals(undefined).recognized).toBe(false);
    expect(gatherFlaskFeatureSignals('/no/such/path/does-not-exist-xyz').recognized).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// updateReachabilityLevels — the Flask orphan-floor override. A finding floored
// at orphan_transitive_unreachable may be promoted ONLY by a rule flagged
// overridesOrphanFloor (idna-encode, where email-validator→idna.encode is a fixed
// transitive consumer). A rule whose signal a DIFFERENT library could satisfy
// (pyjwt via python-jose) must NOT surface an unused orphan pin.
// ---------------------------------------------------------------------------

interface TableState { rows: any[] }
class FakeStorage {
  tables: Record<string, TableState> = {};
  updates: Array<{ table: string; filter: Record<string, unknown>; values: any }> = [];
  set(table: string, rows: any[]) { this.tables[table] = { rows }; }
  from(table: string): any {
    const state = this.tables[table] ?? { rows: [] };
    const filters: Array<{ col: string; val: unknown }> = [];
    const filterRows = () => { let rows = state.rows; for (const f of filters) rows = rows.filter((r) => r[f.col] === f.val); return rows; };
    const builder: any = {
      select() { return builder; },
      eq(col: string, val: unknown) { filters.push({ col, val }); return builder; },
      in() { return builder; },
      maybeSingle() { return Promise.resolve({ data: filterRows()[0] ?? null, error: null }); },
      single() { const rows = filterRows(); return Promise.resolve({ data: rows[0] ?? null, error: rows.length === 0 ? { code: 'PGRST116', message: 'not found' } : null }); },
      insert: () => Promise.resolve({ data: null, error: null }),
      upsert: (rows: any) => { const arr = Array.isArray(rows) ? rows : [rows]; for (const r of arr) this.updates.push({ table, filter: { id: r.id }, values: r }); return Promise.resolve({ data: null, error: null }); },
      then(onFulfilled: any) { return Promise.resolve({ data: filterRows(), error: null }).then(onFulfilled); },
    };
    return builder;
  }
}
const wlog = { info: jest.fn().mockResolvedValue(undefined), success: jest.fn().mockResolvedValue(undefined), warn: jest.fn().mockResolvedValue(undefined), error: jest.fn().mockResolvedValue(undefined) };
const P_ID = 'proj-f'; const R_ID = 'run-f';

/** Seed one pypi dep + one PDV. is_direct:true + files_importing 0 → the classifier floors it at orphan_transitive_unreachable. */
function seedDep(fsk: FakeStorage, opts: { name: string; osvId: string; summary: string; isDirect: boolean }) {
  fsk.set('project_dependency_vulnerabilities', [
    { id: 'pdv-1', project_dependency_id: 'pd-1', project_id: P_ID, extraction_run_id: R_ID, osv_id: opts.osvId, aliases: [], summary: opts.summary },
  ]);
  fsk.set('project_dependencies', [
    { id: 'pd-1', project_id: P_ID, last_seen_extraction_run_id: R_ID, dependency_id: 'dep-1', dependency_version_id: 'dv-1', is_direct: opts.isDirect, files_importing_count: 0, environment: null, name: opts.name, namespace: null },
  ]);
  fsk.set('project_reachable_flows', []);
  fsk.set('project_reachable_flow_suppressions', []);
  fsk.set('dependency_version_edges', []);
  fsk.set('project_usage_slices', []);
}
function levelOf(fsk: FakeStorage): { level?: string; details?: any } {
  const u = fsk.updates.find((x) => x.table === 'project_dependency_vulnerabilities' && x.filter.id === 'pdv-1' && 'reachability_level' in x.values);
  return { level: u?.values.reachability_level, details: u?.values.reachability_details };
}
const flaskSignals = (over: Partial<FlaskFeatureSignals> = {}): FlaskFeatureSignals => ({
  ...emptyFlaskFeatureSignals(), recognized: true, framework: 'fastapi', isDeployedWebApp: true, ...over,
});

describe('updateReachabilityLevels — Flask orphan-floor override', () => {
  beforeEach(() => jest.clearAllMocks());

  it('PROMOTES an orphan idna finding (overridable rule) to data_flow when the app validates request emails', async () => {
    const fsk = new FakeStorage();
    seedDep(fsk, { name: 'idna', osvId: 'CVE-2026-45409', summary: 'Internationalized Domain Names in Applications (IDNA): specific inputs', isDirect: true });
    await updateReachabilityLevels(P_ID, R_ID, fsk as unknown as Storage, wlog, undefined, {
      ecosystem: 'pypi',
      flaskFeatureSignals: flaskSignals({ usesEmailValidation: true, depUniverse: new Set(['fastapi', 'email-validator', 'idna']) }),
      httpEntryPointCount: 5,
    } as any);
    const { level, details } = levelOf(fsk);
    expect(level).toBe('data_flow');
    expect(details?.sink).toBe('idna-encode');
    expect(details?.promoted_from).toBe('orphan_transitive_unreachable');
  });

  it('does NOT promote an orphan PyJWT finding whose usesJwtAuth is satisfied by a DIFFERENT library (cross-dep FP guard)', async () => {
    const fsk = new FakeStorage();
    seedDep(fsk, { name: 'pyjwt', osvId: 'CVE-2026-32597', summary: 'PyJWT accepts unknown `crit` header extensions', isDirect: true });
    await updateReachabilityLevels(P_ID, R_ID, fsk as unknown as Storage, wlog, undefined, {
      ecosystem: 'pypi',
      // usesJwtAuth true (e.g. python-jose provides auth), but PyJWT itself is an unused orphan pin.
      flaskFeatureSignals: flaskSignals({ usesJwtAuth: true, depUniverse: new Set(['fastapi', 'python-jose', 'pyjwt']) }),
      httpEntryPointCount: 5,
    } as any);
    // pyjwt-crit-decode is NOT overridesOrphanFloor → the orphan floor holds.
    expect(levelOf(fsk).level).toBe('unreachable');
  });
});
