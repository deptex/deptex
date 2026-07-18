/**
 * T7c — route-level auth classification + spans for the Python decorator
 * detectors: Flask (@login_required/@jwt_required co-decorators + optional
 * veto), FastAPI (Depends/Security param + decorator + router dependencies,
 * optional-target veto, belt on router-level auth), Starlette (@requires).
 *
 * Run: npx tsx test/framework-detector-python-auth.test.ts
 */
import { pythonModule } from '../src/tree-sitter-extractor/languages/python';
import { entryPointsFor, dep } from '../src/framework-rules/test-helpers';
import type { EntryPoint } from '../src/framework-rules/types';

let failures = 0;
let passes = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) { console.error(`  FAIL: ${msg}`); failures++; }
  else { console.log(`  ok: ${msg}`); passes++; }
}
function eq(a: unknown, b: unknown, msg: string): void {
  assert(JSON.stringify(a) === JSON.stringify(b), `${msg} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`);
}

async function detect(source: string, framework: string, deps: string[]): Promise<EntryPoint[]> {
  const file = await pythonModule.extractFile(source, 'app/main.py', {
    deps: deps.map((d) => dep(d)), workspaceRoot: '/tmp',
  });
  return entryPointsFor(file, framework);
}

function byRoute(eps: EntryPoint[], pattern: string): EntryPoint | undefined {
  return eps.find((e) => e.routePattern === pattern);
}

async function run(): Promise<void> {
  // ==========================================================================
  console.log('\nFLASK — co-decorator evidence');
  // ==========================================================================
  {
    const eps = await detect(`
from flask import Flask, request
from flask_login import login_required
from flask_jwt_extended import jwt_required

app = Flask(__name__)

@app.route('/open')
def open_view():
    return request.args.get('q')

@app.route('/me')
@login_required
def me():
    return request.args.get('q')

@app.post('/admin')
@jwt_required()
def admin():
    return request.form['x']

@app.get('/soft')
@jwt_required(optional=True)
def soft():
    return request.args.get('q')

@app.get('/decorated')
@cache.cached(timeout=60)
def decorated():
    return request.args.get('q')
`, 'flask', ['flask', 'flask-login', 'flask-jwt-extended']);
    eq(byRoute(eps, '/open')?.classification, 'PUBLIC_UNAUTH', 'no co-decorator → PUBLIC (import sniff retired)');
    eq(byRoute(eps, '/me')?.classification, 'AUTH_INTERNAL', '@login_required → AUTH_INTERNAL');
    eq(byRoute(eps, '/admin')?.classification, 'AUTH_INTERNAL', '@jwt_required() → AUTH_INTERNAL');
    eq(byRoute(eps, '/soft')?.classification, 'PUBLIC_UNAUTH', '@jwt_required(optional=True) vetoed (Sem 4)');
    eq(byRoute(eps, '/decorated')?.classification, 'PUBLIC_UNAUTH', 'non-auth co-decorator stays PUBLIC');
    const me = byRoute(eps, '/me')!;
    assert(me.handlerSpan != null, 'flask view span captured');
    eq(me.demotionEligible, true, 'flask declaration-bound eligible');
  }

  // ==========================================================================
  console.log('\nFASTAPI — Depends / Security evidence');
  // ==========================================================================
  {
    const eps = await detect(`
from fastapi import FastAPI, Depends, Security

app = FastAPI()

@app.get('/open')
async def open_route(q: str):
    return q

@app.get('/me')
async def me(user = Depends(get_current_user)):
    return user

@app.get('/verified', dependencies=[Depends(verify_token)])
async def verified(q: str):
    return q

@app.get('/scoped')
async def scoped(user = Security(get_current_user, scopes=['items'])):
    return user

@app.get('/maybe')
async def maybe(user = Depends(get_current_user_optional)):
    return user

@app.get('/db')
async def with_db(db = Depends(get_db)):
    return 'x'
`, 'fastapi', ['fastapi']);
    eq(byRoute(eps, '/open')?.classification, 'PUBLIC_UNAUTH', 'no dependency → PUBLIC');
    eq(byRoute(eps, '/me')?.classification, 'AUTH_INTERNAL', 'Depends(get_current_user) → AUTH_INTERNAL');
    eq(byRoute(eps, '/verified')?.classification, 'AUTH_INTERNAL', 'decorator dependencies=[Depends(verify_token)] → AUTH_INTERNAL');
    eq(byRoute(eps, '/scoped')?.classification, 'AUTH_INTERNAL', 'Security(...) is always an auth requirement');
    eq(byRoute(eps, '/maybe')?.classification, 'PUBLIC_UNAUTH', 'Depends(get_current_user_optional) vetoed');
    eq(byRoute(eps, '/db')?.classification, 'PUBLIC_UNAUTH', 'Depends(get_db) is not auth-shaped');
    const me = byRoute(eps, '/me')!;
    assert(me.handlerSpan != null, 'fastapi handler span captured');
    eq(me.demotionEligible, true, 'fastapi declaration-bound eligible');
  }

  console.log('\nFASTAPI — router-level dependencies (centralized + belt)');
  {
    const eps = await detect(`
from fastapi import APIRouter, Depends

router = APIRouter(dependencies=[Depends(oauth2_scheme)])

@router.get('/dashboard')
async def dashboard(q: str):
    return q

@router.post('/login')
async def login(q: str):
    return q
`, 'fastapi', ['fastapi']);
    eq(byRoute(eps, '/dashboard')?.classification, 'AUTH_INTERNAL', 'router-level Depends(oauth2_scheme) covers routes');
    eq(byRoute(eps, '/login')?.classification, 'PUBLIC_UNAUTH', 'belt: /login never inherits router-level (centralized) auth');
  }

  // ==========================================================================
  console.log('\nSTARLETTE — @requires');
  // ==========================================================================
  {
    const eps = await detect(`
from starlette.applications import Starlette
from starlette.authentication import requires

app = Starlette()

@app.route('/open')
async def open_route(request):
    return None

@app.route('/me')
@requires('authenticated')
async def me(request):
    return None
`, 'starlette', ['starlette']);
    eq(byRoute(eps, '/open')?.classification, 'PUBLIC_UNAUTH', 'no @requires → PUBLIC');
    eq(byRoute(eps, '/me')?.classification, 'AUTH_INTERNAL', "@requires('authenticated') → AUTH_INTERNAL");
    const me = byRoute(eps, '/me')!;
    assert(me.handlerSpan != null, 'starlette handler span captured');
    eq(me.demotionEligible, true, 'starlette declaration-bound eligible');
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });
