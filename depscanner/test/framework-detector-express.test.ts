/**
 * Unit tests for the Express detector's route-level auth classification + handler
 * span capture (entry-point auth classification, T6a).
 *
 * Runs the real JS tree-sitter module + detector over inline source. Covers the
 * per-detector required cases: -authed / -public / -override / -conditional /
 * -unknown-middleware / -machine-evidence / -belt / -span, plus centralized
 * app.use() coverage (pathless + prefix + ordering) and the demotion-eligibility
 * guard (exported / referenced named handlers stay eligible=false).
 *
 * Run: npx tsx test/framework-detector-express.test.ts
 */
import { javascriptModule } from '../src/tree-sitter-extractor/languages/javascript';
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

async function detect(source: string): Promise<EntryPoint[]> {
  const file = await javascriptModule.extractFile(source, 'routes/api.js', {
    deps: [dep('express')], workspaceRoot: '/tmp',
  });
  return entryPointsFor(file, 'express');
}

/** Find the entry point whose route pattern matches. */
function byRoute(eps: EntryPoint[], pattern: string): EntryPoint | undefined {
  return eps.find((e) => e.routePattern === pattern);
}

async function run(): Promise<void> {
  console.log('\nroute-local classification (Sem 1/2/4/8)');
  {
    const eps = await detect(`
const express = require('express');
const router = express.Router();
router.get('/public', (req, res) => { res.send(req.query.x); });
router.post('/admin', requireAuth, (req, res) => { res.send(req.body.y); });
router.get('/anon', allowAnonymous, (req, res) => { res.send(req.query.z); });
router.get('/soft', jwtOptional, (req, res) => { res.send(req.query.q); });
module.exports = router;
`);
    eq(byRoute(eps, '/public')?.classification, 'PUBLIC_UNAUTH', 'no middleware → PUBLIC');
    eq(byRoute(eps, '/admin')?.classification, 'AUTH_INTERNAL', 'requireAuth → AUTH_INTERNAL');
    eq(byRoute(eps, '/anon')?.classification, 'PUBLIC_UNAUTH', 'allowAnonymous override → PUBLIC');
    eq(byRoute(eps, '/soft')?.classification, 'PUBLIC_UNAUTH', 'jwtOptional veto → PUBLIC');
  }

  console.log('\nunknown middleware stays PUBLIC (Sem 8 — non-auth name)');
  {
    const eps = await detect(`
const express = require('express');
const app = express();
app.get('/x', compression(), (req, res) => { res.send(req.query.x); });
`);
    eq(byRoute(eps, '/x')?.classification, 'PUBLIC_UNAUTH', 'compression() is not auth → PUBLIC');
  }

  console.log('\npassport anonymous arg veto (Sem 4)');
  {
    const eps = await detect(`
const express = require('express');
const app = express();
app.get('/maybe', passport.authenticate('anonymous'), (req, res) => { res.send(req.query.x); });
app.get('/real', passport.authenticate('jwt'), (req, res) => { res.send(req.query.y); });
`);
    eq(byRoute(eps, '/maybe')?.classification, 'PUBLIC_UNAUTH', "passport.authenticate('anonymous') → PUBLIC (arg veto)");
    eq(byRoute(eps, '/real')?.classification, 'AUTH_INTERNAL', "passport.authenticate('jwt') → AUTH_INTERNAL");
  }

  console.log('\ncentralized app.use() coverage (Sem 1b/11) + ordering');
  {
    const eps = await detect(`
const express = require('express');
const app = express();
app.get('/before', (req, res) => { res.send(req.query.x); });
app.use(requireAuth);
app.get('/after', (req, res) => { res.send(req.query.y); });
app.get('/after2', (req, res) => { res.send(req.query.z); });
`);
    eq(byRoute(eps, '/before')?.classification, 'PUBLIC_UNAUTH', 'route BEFORE app.use(auth) stays PUBLIC (ordering)');
    eq(byRoute(eps, '/after')?.classification, 'AUTH_INTERNAL', 'route AFTER app.use(auth) → AUTH_INTERNAL');
    eq(byRoute(eps, '/after2')?.classification, 'AUTH_INTERNAL', 'second route after app.use(auth) → AUTH_INTERNAL');
  }

  console.log('\ncentralized prefix is segment-bounded (Sem 11)');
  {
    const eps = await detect(`
const express = require('express');
const app = express();
app.use('/api', requireAuth);
app.get('/api/users', (req, res) => { res.send(req.query.x); });
app.get('/apiv2/users', (req, res) => { res.send(req.query.y); });
app.get('/public', (req, res) => { res.send(req.query.z); });
`);
    eq(byRoute(eps, '/api/users')?.classification, 'AUTH_INTERNAL', 'prefix /api covers /api/users');
    eq(byRoute(eps, '/apiv2/users')?.classification, 'PUBLIC_UNAUTH', 'prefix /api does NOT cover /apiv2 (segment boundary)');
    eq(byRoute(eps, '/public')?.classification, 'PUBLIC_UNAUTH', 'prefix /api does NOT cover /public');
  }

  console.log('\nbelt blocks a purely-centralized demotion, not a route-local one (Sem 10)');
  {
    const eps = await detect(`
const express = require('express');
const app = express();
app.use(requireAuth);
app.post('/login', (req, res) => { res.send(req.body.u); });
app.get('/dashboard', (req, res) => { res.send(req.query.x); });
app.post('/login2', requireAuth, (req, res) => { res.send(req.body.u); });
`);
    eq(byRoute(eps, '/login')?.classification, 'PUBLIC_UNAUTH', 'centralized demotion blocked on /login belt route');
    eq(byRoute(eps, '/dashboard')?.classification, 'AUTH_INTERNAL', 'centralized demotion applies to non-belt route');
    eq(byRoute(eps, '/login2')?.classification, 'AUTH_INTERNAL', 'route-local auth STILL demotes a belt route');
  }

  console.log('\nmachine evidence → OFFLINE_WORKER (Sem 5)');
  {
    const eps = await detect(`
const express = require('express');
const app = express();
app.post('/hooks/qstash', verifyQstashSignature, (req, res) => { res.send(req.body.x); });
app.post('/hooks/inline', (req, res) => {
  const evt = stripe.webhooks.constructEvent(req.body, sig, secret);
  res.send(evt.id);
});
app.post('/hooks/github', (req, res) => { res.send(req.body.action); });
`);
    eq(byRoute(eps, '/hooks/qstash')?.classification, 'OFFLINE_WORKER', 'internal-name middleware → OFFLINE_WORKER');
    eq(byRoute(eps, '/hooks/inline')?.classification, 'OFFLINE_WORKER', 'inline constructEvent verifier → OFFLINE_WORKER');
    eq(byRoute(eps, '/hooks/github')?.classification, 'PUBLIC_UNAUTH', 'webhook path with NO verifier stays PUBLIC (Sem 5 negative)');
  }

  console.log('\nhandler span capture + demotion eligibility (Sem 6)');
  {
    const eps = await detect(`
const express = require('express');
const router = express.Router();
router.post('/inline', requireAuth, (req, res) => {
  const t = req.body.token;
  doReset(t);
});
function resetHandler(req, res) {
  res.send(req.body.token);
}
router.post('/named', requireAuth, resetHandler);
router.post('/exported', requireAuth, exportedHandler);
function exportedHandler(req, res) { res.send(req.body.x); }
module.exports = { exportedHandler };
`);
    const inline = byRoute(eps, '/inline')!;
    assert(inline.handlerSpan != null, 'inline handler has a span');
    assert(inline.handlerSpan!.startLine < inline.handlerSpan!.endLine, 'inline span is multi-line');
    eq(inline.demotionEligible, true, 'inline handler is demotion-eligible');

    const named = byRoute(eps, '/named')!;
    assert(named.handlerSpan != null, 'named same-file handler resolves a span');
    eq(named.demotionEligible, true, 'unexported single-registration named handler is eligible');

    const exported = byRoute(eps, '/exported')!;
    // Span resolves, but the handler is exported → ineligible (re-mountable).
    eq(exported.demotionEligible, false, 'exported named handler is demotion-INELIGIBLE');
  }

  console.log('\nmember-expression handler → null span (never demotes)');
  {
    const eps = await detect(`
const express = require('express');
const router = express.Router();
router.get('/ctrl', requireAuth, ctrl.renderSearch);
`);
    const ctrl = byRoute(eps, '/ctrl')!;
    eq(ctrl.classification, 'AUTH_INTERNAL', 'route still classifies from evidence');
    eq(ctrl.handlerSpan ?? null, null, 'member-expression handler → null span');
    eq(ctrl.demotionEligible, false, 'null span → not demotion-eligible');
  }

  console.log('\nrouter mount (.use with path + router) is a coarse public row, no span');
  {
    const eps = await detect(`
const express = require('express');
const app = express();
const api = express.Router();
app.use('/api', requireAuth, api);
`);
    const mount = byRoute(eps, '/api');
    if (mount) {
      eq(mount.handlerSpan ?? null, null, 'mount row has no handler span');
      eq(mount.demotionEligible, false, 'mount row is not demotion-eligible');
    } else {
      assert(true, 'mount row optional — not emitted is also acceptable');
    }
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });
