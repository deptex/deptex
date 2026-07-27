/**
 * T6b — route-level auth classification + span capture for the remaining JS/TS
 * detectors: Fastify (route-options hooks + same-scope addHook + encapsulation),
 * Koa (middle-arg middleware + `.unless(` carve-out + centralized
 * app.use-before-mount), NestJS (@UseGuards name-matched, ThrottlerGuard
 * neutral, @Public override, method spans). Next.js deliberately unchanged
 * (all-PUBLIC, no spans) — asserted here so a future change is a conscious one.
 *
 * Run: npx tsx test/framework-detector-js-auth.test.ts
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

async function detect(source: string, framework: string, virtualPath: string, deps: string[]): Promise<EntryPoint[]> {
  const file = await javascriptModule.extractFile(source, virtualPath, {
    deps: deps.map((d) => dep(d)), workspaceRoot: '/tmp',
  });
  return entryPointsFor(file, framework);
}

function byRoute(eps: EntryPoint[], pattern: string): EntryPoint | undefined {
  return eps.find((e) => e.routePattern === pattern);
}

async function run(): Promise<void> {
  // ==========================================================================
  console.log('\nFASTIFY — route-options hooks');
  // ==========================================================================
  {
    const eps = await detect(`
const fastify = require('fastify')({ logger: true });
fastify.get('/public', async (req, reply) => { return req.query.x; });
fastify.get('/admin', { preHandler: [fastify.authenticate] }, async (req, reply) => { return req.body.y; });
fastify.get('/on-req', { onRequest: requireAuth }, async (req, reply) => { return req.body.z; });
fastify.get('/soft', { preHandler: [optionalAuth] }, async (req, reply) => { return req.query.q; });
`, 'fastify', 'server.js', ['fastify']);
    eq(byRoute(eps, '/public')?.classification, 'PUBLIC_UNAUTH', 'no hooks → PUBLIC');
    eq(byRoute(eps, '/admin')?.classification, 'AUTH_INTERNAL', 'preHandler fastify.authenticate → AUTH_INTERNAL');
    eq(byRoute(eps, '/on-req')?.classification, 'AUTH_INTERNAL', 'onRequest requireAuth → AUTH_INTERNAL');
    eq(byRoute(eps, '/soft')?.classification, 'PUBLIC_UNAUTH', 'optionalAuth veto → PUBLIC');
    const admin = byRoute(eps, '/admin')!;
    assert(admin.handlerSpan != null, 'options-form route still captures the handler span');
    eq(admin.demotionEligible, true, 'inline async handler eligible');
  }

  console.log('\nFASTIFY — route({...}) config form');
  {
    const eps = await detect(`
const fastify = require('fastify')();
fastify.route({ method: 'POST', url: '/cfg', preHandler: verifyToken, handler: async (req) => req.body.a });
fastify.route({ method: 'GET', url: '/cfg-pub', handler: async (req) => req.query.b });
`, 'fastify', 'server.js', ['fastify']);
    eq(byRoute(eps, '/cfg')?.classification, 'AUTH_INTERNAL', 'route() preHandler verifyToken → AUTH_INTERNAL');
    eq(byRoute(eps, '/cfg-pub')?.classification, 'PUBLIC_UNAUTH', 'route() without hooks → PUBLIC');
    assert(byRoute(eps, '/cfg')!.handlerSpan != null, 'route() handler property span captured');
  }

  console.log('\nFASTIFY — addHook scoping (encapsulation)');
  {
    const eps = await detect(`
const app = require('fastify')();
app.get('/outside', async (req) => req.query.x);
function adminPlugin() {
  app.addHook('onRequest', app.authenticate);
  app.get('/inside', async (req) => req.body.y);
}
app.get('/outside2', async (req) => req.query.z);
`, 'fastify', 'server.js', ['fastify']);
    eq(byRoute(eps, '/inside')?.classification, 'AUTH_INTERNAL', 'route in the SAME scope as addHook → AUTH_INTERNAL');
    eq(byRoute(eps, '/outside')?.classification, 'PUBLIC_UNAUTH', 'top-level route NOT covered by function-scoped hook');
    eq(byRoute(eps, '/outside2')?.classification, 'PUBLIC_UNAUTH', 'second top-level route also uncovered (encapsulation)');
  }

  console.log('\nFASTIFY — top-level addHook covers top-level routes (order-independent) + belt');
  {
    const eps = await detect(`
const app = require('fastify')();
app.get('/early', async (req) => req.query.x);
app.addHook('preHandler', requireAuth);
app.get('/late', async (req) => req.body.y);
app.post('/login', async (req) => req.body.u);
`, 'fastify', 'server.js', ['fastify']);
    eq(byRoute(eps, '/early')?.classification, 'AUTH_INTERNAL', 'fastify hooks are order-independent within a context (route before addHook still covered)');
    eq(byRoute(eps, '/late')?.classification, 'AUTH_INTERNAL', 'route after addHook covered');
    eq(byRoute(eps, '/login')?.classification, 'PUBLIC_UNAUTH', 'belt: /login never inherits a context-hook demotion');
  }

  console.log('\nFASTIFY — conditional addHook does not cover (Sem 3)');
  {
    const eps = await detect(`
const app = require('fastify')();
if (process.env.REQUIRE_AUTH) {
  app.addHook('onRequest', requireAuth);
}
app.get('/maybe', async (req) => req.query.x);
`, 'fastify', 'server.js', ['fastify']);
    eq(byRoute(eps, '/maybe')?.classification, 'PUBLIC_UNAUTH', 'if-guarded addHook is not coverage');
  }

  // ==========================================================================
  console.log('\nKOA — middle-arg middleware');
  // ==========================================================================
  {
    const eps = await detect(`
const Koa = require('koa');
const Router = require('@koa/router');
const router = new Router();
router.get('/public', async (ctx) => { ctx.body = ctx.query.x; });
router.post('/admin', requireAuth, async (ctx) => { ctx.body = ctx.request.body.y; });
router.get('/anon', allowAnonymous, async (ctx) => { ctx.body = ctx.query.z; });
`, 'koa', 'server.js', ['koa', '@koa/router']);
    eq(byRoute(eps, '/public')?.classification, 'PUBLIC_UNAUTH', 'no middleware → PUBLIC');
    eq(byRoute(eps, '/admin')?.classification, 'AUTH_INTERNAL', 'middle-arg requireAuth → AUTH_INTERNAL');
    eq(byRoute(eps, '/anon')?.classification, 'PUBLIC_UNAUTH', 'allowAnonymous override → PUBLIC');
    const admin = byRoute(eps, '/admin')!;
    assert(admin.handlerSpan != null, 'koa handler span captured');
    eq(admin.demotionEligible, true, 'inline koa handler eligible');
  }

  console.log('\nKOA — centralized app.use before mount + .unless carve-out');
  {
    const eps = await detect(`
const Koa = require('koa');
const Router = require('@koa/router');
const jwt = require('koa-jwt');
const app = new Koa();
const router = new Router();
router.get('/covered', async (ctx) => { ctx.body = ctx.query.x; });
app.use(requireAuth);
app.use(router.routes());
`, 'koa', 'server.js', ['koa', '@koa/router', 'koa-jwt']);
    eq(byRoute(eps, '/covered')?.classification, 'AUTH_INTERNAL', 'app.use(auth) BEFORE mount covers router routes');
  }
  {
    const eps = await detect(`
const Koa = require('koa');
const Router = require('@koa/router');
const jwt = require('koa-jwt');
const app = new Koa();
const router = new Router();
router.get('/carved', async (ctx) => { ctx.body = ctx.query.x; });
app.use(jwt({ secret: 'x' }).unless({ path: ['/carved'] }));
app.use(router.routes());
`, 'koa', 'server.js', ['koa', '@koa/router', 'koa-jwt']);
    eq(byRoute(eps, '/carved')?.classification, 'PUBLIC_UNAUTH', '.unless(...) carve-out is NOT coverage (Sem 3)');
  }
  {
    const eps = await detect(`
const Koa = require('koa');
const Router = require('@koa/router');
const app = new Koa();
const router = new Router();
router.get('/late-auth', async (ctx) => { ctx.body = ctx.query.x; });
app.use(router.routes());
app.use(requireAuth);
`, 'koa', 'server.js', ['koa', '@koa/router']);
    eq(byRoute(eps, '/late-auth')?.classification, 'PUBLIC_UNAUTH', 'app.use(auth) AFTER the mount does not cover');
  }

  // ==========================================================================
  console.log('\nNESTJS — @UseGuards / @Public / ThrottlerGuard / spans');
  // ==========================================================================
  {
    const src = `
import { Controller, Get, Post, UseGuards } from '@nestjs/common';

@Controller('users')
export class UsersController {
  @Get('open')
  open(@Query('x') x: string) {
    return x;
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  me(@Query('y') y: string) {
    return y;
  }

  @UseGuards(ThrottlerGuard)
  @Get('throttled')
  throttled(@Query('z') z: string) {
    return z;
  }

  @UseGuards(OptionalJwtAuthGuard)
  @Get('softie')
  softie(@Query('q') q: string) {
    return q;
  }
}
`;
    const eps = await detect(src, 'nestjs', 'src/users.controller.ts', ['@nestjs/common']);
    eq(byRoute(eps, '/users/open')?.classification, 'PUBLIC_UNAUTH', 'no guard → PUBLIC');
    eq(byRoute(eps, '/users/me')?.classification, 'AUTH_INTERNAL', '@UseGuards(JwtAuthGuard) → AUTH_INTERNAL');
    eq(byRoute(eps, '/users/throttled')?.classification, 'PUBLIC_UNAUTH', 'ThrottlerGuard is neutral (rate limit ≠ auth)');
    eq(byRoute(eps, '/users/softie')?.classification, 'PUBLIC_UNAUTH', 'OptionalJwtAuthGuard vetoed (optional)');
    const me = byRoute(eps, '/users/me')!;
    assert(me.handlerSpan != null, 'method span captured');
    eq(me.demotionEligible, true, 'declaration-bound family always eligible');
    assert(me.handlerSpan!.startLine < me.handlerSpan!.endLine, 'span covers the method body');
  }

  console.log('\nNESTJS — class-level guard + method-level @Public override');
  {
    const src = `
import { Controller, Get, UseGuards } from '@nestjs/common';

@Controller('admin')
@UseGuards(JwtAuthGuard)
export class AdminController {
  @Get('dashboard')
  dashboard(@Query('x') x: string) {
    return x;
  }

  @Public()
  @Get('status')
  status() {
    return 'ok';
  }
}
`;
    const eps = await detect(src, 'nestjs', 'src/admin.controller.ts', ['@nestjs/common']);
    eq(byRoute(eps, '/admin/dashboard')?.classification, 'AUTH_INTERNAL', 'class-level @UseGuards covers methods');
    eq(byRoute(eps, '/admin/status')?.classification, 'PUBLIC_UNAUTH', 'method-level @Public() beats class guard (Sem 2)');
  }

  console.log("\nNESTJS — AuthGuard('jwt') call form + anonymous strategy veto");
  {
    const src = `
import { Controller, Get, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Controller('a')
export class AController {
  @UseGuards(AuthGuard('jwt'))
  @Get('jwt')
  jwt(@Query('x') x: string) { return x; }

  @UseGuards(AuthGuard('anonymous'))
  @Get('anon')
  anon(@Query('y') y: string) { return y; }
}
`;
    const eps = await detect(src, 'nestjs', 'src/a.controller.ts', ['@nestjs/common', '@nestjs/passport']);
    eq(byRoute(eps, '/a/jwt')?.classification, 'AUTH_INTERNAL', "AuthGuard('jwt') → AUTH_INTERNAL");
    eq(byRoute(eps, '/a/anon')?.classification, 'PUBLIC_UNAUTH', "AuthGuard('anonymous') vetoed");
  }

  // ==========================================================================
  console.log('\nNEXTJS — stays all-PUBLIC, no spans (deliberate cut)');
  // ==========================================================================
  {
    const file = await javascriptModule.extractFile(
      `export default async function handler(req, res) { res.json({ q: req.query.q }); }\n`,
      '/tmp/pages/api/echo.ts',
      { deps: [dep('next')], workspaceRoot: '/tmp' },
    );
    const eps = entryPointsFor(file, 'nextjs');
    eq(eps.length, 1, 'pages/api route detected');
    eq(eps[0].classification, 'PUBLIC_UNAUTH', 'nextjs stays PUBLIC');
    eq(eps[0].handlerSpan ?? null, null, 'nextjs captures no span (flows stamp unmatched)');
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });
