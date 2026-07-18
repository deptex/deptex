/**
 * T7b — route-level auth classification + spans for the C# + PHP detectors:
 * ASP.NET Core ([Authorize]/[AllowAnonymous], combine-not-replace), Minimal APIs
 * (.RequireAuthorization()/.AllowAnonymous() chains), Symfony (#[IsGranted] +
 * PUBLIC_ACCESS + docblock @IsGranted), Laravel (chained + group middleware,
 * withoutMiddleware, belt), Slim (->add() chains + groups).
 *
 * Run: npx tsx test/framework-detector-csharp-php-auth.test.ts
 */
import { csharpModule } from '../src/tree-sitter-extractor/languages/csharp';
import { phpModule } from '../src/tree-sitter-extractor/languages/php';
import { entryPointsFor, dep } from '../src/framework-rules/test-helpers';
import type { EntryPoint } from '../src/framework-rules/types';
import type { LanguageModule } from '../src/tree-sitter-extractor/languages/types';

let failures = 0;
let passes = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) { console.error(`  FAIL: ${msg}`); failures++; }
  else { console.log(`  ok: ${msg}`); passes++; }
}
function eq(a: unknown, b: unknown, msg: string): void {
  assert(JSON.stringify(a) === JSON.stringify(b), `${msg} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`);
}

async function detect(mod: LanguageModule, source: string, framework: string, virtualPath: string, deps: string[] = []): Promise<EntryPoint[]> {
  const file = await mod.extractFile(source, virtualPath, {
    deps: deps.map((d) => dep(d)), workspaceRoot: '/tmp',
  });
  return entryPointsFor(file, framework);
}

function byRoute(eps: EntryPoint[], pattern: string): EntryPoint | undefined {
  return eps.find((e) => e.routePattern === pattern);
}

async function run(): Promise<void> {
  // ==========================================================================
  console.log('\nASP.NET CORE — [Authorize] / [AllowAnonymous]');
  // ==========================================================================
  {
    const eps = await detect(csharpModule, `
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

[ApiController]
[Route("api/users")]
public class UsersController : ControllerBase {
  [HttpGet("open")]
  public string Open(string q) { return q; }

  [Authorize]
  [HttpGet("me")]
  public string Me(string q) { return q; }
}
`, 'aspnet-core', 'Controllers/UsersController.cs');
    eq(byRoute(eps, '/api/users/open')?.classification, 'PUBLIC_UNAUTH', 'no attribute → PUBLIC');
    eq(byRoute(eps, '/api/users/me')?.classification, 'AUTH_INTERNAL', 'method [Authorize] → AUTH_INTERNAL');
    const me = byRoute(eps, '/api/users/me')!;
    assert(me.handlerSpan != null, 'method span captured');
    eq(me.demotionEligible, true, 'declaration-bound eligible');
  }
  {
    const eps = await detect(csharpModule, `
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

[ApiController]
[Route("api/admin")]
[Authorize(Roles = "Admin")]
public class AdminController : ControllerBase {
  [HttpGet("panel")]
  public string Panel(string q) { return q; }

  [AllowAnonymous]
  [HttpGet("status")]
  public string Status() { return "ok"; }
}
`, 'aspnet-core', 'Controllers/AdminController.cs');
    eq(byRoute(eps, '/api/admin/panel')?.classification, 'AUTH_INTERNAL', 'class [Authorize] covers methods');
    eq(byRoute(eps, '/api/admin/status')?.classification, 'PUBLIC_UNAUTH', 'method [AllowAnonymous] bypasses class [Authorize]');
  }

  // ==========================================================================
  console.log('\nMINIMAL APIS — fluent auth chains');
  // ==========================================================================
  {
    const eps = await detect(csharpModule, `
var app = WebApplication.Create();
app.MapGet("/open", (string q) => q);
app.MapGet("/me", (string q) => q).RequireAuthorization();
app.MapGet("/anon", (string q) => q).RequireAuthorization().AllowAnonymous();
app.MapPost("/named", CreateUser).RequireAuthorization();
`, 'minimal-apis', 'Program.cs');
    eq(byRoute(eps, '/open')?.classification, 'PUBLIC_UNAUTH', 'no chain → PUBLIC');
    eq(byRoute(eps, '/me')?.classification, 'AUTH_INTERNAL', '.RequireAuthorization() → AUTH_INTERNAL');
    eq(byRoute(eps, '/anon')?.classification, 'PUBLIC_UNAUTH', '.AllowAnonymous() beats .RequireAuthorization()');
    const me = byRoute(eps, '/me')!;
    assert(me.handlerSpan != null, 'lambda handler span captured');
    eq(me.demotionEligible, true, 'lambda eligible');
    const named = byRoute(eps, '/named')!;
    eq(named.classification, 'AUTH_INTERNAL', 'method-group route still classifies');
    eq(named.handlerSpan ?? null, null, 'method-group handler → null span (cross-file)');
    eq(named.demotionEligible, false, 'method-group → not demotion-eligible');
  }

  // ==========================================================================
  console.log('\nSYMFONY — #[IsGranted] attribute + PUBLIC_ACCESS');
  // ==========================================================================
  {
    const eps = await detect(phpModule, `<?php
namespace App\\Controller;

use Symfony\\Component\\Routing\\Annotation\\Route;
use Symfony\\Component\\Security\\Http\\Attribute\\IsGranted;

class AccountController
{
    #[Route('/account', methods: ['GET'])]
    #[IsGranted('ROLE_USER')]
    public function account(): Response
    {
        return $this->render('account.html.twig');
    }

    #[Route('/pricing', methods: ['GET'])]
    #[IsGranted('PUBLIC_ACCESS')]
    public function pricing(): Response
    {
        return $this->render('pricing.html.twig');
    }

    #[Route('/about', methods: ['GET'])]
    public function about(): Response
    {
        return $this->render('about.html.twig');
    }
}
`, 'symfony', 'src/Controller/AccountController.php', ['symfony/routing']);
    eq(byRoute(eps, '/account')?.classification, 'AUTH_INTERNAL', '#[IsGranted(ROLE_USER)] → AUTH_INTERNAL');
    eq(byRoute(eps, '/pricing')?.classification, 'PUBLIC_UNAUTH', '#[IsGranted(PUBLIC_ACCESS)] → explicit public');
    eq(byRoute(eps, '/about')?.classification, 'PUBLIC_UNAUTH', 'no security attribute → PUBLIC');
    const acct = byRoute(eps, '/account')!;
    assert(acct.handlerSpan != null, 'symfony method span captured');
    eq(acct.demotionEligible, true, 'symfony declaration-bound eligible');
  }

  // ==========================================================================
  console.log('\nLARAVEL — chained + group middleware, withoutMiddleware, belt');
  // ==========================================================================
  {
    const eps = await detect(phpModule, `<?php
use Illuminate\\Support\\Facades\\Route;

Route::get('/open', function () { return request('q'); });
Route::get('/me', function () { return request('q'); })->middleware('auth');
Route::get('/sanctum', function () { return request('q'); })->middleware(['auth:sanctum', 'verified']);
Route::get('/optout', function () { return request('q'); })->middleware('auth')->withoutMiddleware('auth');
Route::get('/throttled', function () { return request('q'); })->middleware('throttle:60,1');
`, 'laravel', 'routes/web.php', ['laravel/framework']);
    eq(byRoute(eps, '/open')?.classification, 'PUBLIC_UNAUTH', 'no middleware → PUBLIC');
    eq(byRoute(eps, '/me')?.classification, 'AUTH_INTERNAL', "->middleware('auth') → AUTH_INTERNAL");
    eq(byRoute(eps, '/sanctum')?.classification, 'AUTH_INTERNAL', "->middleware(['auth:sanctum','verified']) → AUTH_INTERNAL");
    eq(byRoute(eps, '/optout')?.classification, 'PUBLIC_UNAUTH', "->withoutMiddleware('auth') → explicit public");
    eq(byRoute(eps, '/throttled')?.classification, 'PUBLIC_UNAUTH', 'throttle middleware is not auth');
    const me = byRoute(eps, '/me')!;
    assert(me.handlerSpan != null, 'closure handler span captured');
    eq(me.demotionEligible, true, 'closure eligible');
  }
  {
    const eps = await detect(phpModule, `<?php
use Illuminate\\Support\\Facades\\Route;

Route::middleware('auth')->group(function () {
    Route::get('/dashboard', function () { return request('q'); });
    Route::post('/login', function () { return request('u'); });
});
Route::get('/outside', function () { return request('q'); });
`, 'laravel', 'routes/web.php', ['laravel/framework']);
    eq(byRoute(eps, '/dashboard')?.classification, 'AUTH_INTERNAL', 'fluent group middleware covers inner routes');
    eq(byRoute(eps, '/login')?.classification, 'PUBLIC_UNAUTH', 'belt: /login never inherits group (centralized) auth');
    eq(byRoute(eps, '/outside')?.classification, 'PUBLIC_UNAUTH', 'route outside the group stays PUBLIC');
  }
  {
    const eps = await detect(phpModule, `<?php
use Illuminate\\Support\\Facades\\Route;

Route::group(['middleware' => ['auth']], function () {
    Route::get('/legacy', function () { return request('q'); });
});
`, 'laravel', 'routes/web.php', ['laravel/framework']);
    eq(byRoute(eps, '/legacy')?.classification, 'AUTH_INTERNAL', "legacy Route::group(['middleware'=>...]) covers inner routes");
  }
  {
    // Controller-reference handler: classifies but never demotes (no span).
    const eps = await detect(phpModule, `<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\UserController;

Route::get('/ctrl', [UserController::class, 'index'])->middleware('auth');
`, 'laravel', 'routes/web.php', ['laravel/framework']);
    const ctrl = byRoute(eps, '/ctrl')!;
    eq(ctrl.classification, 'AUTH_INTERNAL', 'controller-ref route classifies from chain');
    eq(ctrl.handlerSpan ?? null, null, 'controller-ref handler → null span (cross-file)');
    eq(ctrl.demotionEligible, false, 'controller-ref → not demotion-eligible');
  }

  // ==========================================================================
  console.log('\nSLIM — ->add() chains + group coverage');
  // ==========================================================================
  {
    const eps = await detect(phpModule, `<?php
use Slim\\Factory\\AppFactory;

$app = AppFactory::create();
$app->get('/open', function ($req, $res) { return $res; });
$app->get('/me', function ($req, $res) { return $res; })->add(new AuthMiddleware());
$app->get('/jwt', function ($req, $res) { return $res; })->add($jwtAuthentication);
$app->get('/logged', function ($req, $res) { return $res; })->add(new LoggingMiddleware());
`, 'slim', 'public/index.php', ['slim/slim']);
    eq(byRoute(eps, '/open')?.classification, 'PUBLIC_UNAUTH', 'no ->add → PUBLIC');
    eq(byRoute(eps, '/me')?.classification, 'AUTH_INTERNAL', '->add(new AuthMiddleware()) → AUTH_INTERNAL');
    eq(byRoute(eps, '/jwt')?.classification, 'AUTH_INTERNAL', '->add($jwtAuthentication) → AUTH_INTERNAL (name pattern)');
    eq(byRoute(eps, '/logged')?.classification, 'PUBLIC_UNAUTH', 'LoggingMiddleware is not auth');
    assert(byRoute(eps, '/me')!.handlerSpan != null, 'slim closure span captured');
  }
  {
    const eps = await detect(phpModule, `<?php
use Slim\\Factory\\AppFactory;

$app = AppFactory::create();
$app->group('/admin', function ($group) {
    $group->get('/panel', function ($req, $res) { return $res; });
})->add(new AuthMiddleware());
$app->get('/outside', function ($req, $res) { return $res; });
`, 'slim', 'public/index.php', ['slim/slim']);
    eq(byRoute(eps, '/panel')?.classification, 'AUTH_INTERNAL', 'group ->add(auth) covers inner routes');
    eq(byRoute(eps, '/outside')?.classification, 'PUBLIC_UNAUTH', 'route outside the group stays PUBLIC');
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });
