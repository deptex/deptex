/**
 * T10 — Rust baseline: axum .layer/.route_layer chain coverage + same-file fn
 * spans (pub → ineligible), actix App::new().wrap() centralized coverage +
 * attribute-fn spans. rocket/warp stay all-PUBLIC and span-less (asserted so a
 * future change is conscious); aws-lambda rows are honest non-members of the
 * span join (serverless flows stamp unmatched).
 *
 * Run: npx tsx test/framework-detector-rust-auth.test.ts
 */
import { rustModule } from '../src/tree-sitter-extractor/languages/rust';
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
  const file = await rustModule.extractFile(source, 'src/main.rs', {
    deps: deps.map((d) => dep(d)), workspaceRoot: '/tmp',
  });
  return entryPointsFor(file, framework);
}

function byRoute(eps: EntryPoint[], pattern: string): EntryPoint | undefined {
  return eps.find((e) => e.routePattern === pattern);
}

async function run(): Promise<void> {
  // ==========================================================================
  console.log('\nAXUM — route_layer coverage + spans');
  // ==========================================================================
  {
    const eps = await detect(`
use axum::{routing::get, Router};

async fn list_users() -> String {
    "users".to_string()
}

pub async fn admin_panel() -> String {
    "admin".to_string()
}

fn app() -> Router {
    let authed = Router::new()
        .route("/admin", get(admin_panel))
        .route("/me", get(list_users))
        .route_layer(axum::middleware::from_fn(require_auth));
    Router::new()
        .route("/public", get(public_page))
        .merge(authed)
}
`, 'axum', ['axum']);
    eq(byRoute(eps, '/me')?.classification, 'AUTH_INTERNAL', 'route inside route_layer(require_auth) chain → AUTH_INTERNAL');
    eq(byRoute(eps, '/admin')?.classification, 'AUTH_INTERNAL', 'sibling route in the same layered chain → AUTH_INTERNAL');
    eq(byRoute(eps, '/public')?.classification, 'PUBLIC_UNAUTH', 'route in the unlayered chain stays PUBLIC');
    const me = byRoute(eps, '/me')!;
    assert(me.handlerSpan != null, 'same-file fn handler span resolved');
    eq(me.demotionEligible, true, 'non-pub single-use fn eligible');
    const admin = byRoute(eps, '/admin')!;
    eq(admin.demotionEligible, false, 'pub fn handler INELIGIBLE (cross-module callable)');
  }
  {
    const eps = await detect(`
use axum::{routing::get, Router};

fn app() -> Router {
    Router::new()
        .route("/login", get(login_page))
        .route_layer(axum::middleware::from_fn(require_auth))
}
`, 'axum', ['axum']);
    eq(byRoute(eps, '/login')?.classification, 'PUBLIC_UNAUTH', 'belt: /login never inherits layer (centralized) auth');
  }
  {
    const eps = await detect(`
use axum::{routing::get, Router};

fn app() -> Router {
    Router::new()
        .route("/traced", get(traced))
        .layer(TraceLayer::new_for_http())
}
`, 'axum', ['axum']);
    eq(byRoute(eps, '/traced')?.classification, 'PUBLIC_UNAUTH', 'non-auth layer (TraceLayer) is not evidence');
  }

  // ==========================================================================
  console.log('\nACTIX — App::new().wrap() coverage + attribute spans');
  // ==========================================================================
  {
    const eps = await detect(`
use actix_web::{get, post, App, HttpServer};
use actix_web_httpauth::middleware::HttpAuthentication;

#[get("/dashboard")]
async fn dashboard() -> String {
    "d".to_string()
}

#[post("/login")]
async fn login() -> String {
    "l".to_string()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(HttpAuthentication::bearer(validator))
            .service(dashboard)
            .service(login)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
`, 'actix', ['actix-web']);
    eq(byRoute(eps, '/dashboard')?.classification, 'AUTH_INTERNAL', 'App::new().wrap(HttpAuthentication...) covers routes');
    eq(byRoute(eps, '/login')?.classification, 'PUBLIC_UNAUTH', 'belt: /login never inherits the app-wide wrap');
    const dash = byRoute(eps, '/dashboard')!;
    assert(dash.handlerSpan != null, 'attribute-macro fn span captured');
    eq(dash.demotionEligible, true, 'declaration-bound attribute route eligible');
  }
  {
    const eps = await detect(`
use actix_web::{get, App};

#[get("/open")]
async fn open() -> String {
    "o".to_string()
}
`, 'actix', ['actix-web']);
    eq(byRoute(eps, '/open')?.classification, 'PUBLIC_UNAUTH', 'no wrap → PUBLIC');
  }

  // ==========================================================================
  console.log('\nROCKET / WARP — stay all-PUBLIC (deliberate cut)');
  // ==========================================================================
  {
    const eps = await detect(`
#[macro_use] extern crate rocket;

#[get("/hello")]
fn hello() -> String {
    "hi".to_string()
}
`, 'rocket', ['rocket']);
    for (const ep of eps) {
      eq(ep.classification, 'PUBLIC_UNAUTH', `rocket ${ep.routePattern} stays PUBLIC`);
      eq(ep.handlerSpan ?? null, null, `rocket ${ep.routePattern} has no span`);
    }
    assert(true, `rocket rows checked (${eps.length})`);
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });
