import { rustModule } from '../../tree-sitter-extractor/languages/rust';
import { dep, entryPointsFor, extractInline } from '../test-helpers';

describe('Rust framework detectors', () => {
  describe('actix', () => {
    it('detects #[get] / #[post] attribute macros', async () => {
      const file = await extractInline(
        rustModule,
        `
use actix_web::{get, post, App, HttpServer, Responder};

#[get("/health")]
async fn health() -> impl Responder {
    "ok"
}

#[post("/items")]
async fn create() -> impl Responder {
    "created"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(health).service(create))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
`,
        '/tmp/main.rs',
        [dep('actix-web')],
      );
      const eps = entryPointsFor(file, 'actix');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/health');
      expect(byMethod.get('POST')).toBe('/items');
    });
  });

  describe('rocket', () => {
    it('detects #[get] / #[post] with Rocket routing', async () => {
      const file = await extractInline(
        rustModule,
        `
use rocket::{get, post, routes, launch};

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[post("/echo", data = "<body>")]
fn echo(body: String) -> String {
    body
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, echo])
}
`,
        '/tmp/main.rs',
        [dep('rocket')],
      );
      const eps = entryPointsFor(file, 'rocket');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/');
      expect(byMethod.get('POST')).toBe('/echo');
    });
  });

  describe('axum', () => {
    it('detects Router::new().route() chains', async () => {
      const file = await extractInline(
        rustModule,
        `
use axum::{routing::{get, post}, Router};

async fn root() -> &'static str { "hello" }
async fn users() -> &'static str { "users" }

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/users", post(users));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
`,
        '/tmp/main.rs',
        [dep('axum')],
      );
      const eps = entryPointsFor(file, 'axum');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/');
      expect(byMethod.get('POST')).toBe('/users');
    });
  });

  describe('warp', () => {
    it('detects warp::path filter-chain form', async () => {
      const file = await extractInline(
        rustModule,
        `
use warp::Filter;

#[tokio::main]
async fn main() {
    let hello = warp::path("hello")
        .and(warp::get())
        .map(|| "hi");

    let users = warp::path("users")
        .and(warp::post())
        .map(|| "created");

    let routes = hello.or(users);
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
`,
        '/tmp/main.rs',
        [dep('warp')],
      );
      const eps = entryPointsFor(file, 'warp');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/hello');
      expect(byMethod.get('POST')).toBe('/users');
    });
  });
});
