# Framework Fixture Spec — Reachable / Unreachable

End-to-end depscanner pipeline fixtures: each `frameworks/<slug>/` directory has a `reachable/` and `unreachable/` subdir. Both pin the **same vulnerable dep version**; they differ only in whether the framework entry point reaches the vulnerable sink.

- **reachable/** — the framework's HTTP/RPC handler invokes the vulnerable code path through user input. Expected classifier verdict: `confirmed` (with CVE-targeted spec match) or `data_flow`.
- **unreachable/** — same dep version is imported but the vulnerable function is never invoked from any entry point. Expected classifier verdict: `module` or `unreachable`.

These are **authoring artifacts only**. They are not wired into a snapshot/CI runner in this commit (Docker-only depscanner runs are out of scope per the marathon-day-2 doc); follow-up work can plug them into a `--tag=<framework>` runner per `docs/contributor-test-infra-plan.md` §6.

## Coverage table

| Framework | Language | PM | Suggested CVE | Vulnerable dep (pinned) | Sink pattern | Reachable path | Unreachable path | Already exists at | Notes |
|---|---|---|---|---|---|---|---|---|---|
| express | js | npm | CVE-2021-23337 | lodash@4.17.20 | `_.template(userInput)()` | POST handler → renderTemplate(req.body.template) | imported but never called from a route | partial: `depscanner/test/cve-targeted-flow-fixtures/js-lodash-template-injection/` (taint-engine only) | canonical fixture per contributor-test-infra-plan §2 |
| fastify | js | npm | CVE-2019-10744 | lodash@4.17.11 | `_.defaultsDeep(userInput)` (proto pollution) | `fastify.post('/merge', ...)` calls defaultsDeep on body | dep imported, only static helper called | new | |
| koa | js | npm | CVE-2017-16026 | request@2.81.0 | `request(userUrl)` (SSRF) | `app.use` route makes request to ctx.query.url | request imported but unreferenced | new | |
| nestjs | js | npm | CVE-2022-24999 | qs@6.5.2 | DoS via prototype pollution from parsed query | `@Get` controller calls `qs.parse(req.query.q)` | qs imported in module file, never invoked | new | reuse pattern from existing taint-engine fixture |
| nextjs | js | npm | CVE-2024-21505 | next@14.0.0 | SSRF via image optimization | API route handler calls `next/server` redirect with user input | next imported in pages but no API route handler | new | next is the "vulnerable dep" itself |
| aws-lambda | js | npm | CVE-2021-44906 | minimist@1.2.5 | argument injection via `minimist(payload)` | exports.handler parses event.body via minimist | minimist imported but never invoked | new | |
| aiohttp | python | pip | CVE-2024-23334 | aiohttp@3.9.1 | path traversal via `web.static` | `web.RouteTableDef` exposes static at user path | aiohttp imported but app.run never called | new | |
| django | python | pip | CVE-2022-28346 | django@4.0.3 | SQL injection via `QuerySet.annotate(**user_kwargs)` | view receives `request.GET` and unpacks into annotate | view imported but URL conf empty | partial: taint-engine fixtures exist | |
| fastapi | python | pip | CVE-2024-24762 | python-multipart@0.0.6 | ReDoS via Content-Type parsing | `@app.post('/upload')` Form() triggers parser | FastAPI app defined but no Form()-using route | partial: taint-engine fixtures exist | |
| flask | python | pip | CVE-2023-30861 | flask@2.2.2 | session cookie leak via Cache-Control | view returns `make_response(...)` from user input cookie | flask app exists, no route handlers | partial: taint-engine fixtures exist | |
| starlette | python | pip | CVE-2023-29159 | starlette@0.27.0 | open redirect | `RedirectResponse(request.query_params['next'])` | route returns plain text, no redirect | new | |
| tornado | python | pip | CVE-2023-28370 | tornado@6.2 | open redirect via Location header | `RequestHandler.get` calls `self.redirect(self.get_argument('u'))` | tornado app defined, handler returns static text | new | |
| gin | go | gomod | CVE-2023-26125 | github.com/gin-gonic/gin@v1.9.0 | path traversal via untrusted proxy headers / SSRF via param | `r.GET("/file", ...)` calls os.ReadFile(c.Query("p")) | gin imported, no route registered | partial: taint-engine fixtures exist | |
| echo | go | gomod | CVE-2022-40083 | github.com/labstack/echo/v4@v4.6.3 | open redirect via `c.Redirect` | echo Handler redirects to user-controlled URL | echo imported, no Redirect call | new | |
| fiber | go | gomod | CVE-2023-45141 | github.com/gofiber/fiber/v2@v2.49.0 | header injection / open redirect | `app.Get` calls `c.Redirect(c.Query("u"))` | fiber imported, no Redirect call | new | |
| chi | go | gomod | CVE-2023-44487 | github.com/go-chi/chi/v5@v5.0.10 | reflected XSS via `w.Write([]byte(r.URL.Query().Get(...)))` | route writes user input into response | chi imported, no route handler | new | |
| gorilla-mux | go | gomod | CVE-2023-39325 | github.com/gorilla/mux@v1.8.0 + golang.org/x/net@v0.16.0 | HTTP/2 rapid reset (transitive) | router serves user-controlled path with file read | mux imported, no route registered | new | dep `golang.org/x/net` is the vulnerable transitive |
| nethttp | go | gomod | CVE-2023-24539 | golang.org/x/text@v0.3.7 | HTML injection via templates | `http.HandleFunc` writes user input via html/template UnsafeHTML | http server defined, no HandleFunc | new | x/text as vulnerable dep |
| actix | rust | cargo | RUSTSEC-2020-0071 | time@0.1.43 | segfault via concurrent calls (use as proxy CVE) | actix handler reads time::at(c) on user input | actix-web imported, no route registered | partial: taint-engine fixtures exist | |
| axum | rust | cargo | CVE-2024-32650 | hyper@0.14.27 (transitive) | request smuggling | axum router with handler reading body as bytes | axum imported, no Router::new | partial: taint-engine fixtures exist | |
| rocket | rust | cargo | RUSTSEC-2022-0046 | rocket@0.5.0-rc.1 (use as proxy) | command injection via `Process::new` on form input | `#[post("/run")]` spawns process from form data | rocket imported, no #[launch] entry | new | |
| warp | rust | cargo | CVE-2023-26964 | h2@0.3.16 (transitive) | DoS via excessive memory allocation | warp filter receives body and parses h2 stream | warp imported, no filter / serve | new | |
| rails | ruby | bundler | CVE-2022-32224 | rails@6.1.4 (activerecord/yaml) | YAML deserialization | controller calls `YAML.load(params[:data])` | controller defined but route not mounted | partial: taint-engine fixtures exist | |
| sinatra | ruby | bundler | CVE-2024-21510 | sinatra@2.2.0 | Path traversal via send_file | `get '/file'` calls `send_file params[:p]` | sinatra app, no route definitions | partial: taint-engine fixtures exist | |
| grape | ruby | bundler | CVE-2018-3769 | grape@1.0.2 | XSS via `format :json` formatter | `get '/echo'` returns user param via JSONP | Grape API class defined, no endpoint declared | new | |
| laravel | php | composer | CVE-2021-43808 | laravel/framework@8.40.0 | XSS via Mail rendering | controller renders user input in mail.blade.php | controller exists, route not mapped | partial: taint-engine fixtures exist | |
| symfony | php | composer | CVE-2024-50340 | symfony/runtime@6.3.0 | env override via query string | controller invokes `Runtime::getEnv(query)` | symfony route file with no #[Route] | partial: taint-engine fixtures exist | |
| slim | php | composer | CVE-2019-12867 | slim/slim@3.12.1 | header injection via `withHeader` | route writes user input into Location header | Slim app instantiated, no addRoute/get | new | |
| spring | java | maven | CVE-2022-22965 | org.springframework:spring-webmvc:5.3.16 | Spring4Shell — class loader RCE | `@PostMapping` accepts POJO with class.module.classLoader | controller without @PostMapping handler | partial: taint-engine fixtures exist | |
| jaxrs | java | maven | CVE-2022-1471 | org.yaml:snakeyaml:1.30 | YAML deserialization | `@POST` resource method calls `new Yaml().load(body)` | resource class without @Path methods | new | |
| micronaut | java | maven | CVE-2023-25569 | io.micronaut:micronaut-http-server:3.7.4 | HTTP/2 reset DoS | `@Controller` with `@Get` reading user input | controller class with no route methods | new | |
| quarkus | java | maven | CVE-2023-2974 | io.quarkus:quarkus-core:2.16.6.Final | TLS hostname mismatch / RCE in resteasy | `@Path` resource invokes resteasy client with user URL | resource class with no annotated methods | new | |
| aspnet-core | csharp | nuget | CVE-2023-36038 | Microsoft.AspNetCore.App@7.0.10 | DoS via Form parsing | controller `[HttpPost]` reads `IFormCollection` from user | controller class with no [HttpPost] | partial: taint-engine fixtures exist | |
| minimal-apis | csharp | nuget | CVE-2024-21319 | Microsoft.IdentityModel.JsonWebTokens@6.27.0 | JWT validation bypass | `app.MapPost("/token")` validates user JWT | minimal API program with no endpoints | new | |

## Skipped frameworks

None outright skipped — all 33 detectors are covered. Where a taint-engine fixture already exists at `depscanner/test/taint-engine/fixtures/`, the new pipeline-level fixture is still authored (different shape: real `package.json` + pinned vulnerable dep, not just an isolated taint pattern). The "already exists at" column flags overlap so a future Docker-gated runner can choose to dedupe.

## Notes from the survey

- All 33 detectors are present and live; none are dead-code. The 34th referenced in CLAUDE.md likely counts something tangential (e.g., a generic catch-all). `nextjs`, `minimal-apis`, `aws-lambda`, `rails` use `triggerImports: []` and rely on file-name / annotation heuristics.
- For Go, Rust, Java, the "vulnerable dep" is sometimes a transitive (e.g., `golang.org/x/net` for net/http; `hyper` for axum). The reachable fixture's import is to the framework; the CVE attaches to whichever package in the build graph dep-scan flags.
- For Rails / Next.js / Lambda / Minimal APIs, `triggerImports` is empty, so reachability detection relies on convention-over-configuration cues (file paths, attributes). The fixtures place files where the detectors expect them.
- ASP.NET / Spring / Laravel CVE picks lean on real library CVEs that the dep-scan VDR will flag. Where a CVE is shaky (e.g., Rocket, Quarkus, transitives), a follow-up should verify the dep-scan match before wiring into a snapshot runner.

## Follow-ups

1. Wire fixtures into a Docker-gated `npm run test:fixtures -- --tag=<framework>` runner per contributor-test-infra-plan §6. Each framework's reachable fixture should produce ≥1 reachable flow; unreachable should produce 0.
2. Lockfiles (`package-lock.json`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `go.sum`) are intentionally NOT committed in this initial dispatch. Add lockfiles in a follow-up if/when the runner needs deterministic installs (cdxgen reads lockfiles where present).
3. Verify dep-scan VDR flags for each pinned (dep, version, CVE) tuple. A handful of picks (Rocket, Quarkus, Micronaut) are aspirational — the version is vulnerable in vendor advisories but dep-scan source coverage may differ.
4. Consider de-duplicating against `depscanner/test/taint-engine/fixtures/` once the Docker-gated runner exists. Today the two sets serve different purposes (engine-only vs end-to-end).
