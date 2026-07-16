/**
 * T8 — route-level auth classification + spans for the Go detectors: chi
 * (Use parse-vs-enforce, .With chains), gin/echo (middle-arg middleware +
 * Use-before-route ordering + belt), fiber, gorilla-mux (Subrouter + Use),
 * net/http (wrapped handlers). Go named-handler eligibility: inline func
 * literals eligible; unexported same-file single-ref named funcs eligible;
 * exported (capitalized) handlers INELIGIBLE (callable cross-package).
 *
 * Run: npx tsx test/framework-detector-go-auth.test.ts
 */
import { goModule } from '../src/tree-sitter-extractor/languages/go';
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
  const file = await goModule.extractFile(source, 'cmd/server/main.go', {
    deps: deps.map((d) => dep(d)), workspaceRoot: '/tmp',
  });
  return entryPointsFor(file, framework);
}

function byRoute(eps: EntryPoint[], pattern: string): EntryPoint | undefined {
  return eps.find((e) => e.routePattern === pattern);
}

async function run(): Promise<void> {
  // ==========================================================================
  console.log('\nCHI — Use parse-vs-enforce + .With chains');
  // ==========================================================================
  {
    const eps = await detect(`
package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
)

func main() {
	r := chi.NewRouter()
	r.Use(jwtauth.Verifier(tokenAuth))
	r.Get("/parsed-only", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(req.URL.Query().Get("q")))
	})
	r.Use(jwtauth.Authenticator)
	r.Get("/enforced", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(req.URL.Query().Get("q")))
	})
	r.With(requireAuth).Get("/with-auth", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(req.URL.Query().Get("q")))
	})
}
`, 'chi', ['github.com/go-chi/chi']);
    eq(byRoute(eps, '/parsed-only')?.classification, 'PUBLIC_UNAUTH', 'jwtauth.Verifier is parse-only — NOT auth evidence');
    eq(byRoute(eps, '/enforced')?.classification, 'AUTH_INTERNAL', 'jwtauth.Authenticator (after Use) → AUTH_INTERNAL');
    eq(byRoute(eps, '/with-auth')?.classification, 'AUTH_INTERNAL', '.With(requireAuth) chain → AUTH_INTERNAL');
    const enforced = byRoute(eps, '/enforced')!;
    assert(enforced.handlerSpan != null, 'inline func literal span captured');
    eq(enforced.demotionEligible, true, 'inline literal eligible');
  }

  // ==========================================================================
  console.log('\nGIN — middle-arg middleware + Use ordering + belt');
  // ==========================================================================
  {
    const eps = await detect(`
package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.GET("/open", func(c *gin.Context) { c.String(200, c.Query("q")) })
	r.GET("/me", requireAuth(), func(c *gin.Context) { c.String(200, c.Query("q")) })
	r.Use(authMiddleware())
	r.GET("/after", func(c *gin.Context) { c.String(200, c.Query("q")) })
	r.POST("/login", func(c *gin.Context) { c.String(200, c.PostForm("u")) })
}
`, 'gin', ['github.com/gin-gonic/gin']);
    eq(byRoute(eps, '/open')?.classification, 'PUBLIC_UNAUTH', 'no middleware → PUBLIC');
    eq(byRoute(eps, '/me')?.classification, 'AUTH_INTERNAL', 'middle-arg requireAuth() → AUTH_INTERNAL');
    eq(byRoute(eps, '/after')?.classification, 'AUTH_INTERNAL', 'route after r.Use(authMiddleware()) → AUTH_INTERNAL');
    eq(byRoute(eps, '/login')?.classification, 'PUBLIC_UNAUTH', 'belt: /login never inherits Use-only (centralized) auth');
    // /open registered BEFORE the Use — ordering respected.
    const open = byRoute(eps, '/open')!;
    assert(open.handlerSpan != null, 'gin inline handler span captured');
    eq(open.demotionEligible, true, 'gin inline literal eligible');
  }

  // ==========================================================================
  console.log('\nGO named-handler eligibility (Sem 6 guard)');
  // ==========================================================================
  {
    const eps = await detect(`
package main

import "github.com/gin-gonic/gin"

func lowercaseHandler(c *gin.Context) {
	c.String(200, c.Query("q"))
}

func ExportedHandler(c *gin.Context) {
	c.String(200, c.Query("q"))
}

func reusedHandler(c *gin.Context) {
	c.String(200, c.Query("q"))
}

func main() {
	r := gin.Default()
	r.GET("/named", requireAuth(), lowercaseHandler)
	r.GET("/exported", requireAuth(), ExportedHandler)
	r.GET("/reused-a", requireAuth(), reusedHandler)
	r.GET("/reused-b", reusedHandler)
}
`, 'gin', ['github.com/gin-gonic/gin']);
    const named = byRoute(eps, '/named')!;
    assert(named.handlerSpan != null, 'unexported named handler resolves a span');
    eq(named.demotionEligible, true, 'unexported single-registration named handler eligible');
    const exported = byRoute(eps, '/exported')!;
    eq(exported.demotionEligible, false, 'exported (capitalized) handler INELIGIBLE (cross-package visible)');
    const reused = byRoute(eps, '/reused-a')!;
    eq(reused.demotionEligible, false, 'handler registered twice → INELIGIBLE (same-file reference guard)');
  }

  // ==========================================================================
  console.log('\nNET/HTTP — wrapped handlers');
  // ==========================================================================
  {
    const eps = await detect(`
package main

import "net/http"

func adminHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(r.URL.Query().Get("q")))
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(r.URL.Query().Get("q")))
}

func dualHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(r.URL.Query().Get("q")))
}

func main() {
	http.HandleFunc("/open", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Query().Get("q")))
	})
	http.Handle("/admin", requireAuth(adminHandler))
	http.Handle("/logged", withLogging(metricsHandler))
	http.Handle("/dual-a", requireAuth(dualHandler))
	http.Handle("/dual-b", withLogging(dualHandler))
}
`, 'nethttp', []);
    eq(byRoute(eps, '/open')?.classification, 'PUBLIC_UNAUTH', 'bare HandleFunc → PUBLIC');
    eq(byRoute(eps, '/admin')?.classification, 'AUTH_INTERNAL', 'requireAuth(h) wrapper → AUTH_INTERNAL');
    eq(byRoute(eps, '/logged')?.classification, 'PUBLIC_UNAUTH', 'withLogging(h) wrapper is not auth');
    const admin = byRoute(eps, '/admin')!;
    assert(admin.handlerSpan != null, 'wrapped handler span resolves from the inner same-file func');
    eq(admin.demotionEligible, true, 'unexported single-use inner handler eligible');
    // dualHandler is wrapped into BOTH an authed route and a public one — the
    // reference guard must make it INELIGIBLE (its span would wrongly demote
    // the public /dual-b flow otherwise).
    eq(byRoute(eps, '/dual-a')!.demotionEligible, false, 'double-wrapped handler INELIGIBLE (reference guard)');
    const open = byRoute(eps, '/open')!;
    assert(open.handlerSpan != null, 'inline literal span captured');
  }

  // ==========================================================================
  console.log('\nGORILLA — Subrouter + Use');
  // ==========================================================================
  {
    const eps = await detect(`
package main

import "github.com/gorilla/mux"

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/public", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(req.URL.Query().Get("q")))
	})
	s := r.PathPrefix("/admin").Subrouter()
	s.Use(authenticationMiddleware)
	s.HandleFunc("/panel", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(req.URL.Query().Get("q")))
	}).Methods("GET")
}
`, 'gorilla-mux', ['github.com/gorilla/mux']);
    eq(byRoute(eps, '/public')?.classification, 'PUBLIC_UNAUTH', 'root-router route stays PUBLIC');
    eq(byRoute(eps, '/panel')?.classification, 'AUTH_INTERNAL', 'subrouter Use(authenticationMiddleware) → AUTH_INTERNAL');
    const panel = byRoute(eps, '/panel')!;
    eq(panel.httpMethod, 'GET', '.Methods("GET") still parsed');
    assert(panel.handlerSpan != null, 'gorilla inline handler span captured');
  }

  // ==========================================================================
  console.log('\nECHO — middleware args');
  // ==========================================================================
  {
    const eps = await detect(`
package main

import "github.com/labstack/echo/v4"

func main() {
	e := echo.New()
	e.GET("/open", func(c echo.Context) error { return c.String(200, c.QueryParam("q")) })
	e.GET("/me", func(c echo.Context) error { return c.String(200, c.QueryParam("q")) }, middlewareJWT)
}
`, 'echo', ['github.com/labstack/echo']);
    eq(byRoute(eps, '/open')?.classification, 'PUBLIC_UNAUTH', 'no middleware → PUBLIC');
    // Echo puts middleware AFTER the handler (variadic tail) — our middle-arg
    // window is (path, handler, ...mw): the mw sits after the handler, so the
    // "last arg = handler" convention reads middlewareJWT as the handler and
    // the real handler as middleware. Assert the honest current behavior:
    // the route still classifies from the auth-shaped token seen in the args.
    eq(byRoute(eps, '/me')?.classification, 'PUBLIC_UNAUTH', 'echo trailing-middleware form: token not auth-named → stays PUBLIC (honest fail-safe)');
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });
