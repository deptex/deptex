import { goModule } from '../../tree-sitter-extractor/languages/go';
import { dep, entryPointsFor, extractInline } from '../test-helpers';

describe('Go framework detectors', () => {
  describe('nethttp', () => {
    it('detects http.HandleFunc registrations', async () => {
      const file = await extractInline(
        goModule,
        `
package main

import (
    "net/http"
)

func main() {
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("ok"))
    })
    http.HandleFunc("/users", usersHandler)
    http.ListenAndServe(":8080", nil)
}

func usersHandler(w http.ResponseWriter, r *http.Request) {}
        `,
        '/tmp/main.go',
        [dep('net/http')],
      );
      const eps = entryPointsFor(file, 'nethttp');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const paths = new Set(eps.map((e) => e.routePattern));
      expect(paths.has('/health')).toBe(true);
      expect(paths.has('/users')).toBe(true);
    });
  });

  describe('gin', () => {
    it('detects gin.Engine method routes', async () => {
      const file = await extractInline(
        goModule,
        `
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/ping", func(c *gin.Context) { c.String(200, "pong") })
    r.POST("/users", createUser)
    r.Run(":8080")
}

func createUser(c *gin.Context) {}
        `,
        '/tmp/main.go',
        [dep('github.com/gin-gonic/gin')],
      );
      const eps = entryPointsFor(file, 'gin');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/ping');
      expect(byMethod.get('POST')).toBe('/users');
    });
  });

  describe('echo', () => {
    it('detects echo.Echo method routes', async () => {
      const file = await extractInline(
        goModule,
        `
package main

import "github.com/labstack/echo/v4"

func main() {
    e := echo.New()
    e.GET("/health", healthHandler)
    e.PUT("/items/:id", updateItem)
    e.Start(":8080")
}

func healthHandler(c echo.Context) error { return nil }
func updateItem(c echo.Context) error { return nil }
        `,
        '/tmp/main.go',
        [dep('github.com/labstack/echo/v4')],
      );
      const eps = entryPointsFor(file, 'echo');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/health');
      expect(byMethod.get('PUT')).toBe('/items/:id');
    });
  });

  describe('fiber', () => {
    it('detects fiber.App method routes', async () => {
      const file = await extractInline(
        goModule,
        `
package main

import "github.com/gofiber/fiber/v2"

func main() {
    app := fiber.New()
    app.Get("/", func(c *fiber.Ctx) error { return c.SendString("hello") })
    app.Post("/upload", uploadHandler)
    app.Listen(":3000")
}

func uploadHandler(c *fiber.Ctx) error { return nil }
        `,
        '/tmp/main.go',
        [dep('github.com/gofiber/fiber/v2')],
      );
      const eps = entryPointsFor(file, 'fiber');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/');
      expect(byMethod.get('POST')).toBe('/upload');
    });
  });

  describe('chi', () => {
    it('detects chi.Mux method routes', async () => {
      const file = await extractInline(
        goModule,
        `
package main

import (
    "net/http"
    "github.com/go-chi/chi/v5"
)

func main() {
    r := chi.NewRouter()
    r.Get("/", homeHandler)
    r.Delete("/items/{id}", deleteItem)
    http.ListenAndServe(":8080", r)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {}
func deleteItem(w http.ResponseWriter, r *http.Request) {}
        `,
        '/tmp/main.go',
        [dep('github.com/go-chi/chi/v5')],
      );
      const eps = entryPointsFor(file, 'chi');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/');
      expect(byMethod.get('DELETE')).toBe('/items/{id}');
    });
  });

  describe('gorilla-mux', () => {
    it('detects mux.Router HandleFunc with Methods chain', async () => {
      const file = await extractInline(
        goModule,
        `
package main

import (
    "net/http"
    "github.com/gorilla/mux"
)

func main() {
    r := mux.NewRouter()
    r.HandleFunc("/products", productsHandler).Methods("GET")
    r.HandleFunc("/products/{id}", updateProduct).Methods("PUT")
    http.ListenAndServe(":8000", r)
}

func productsHandler(w http.ResponseWriter, r *http.Request) {}
func updateProduct(w http.ResponseWriter, r *http.Request) {}
        `,
        '/tmp/main.go',
        [dep('github.com/gorilla/mux')],
      );
      const eps = entryPointsFor(file, 'gorilla-mux');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/products');
      expect(byMethod.get('PUT')).toBe('/products/{id}');
    });
  });
});
